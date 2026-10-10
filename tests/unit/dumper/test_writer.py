"""Tests for uc_declarative_abac.dumper.writer (dump_state function)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml
from databricks.sdk.errors import NotFound, PermissionDenied

from uc_declarative_abac import ActualState
from uc_declarative_abac.configs import ResourcesConfig
from uc_declarative_abac.dumper import INSERT_MAX_ROWS, TABLE_SPECS, dump_state
from uc_declarative_abac.securables import Securable
from uc_declarative_abac.types import SecurableType
from uc_declarative_abac.utils import ExecutionBatchError

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _build_minimal_config_dir(tmp_path: Path) -> Path:
    """Build a minimal valid config directory in tmp_path."""
    config = {"resources": {"catalogs": {"main": {}}}}
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.dump(config, default_flow_style=False))
    return tmp_path


def _build_minimal_actual_state() -> ActualState:
    """Build a minimal ActualState with all required fields."""
    return ActualState(
        groups=frozenset(),
        all_account_groups=frozenset(),
        governed_tags=frozenset(),
        domains=frozenset(),
        securables=frozenset(),
        attributes=frozenset(),
        tags=frozenset(),
        policies=frozenset(),
        privileges=frozenset(),
        principals={},
    )


def _normalize_sql_backticks(sql: str) -> str:
    """Remove all backticks from SQL to make comparisons lenient."""
    return sql.replace("`", "")


# ---
# CREATE TABLE and INSERT statement tests
# ---


def test_dumper_writer_creates_one_table_per_spec(
    mock_workspace_client: MagicMock, tmp_path: Path, caplog: Any
) -> None:
    """dump_state writes one CREATE OR REPLACE TABLE per TABLE_SPECS table into the target schema."""
    config_dir = _build_minimal_config_dir(tmp_path)
    mock_workspace_client.schemas.get.return_value = MagicMock()  # Schema exists

    with patch("uc_declarative_abac.dumper.writer.fetch_actual_state") as mock_fetch:
        mock_fetch.return_value = _build_minimal_actual_state()

        dump_state(
            mock_workspace_client,
            config_dir=config_dir,
            warehouse_id="warehouse-1",
            target_schema="main.state",
        )

    # Check that we have one CREATE for each table
    create_statements = [
        sql
        for sql in mock_workspace_client.executed_sql
        if "CREATE OR REPLACE TABLE" in sql
    ]
    assert len(create_statements) == len(TABLE_SPECS), (
        f"Expected {len(TABLE_SPECS)} CREATE statements, got {len(create_statements)}"
    )

    # Check that each table name appears in the CREATE statements
    normalized_creates = [_normalize_sql_backticks(sql) for sql in create_statements]
    for spec in TABLE_SPECS:
        table_full_name = f"main.state.{spec.name}"
        assert any(
            table_full_name in normalized for normalized in normalized_creates
        ), f"Table {table_full_name} not found in CREATE statements"


def test_dumper_writer_create_precedes_inserts(
    mock_workspace_client: MagicMock, tmp_path: Path
) -> None:
    """dump_state ensures each table's CREATE precedes that table's INSERTs."""
    config_dir = _build_minimal_config_dir(tmp_path)
    mock_workspace_client.schemas.get.return_value = MagicMock()  # Schema exists

    with patch("uc_declarative_abac.dumper.writer.fetch_actual_state") as mock_fetch:
        mock_fetch.return_value = _build_minimal_actual_state()

        dump_state(
            mock_workspace_client,
            config_dir=config_dir,
            warehouse_id="warehouse-1",
            target_schema="main.state",
        )

    sql_statements = mock_workspace_client.executed_sql
    normalized_stmts = [_normalize_sql_backticks(sql) for sql in sql_statements]

    for spec in TABLE_SPECS:
        table_full_name = f"main.state.{spec.name}"
        create_idx = None
        insert_indices = []

        for i, stmt in enumerate(normalized_stmts):
            if f"CREATE OR REPLACE TABLE {table_full_name}" in stmt:
                create_idx = i
            if f"INSERT INTO {table_full_name}" in stmt:
                insert_indices.append(i)

        if insert_indices:
            # If there are INSERT statements, CREATE must come first
            assert create_idx is not None, (
                f"No CREATE found for table {table_full_name} which has INSERTs"
            )
            assert create_idx < min(insert_indices), (
                f"CREATE for {table_full_name} at index {create_idx} "
                f"comes after INSERT at index {min(insert_indices)}"
            )


def test_dumper_writer_empty_domain_creates_table_without_insert(
    mock_workspace_client: MagicMock, tmp_path: Path
) -> None:
    """dump_state handles a table with no rows: CREATE only, no INSERT."""
    config_dir = _build_minimal_config_dir(tmp_path)
    mock_workspace_client.schemas.get.return_value = MagicMock()  # Schema exists

    with patch("uc_declarative_abac.dumper.writer.fetch_actual_state") as mock_fetch:
        # All tables have empty row sets
        mock_fetch.return_value = _build_minimal_actual_state()

        dump_state(
            mock_workspace_client,
            config_dir=config_dir,
            warehouse_id="warehouse-1",
            target_schema="main.state",
        )

    sql_statements = mock_workspace_client.executed_sql
    normalized_stmts = [_normalize_sql_backticks(sql) for sql in sql_statements]

    # The domains table should have a CREATE but no INSERT (since state has no domains)
    domains_creates = [
        s for s in normalized_stmts if "CREATE OR REPLACE TABLE main.state.domains" in s
    ]
    domains_inserts = [
        s for s in normalized_stmts if "INSERT INTO main.state.domains" in s
    ]

    assert len(domains_creates) == 1, "Should have exactly one CREATE for domains table"
    assert len(domains_inserts) == 0, "Should have no INSERT for empty domains table"


def test_dumper_writer_multiple_inserts_when_exceeding_max_rows(
    mock_workspace_client: MagicMock, tmp_path: Path
) -> None:
    """dump_state chunks INSERT statements when row count exceeds INSERT_MAX_ROWS."""
    config_dir = _build_minimal_config_dir(tmp_path)
    mock_workspace_client.schemas.get.return_value = MagicMock()  # Schema exists

    with patch("uc_declarative_abac.dumper.writer.fetch_actual_state") as mock_fetch:
        # Build a state with many securables (>INSERT_MAX_ROWS)
        num_securables = INSERT_MAX_ROWS * 2 + 500  # 2500 with default 1000
        securables = frozenset(
            Securable(SecurableType.CATALOG, f"c{i}") for i in range(num_securables)
        )
        state = ActualState(
            groups=frozenset(),
            all_account_groups=frozenset(),
            governed_tags=frozenset(),
            domains=frozenset(),
            securables=securables,
            attributes=frozenset(),
            tags=frozenset(),
            policies=frozenset(),
            privileges=frozenset(),
            principals={},
        )
        mock_fetch.return_value = state

        dump_state(
            mock_workspace_client,
            config_dir=config_dir,
            warehouse_id="warehouse-1",
            target_schema="main.state",
        )

    sql_statements = mock_workspace_client.executed_sql
    normalized_stmts = [_normalize_sql_backticks(sql) for sql in sql_statements]

    # Find all INSERT statements for securables table - match precisely
    securables_inserts = [
        s
        for s in normalized_stmts
        if "INSERT INTO main.state.securables " in s
        or "INSERT INTO main.state.securables(" in s
    ]

    # With 2500 rows and INSERT_MAX_ROWS=1000, we expect exactly 3 INSERT statements
    assert len(securables_inserts) == 3, (
        f"Expected exactly 3 INSERT statements for securables "
        f"(2500 rows / 1000 max), got {len(securables_inserts)}"
    )


# ---
# Schema creation tests
# ---


def test_dumper_writer_schema_exists_no_create_schema(
    mock_workspace_client: MagicMock, tmp_path: Path
) -> None:
    """dump_state skips CREATE SCHEMA when the schema already exists."""
    config_dir = _build_minimal_config_dir(tmp_path)
    mock_workspace_client.schemas.get.return_value = MagicMock()  # Schema exists

    with patch("uc_declarative_abac.dumper.writer.fetch_actual_state") as mock_fetch:
        mock_fetch.return_value = _build_minimal_actual_state()

        dump_state(
            mock_workspace_client,
            config_dir=config_dir,
            warehouse_id="warehouse-1",
            target_schema="main.state",
        )

    # No CREATE SCHEMA should be issued
    create_schema_stmts = [
        sql
        for sql in mock_workspace_client.executed_sql
        if "CREATE SCHEMA" in sql.upper()
    ]
    assert len(create_schema_stmts) == 0, (
        f"Expected no CREATE SCHEMA, but found: {create_schema_stmts}"
    )


def test_dumper_writer_schema_missing_creates_schema(
    mock_workspace_client: MagicMock, tmp_path: Path
) -> None:
    """dump_state creates the schema when it doesn't exist (NotFound error)."""
    config_dir = _build_minimal_config_dir(tmp_path)
    mock_workspace_client.schemas.get.side_effect = NotFound("schema not found")

    with patch("uc_declarative_abac.dumper.writer.fetch_actual_state") as mock_fetch:
        mock_fetch.return_value = _build_minimal_actual_state()

        dump_state(
            mock_workspace_client,
            config_dir=config_dir,
            warehouse_id="warehouse-1",
            target_schema="main.state",
        )

    # Should have exactly one CREATE SCHEMA statement
    create_schema_stmts = [
        sql
        for sql in mock_workspace_client.executed_sql
        if "CREATE SCHEMA" in sql.upper()
    ]
    assert len(create_schema_stmts) == 1, (
        f"Expected exactly one CREATE SCHEMA, got {len(create_schema_stmts)}: "
        f"{create_schema_stmts}"
    )

    # Verify it doesn't use IF NOT EXISTS
    schema_sql = create_schema_stmts[0].upper()
    assert "IF NOT EXISTS" not in schema_sql, (
        "CREATE SCHEMA should not use IF NOT EXISTS"
    )


def test_dumper_writer_create_schema_before_create_tables(
    mock_workspace_client: MagicMock, tmp_path: Path
) -> None:
    """dump_state executes CREATE SCHEMA before any CREATE OR REPLACE TABLE."""
    config_dir = _build_minimal_config_dir(tmp_path)
    mock_workspace_client.schemas.get.side_effect = NotFound("schema not found")

    with patch("uc_declarative_abac.dumper.writer.fetch_actual_state") as mock_fetch:
        mock_fetch.return_value = _build_minimal_actual_state()

        dump_state(
            mock_workspace_client,
            config_dir=config_dir,
            warehouse_id="warehouse-1",
            target_schema="main.state",
        )

    sql_statements = mock_workspace_client.executed_sql

    create_schema_idx = None
    first_create_table_idx = None

    for i, sql in enumerate(sql_statements):
        if "CREATE SCHEMA" in sql.upper() and create_schema_idx is None:
            create_schema_idx = i
        if "CREATE OR REPLACE TABLE" in sql and first_create_table_idx is None:
            first_create_table_idx = i

    assert create_schema_idx is not None, (
        "CREATE SCHEMA not found in executed statements"
    )
    assert first_create_table_idx is not None, (
        "CREATE OR REPLACE TABLE not found in executed statements"
    )
    assert create_schema_idx < first_create_table_idx, (
        "CREATE SCHEMA should execute before CREATE OR REPLACE TABLE"
    )


def test_dumper_writer_schemas_get_before_fetch_actual_state(
    mock_workspace_client: MagicMock, tmp_path: Path
) -> None:
    """dump_state checks schema existence before calling fetch_actual_state."""
    config_dir = _build_minimal_config_dir(tmp_path)
    call_order = []

    def track_schemas_get(*args, **kwargs):
        call_order.append("schemas_get")
        raise NotFound("schema not found")

    mock_workspace_client.schemas.get.side_effect = track_schemas_get

    with patch("uc_declarative_abac.dumper.writer.fetch_actual_state") as mock_fetch:

        def track_fetch(*args, **kwargs):
            call_order.append("fetch_actual_state")
            return _build_minimal_actual_state()

        mock_fetch.side_effect = track_fetch

        dump_state(
            mock_workspace_client,
            config_dir=config_dir,
            warehouse_id="warehouse-1",
            target_schema="main.state",
        )

    assert call_order == ["schemas_get", "fetch_actual_state"], (
        f"Expected schemas_get before fetch_actual_state, got: {call_order}"
    )


def test_dumper_writer_non_notfound_error_from_schemas_get_propagates(
    mock_workspace_client: MagicMock, tmp_path: Path
) -> None:
    """dump_state propagates non-NotFound errors from schemas.get and doesn't call fetch_actual_state."""
    config_dir = _build_minimal_config_dir(tmp_path)
    mock_workspace_client.schemas.get.side_effect = PermissionDenied("no access")

    with patch("uc_declarative_abac.dumper.writer.fetch_actual_state") as mock_fetch:
        mock_fetch.return_value = _build_minimal_actual_state()

        with pytest.raises(PermissionDenied):
            dump_state(
                mock_workspace_client,
                config_dir=config_dir,
                warehouse_id="warehouse-1",
                target_schema="main.state",
            )

    # fetch_actual_state should not have been called
    mock_fetch.assert_not_called()


# ---
# Dry run tests
# ---


def test_dumper_writer_dry_run_executes_no_sql(
    mock_workspace_client: MagicMock, tmp_path: Path
) -> None:
    """dump_state with dry_run=True executes no SQL at all."""
    config_dir = _build_minimal_config_dir(tmp_path)
    mock_workspace_client.schemas.get.side_effect = NotFound("schema not found")

    with patch("uc_declarative_abac.dumper.writer.fetch_actual_state") as mock_fetch:
        mock_fetch.return_value = _build_minimal_actual_state()

        dump_state(
            mock_workspace_client,
            config_dir=config_dir,
            warehouse_id="warehouse-1",
            target_schema="main.state",
            dry_run=True,
        )

    assert len(mock_workspace_client.executed_sql) == 0, (
        "Dry run should execute no SQL statements"
    )


def test_dumper_writer_dry_run_logs_would_create_schema(
    mock_workspace_client: MagicMock, tmp_path: Path, caplog: Any
) -> None:
    """dump_state with dry_run=True logs about the schema it would create."""
    config_dir = _build_minimal_config_dir(tmp_path)
    mock_workspace_client.schemas.get.side_effect = NotFound("schema not found")

    with patch("uc_declarative_abac.dumper.writer.fetch_actual_state") as mock_fetch:
        mock_fetch.return_value = _build_minimal_actual_state()

        with caplog.at_level(logging.INFO):
            dump_state(
                mock_workspace_client,
                config_dir=config_dir,
                warehouse_id="warehouse-1",
                target_schema="main.state",
                dry_run=True,
            )

    # Log should mention "Would create" and the schema name
    log_text = caplog.text
    assert "Would create" in log_text, (
        f"Expected 'Would create' in log, got: {caplog.text}"
    )
    assert "main.state" in log_text, (
        f"Expected 'main.state' schema name in log, got: {caplog.text}"
    )


# ---
# Failure handling tests
# ---


def test_dumper_writer_failing_table_continues_other_tables(
    mock_workspace_client: MagicMock, tmp_path: Path
) -> None:
    """dump_state continues processing other tables when one table fails."""
    config_dir = _build_minimal_config_dir(tmp_path)
    mock_workspace_client.schemas.get.return_value = MagicMock()  # Schema exists

    original_side_effect = (
        mock_workspace_client.statement_execution.execute_statement.side_effect
    )

    def fail_on_securable_tags(*args, **kwargs):
        statement = kwargs.get("statement", args[0] if args else "")
        # Match precisely: securable_tags but not securables/securable_privileges
        if "main.state.securable_tags" in _normalize_sql_backticks(statement):
            raise RuntimeError("securable_tags table failed")
        # Use original side effect for other statements
        return original_side_effect(*args, **kwargs)

    mock_workspace_client.statement_execution.execute_statement.side_effect = (
        fail_on_securable_tags
    )

    with patch("uc_declarative_abac.dumper.writer.fetch_actual_state") as mock_fetch:
        mock_fetch.return_value = _build_minimal_actual_state()

        with pytest.raises(ExecutionBatchError) as exc_info:
            dump_state(
                mock_workspace_client,
                config_dir=config_dir,
                warehouse_id="warehouse-1",
                target_schema="main.state",
            )

        # The error should mention the failed table
        assert "securable_tags" in str(exc_info.value).lower()

    # Every OTHER table (all except securable_tags) should have CREATE executed
    sql_statements = mock_workspace_client.executed_sql
    normalized_stmts = [_normalize_sql_backticks(sql) for sql in sql_statements]

    for spec in TABLE_SPECS:
        if spec.name != "securable_tags":
            # Check that this table has a CREATE statement
            table_full_name = f"main.state.{spec.name}"
            has_create = any(
                f"CREATE OR REPLACE TABLE {table_full_name} " in stmt
                or f"CREATE OR REPLACE TABLE {table_full_name}(" in stmt
                for stmt in normalized_stmts
            )
            assert has_create, (
                f"Table {spec.name} should have CREATE executed "
                f"even though another table failed"
            )


def test_dumper_writer_failing_table_raises_execution_batch_error(
    mock_workspace_client: MagicMock, tmp_path: Path
) -> None:
    """dump_state raises ExecutionBatchError naming the failed table(s)."""
    config_dir = _build_minimal_config_dir(tmp_path)
    mock_workspace_client.schemas.get.return_value = MagicMock()  # Schema exists

    original_side_effect = (
        mock_workspace_client.statement_execution.execute_statement.side_effect
    )

    def fail_on_securables(*args, **kwargs):
        statement = kwargs.get("statement", args[0] if args else "")
        # Match precisely: main.state.securables (not securable_tags/securable_privileges)
        normalized = _normalize_sql_backticks(statement)
        if "main.state.securables " in normalized and "CREATE OR REPLACE" in normalized:
            raise RuntimeError("securables table creation failed")
        # Use original side effect for other statements
        return original_side_effect(*args, **kwargs)

    mock_workspace_client.statement_execution.execute_statement.side_effect = (
        fail_on_securables
    )

    with patch("uc_declarative_abac.dumper.writer.fetch_actual_state") as mock_fetch:
        mock_fetch.return_value = _build_minimal_actual_state()

        with pytest.raises(ExecutionBatchError) as exc_info:
            dump_state(
                mock_workspace_client,
                config_dir=config_dir,
                warehouse_id="warehouse-1",
                target_schema="main.state",
            )

        error = exc_info.value
        assert isinstance(error, ExecutionBatchError)
        # Assert "securables" is in the error (the failed table name)
        error_text = str(error).lower()
        assert "securables" in error_text, (
            f"Error should mention 'securables' table, got: {error_text}"
        )
        # Verify other tables don't appear as failures
        assert (
            "securable_tags" not in error_text
            or "securable_tags" not in error_text.split("securables")[0]
        ), f"Error should not list securable_tags as failed, got: {error_text}"


# ---
# Logging tests
# ---


def test_dumper_writer_logs_writing_and_wrote_per_table(
    mock_workspace_client: MagicMock, tmp_path: Path, caplog: Any
) -> None:
    """dump_state logs a 'Writing to' and a 'Wrote to' line per table."""
    config_dir = _build_minimal_config_dir(tmp_path)
    mock_workspace_client.schemas.get.return_value = MagicMock()  # Schema exists

    with patch("uc_declarative_abac.dumper.writer.fetch_actual_state") as mock_fetch:
        mock_fetch.return_value = _build_minimal_actual_state()

        with caplog.at_level(logging.INFO):
            dump_state(
                mock_workspace_client,
                config_dir=config_dir,
                warehouse_id="warehouse-1",
                target_schema="main.state",
            )

    log_text = caplog.text
    for spec in TABLE_SPECS:
        writing_found = False
        wrote_found = False
        for record in caplog.records:
            if "Writing to" in record.message and spec.name in record.message:
                writing_found = True
            if "Wrote to" in record.message and spec.name in record.message:
                wrote_found = True
        assert writing_found, (
            f"Expected 'Writing to' log for '{spec.name}', got: {log_text}"
        )
        assert wrote_found, (
            f"Expected 'Wrote to' log for '{spec.name}', got: {log_text}"
        )


# ---
# Configuration and helpers passing tests
# ---


def test_dumper_writer_passes_config_and_helpers_to_fetch(
    mock_workspace_client: MagicMock, tmp_path: Path
) -> None:
    """dump_state passes loaded config and helpers to fetch_actual_state without RunContext."""
    config_dir = _build_minimal_config_dir(tmp_path)
    mock_workspace_client.schemas.get.return_value = MagicMock()  # Schema exists

    with patch("uc_declarative_abac.dumper.writer.fetch_actual_state") as mock_fetch:
        mock_fetch.return_value = _build_minimal_actual_state()

        dump_state(
            mock_workspace_client,
            config_dir=config_dir,
            warehouse_id="warehouse-1",
            target_schema="main.state",
        )

    # Verify fetch_actual_state was called exactly once
    assert mock_fetch.call_count == 1

    # Get the call arguments
    call_args = mock_fetch.call_args
    # Should be 3 positional args: config, uc_helper, ws_helper
    # And the 4th arg (settings) should be None or not passed
    assert call_args is not None
    args, kwargs = call_args
    assert len(args) >= 3, f"Expected at least 3 positional args, got {len(args)}"

    # First arg should be the loaded config (ResourcesConfig)
    config_arg = args[0]
    assert isinstance(config_arg, ResourcesConfig), (
        f"First arg should be ResourcesConfig, got {type(config_arg)}"
    )
    # Check that the config has the catalogs from the YAML
    assert config_arg.catalogs is not None, "Config should have catalogs"
    assert "main" in config_arg.catalogs, (
        f"Config catalogs should include 'main', got: {list(config_arg.catalogs.keys())}"
    )

    # 4th argument (settings in kwargs or as positional arg) should be None or not present
    if len(args) > 3:
        # settings passed as positional arg
        settings = args[3]
        assert settings is None, f"Expected settings to be None, got {settings}"
    elif "settings" in kwargs:
        # settings passed as keyword arg
        settings = kwargs["settings"]
        assert settings is None, f"Expected settings to be None, got {settings}"


# ---
# Parallelism tests
# ---


def test_dumper_writer_with_default_parallelism(
    mock_workspace_client: MagicMock, tmp_path: Path
) -> None:
    """dump_state uses default max_parallel_tables unless overridden."""
    config_dir = _build_minimal_config_dir(tmp_path)
    mock_workspace_client.schemas.get.return_value = MagicMock()  # Schema exists

    with patch("uc_declarative_abac.dumper.writer.fetch_actual_state") as mock_fetch:
        mock_fetch.return_value = _build_minimal_actual_state()

        # Call without max_parallel_tables parameter
        dump_state(
            mock_workspace_client,
            config_dir=config_dir,
            warehouse_id="warehouse-1",
            target_schema="main.state",
        )

    # Should complete without error and execute statements
    assert len(mock_workspace_client.executed_sql) >= len(TABLE_SPECS)


# ---------------------------------------------------------------------------
# Truncation of partially written tables
# ---------------------------------------------------------------------------


def _fail_statements_matching(mock_workspace_client: MagicMock, predicate) -> None:
    """Make every statement whose backtick-normalised SQL matches ``predicate`` raise,
    while still recording it in ``executed_sql``."""
    original = mock_workspace_client.statement_execution.execute_statement.side_effect

    def _side_effect(*args, **kwargs):
        statement = kwargs.get("statement", args[0] if args else "")
        if predicate(_normalize_sql_backticks(statement)):
            mock_workspace_client.executed_sql.append(statement)
            raise RuntimeError("insert failed")
        return original(*args, **kwargs)

    mock_workspace_client.statement_execution.execute_statement.side_effect = (
        _side_effect
    )


def _state_with_securables(count: int) -> ActualState:
    securables = frozenset(
        Securable(SecurableType.CATALOG, f"c{i}") for i in range(count)
    )
    return ActualState(
        **{**_build_minimal_actual_state().__dict__, "securables": securables}
    )


def _dump(mock_workspace_client: MagicMock, tmp_path: Path, state: ActualState):
    with patch(
        "uc_declarative_abac.dumper.writer.fetch_actual_state", return_value=state
    ):
        dump_state(
            mock_workspace_client,
            config_dir=_build_minimal_config_dir(tmp_path),
            warehouse_id="warehouse-1",
            target_schema="main.state",
            max_parallel_tables=1,
        )


def test_dumper_writer_truncates_table_when_an_insert_fails(
    mock_workspace_client: MagicMock, tmp_path: Path
) -> None:
    """A failed INSERT leaves no partial snapshot: the table is truncated, so it
    reads as empty rather than silently incomplete."""
    _fail_statements_matching(
        mock_workspace_client,
        lambda sql: (
            sql.startswith("INSERT INTO main.state.securables ") and "'c1500'" in sql
        ),
    )

    with pytest.raises(ExecutionBatchError, match="main.state.securables"):
        _dump(
            mock_workspace_client, tmp_path, _state_with_securables(2 * INSERT_MAX_ROWS)
        )

    statements = [
        _normalize_sql_backticks(s) for s in mock_workspace_client.executed_sql
    ]
    failed_index = next(
        i for i, s in enumerate(statements) if "'c1500'" in s and "INSERT" in s
    )
    truncates = [
        i
        for i, s in enumerate(statements)
        if s.strip() == "TRUNCATE TABLE main.state.securables"
    ]
    assert truncates and truncates[0] > failed_index


def test_dumper_writer_does_not_truncate_when_create_fails(
    mock_workspace_client: MagicMock, tmp_path: Path
) -> None:
    """Nothing was written if the CREATE itself failed, so there is nothing to truncate."""
    _fail_statements_matching(
        mock_workspace_client,
        lambda sql: sql.startswith("CREATE OR REPLACE TABLE main.state.securables "),
    )

    with pytest.raises(ExecutionBatchError):
        _dump(mock_workspace_client, tmp_path, _state_with_securables(3))

    assert not any("TRUNCATE" in s for s in mock_workspace_client.executed_sql)


def test_dumper_writer_does_not_truncate_successful_tables(
    mock_workspace_client: MagicMock, tmp_path: Path
) -> None:
    _dump(mock_workspace_client, tmp_path, _state_with_securables(3))

    assert not any("TRUNCATE" in s for s in mock_workspace_client.executed_sql)


# ---------------------------------------------------------------------------
# Progress logging
# ---------------------------------------------------------------------------


def _progress_lines(caplog: Any, table: str) -> list[str]:
    return [
        r.message
        for r in caplog.records
        if f"Writing to {table} (" in r.message
        and " of " in r.message
        and f"Writing to {table} (0 of " not in r.message
    ]


def test_dumper_writer_logs_progress_between_batches_of_a_long_table(
    mock_workspace_client: MagicMock, tmp_path: Path, caplog: Any
) -> None:
    """Once the progress interval has elapsed, each completed batch logs the rows
    written so far out of the table's total; the final batch is covered by the
    'Wrote to' line instead."""
    state = _state_with_securables(2 * INSERT_MAX_ROWS + 500)
    with (
        patch(
            "uc_declarative_abac.dumper.writer.fetch_actual_state", return_value=state
        ),
        caplog.at_level(logging.INFO),
    ):
        dump_state(
            mock_workspace_client,
            config_dir=_build_minimal_config_dir(tmp_path),
            warehouse_id="warehouse-1",
            target_schema="main.state",
            progress_interval_seconds=0,
        )

    lines = _progress_lines(caplog, "main.state.securables")
    assert [line.split("(")[-1] for line in lines] == [
        "1000 of 2500 rows)",
        "2000 of 2500 rows)",
    ]


def test_dumper_writer_logs_no_progress_for_a_table_written_within_the_interval(
    mock_workspace_client: MagicMock, tmp_path: Path, caplog: Any
) -> None:
    state = _state_with_securables(2 * INSERT_MAX_ROWS + 500)
    with (
        patch(
            "uc_declarative_abac.dumper.writer.fetch_actual_state", return_value=state
        ),
        caplog.at_level(logging.INFO),
    ):
        dump_state(
            mock_workspace_client,
            config_dir=_build_minimal_config_dir(tmp_path),
            warehouse_id="warehouse-1",
            target_schema="main.state",
        )

    assert _progress_lines(caplog, "main.state.securables") == []
