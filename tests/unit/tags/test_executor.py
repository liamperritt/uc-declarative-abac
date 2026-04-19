from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import sqlglot

from uc_abac_governor.logger import ChangeLogger
from uc_abac_governor.tags.executor import execute_tag_diff
from uc_abac_governor.tags.state import SecurableTag, TagDiff
from uc_abac_governor.types import InteractiveConfirmationRequiredError, SecurableType


def _parse_sql(sql: str):
    """Attempt to parse SQL via sqlglot. Returns the parsed expression or None."""
    try:
        return sqlglot.parse_one(sql, dialect="databricks")
    except sqlglot.errors.ParseError:
        return None


def _assert_sql_contains(sql: str, *fragments: str):
    """Assert that every fragment appears in the SQL string (case-insensitive, ignoring backticks)."""
    normalised = sql.upper().replace("`", "")
    for fragment in fragments:
        assert fragment.upper() in normalised, (
            f"Expected {fragment!r} in SQL: {sql}"
        )


# ---------------------------------------------------------------------------
# Tag diffs to ALTER statement resolution
# ---------------------------------------------------------------------------


def test_tag_executor_generates_set_tags_sql_for_adds():
    """to_add tags produce ALTER SET TAGS with the expected securable and tag."""
    uc_helper = MagicMock()
    diff = TagDiff(
        to_add={
            SecurableTag(
                securable_type=SecurableType.CATALOG,
                securable_full_name="my_catalog",
                tag_name="env",
                tag_value="prod",
            )
        },
    )

    stmts = execute_tag_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]

    # Try sqlglot parse; fall back to string assertions if Databricks syntax
    # is not fully supported.
    parsed = _parse_sql(sql)
    if parsed is not None:
        sql_text = parsed.sql(dialect="databricks")
        _assert_sql_contains(sql_text, "SET TAGS", "my_catalog", "env", "prod")
    else:
        _assert_sql_contains(sql, "ALTER", "CATALOG", "SET TAGS", "my_catalog", "env", "prod")

    # Securable name should be backtick-quoted
    assert "`my_catalog`" in sql

    uc_helper.execute_sql.assert_called_once_with(sql)


def test_tag_executor_generates_set_tags_sql_for_updates():
    """to_update tags produce ALTER SET TAGS — same SQL shape as adds."""
    uc_helper = MagicMock()
    diff = TagDiff(
        to_update={
            SecurableTag(
                securable_type=SecurableType.TABLE,
                securable_full_name="cat.schema.orders",
                tag_name="pii",
                tag_value="true",
            )
        },
    )

    stmts = execute_tag_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]

    parsed = _parse_sql(sql)
    if parsed is not None:
        sql_text = parsed.sql(dialect="databricks")
        _assert_sql_contains(sql_text, "SET TAGS", "cat.schema.orders", "pii", "true")
    else:
        _assert_sql_contains(sql, "ALTER", "TABLE", "SET TAGS", "cat.schema.orders", "pii", "true")

    uc_helper.execute_sql.assert_called_once_with(sql)


def test_tag_executor_generates_unset_tags_sql_for_removes():
    """to_remove tags produce ALTER UNSET TAGS containing the tag key only."""
    uc_helper = MagicMock()
    diff = TagDiff(
        to_remove={
            SecurableTag(
                securable_type=SecurableType.CATALOG,
                securable_full_name="my_catalog",
                tag_name="env",
                tag_value="prod",
            )
        },
    )

    stmts = execute_tag_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]

    parsed = _parse_sql(sql)
    if parsed is not None:
        sql_text = parsed.sql(dialect="databricks")
        _assert_sql_contains(sql_text, "UNSET TAGS", "my_catalog", "env")
    else:
        _assert_sql_contains(sql, "ALTER", "CATALOG", "UNSET TAGS", "my_catalog", "env")

    # UNSET TAGS should not include the tag value assignment.
    assert "= 'prod'" not in sql

    uc_helper.execute_sql.assert_called_once_with(sql)


def test_tag_executor_handles_valueless_tags():
    """A tag with tag_value="" produces SET TAGS('key' = '') with an empty string value."""
    uc_helper = MagicMock()
    diff = TagDiff(
        to_add={
            SecurableTag(
                securable_type=SecurableType.CATALOG,
                securable_full_name="my_catalog",
                tag_name="operations",
                tag_value="",
            )
        },
    )

    stmts = execute_tag_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]

    _assert_sql_contains(sql, "SET TAGS", "my_catalog", "operations")
    # Empty-string tag should produce an assignment with an empty value.
    assert "= ''" in sql.split("operations")[-1].split(",")[0].split(")")[0], (
        f"Empty-string tag should have '= \"\"' assignment: {sql}"
    )

    uc_helper.execute_sql.assert_called_once_with(sql)


# ---------------------------------------------------------------------------
# Batching — multiple tags on the same securable → single statement
# ---------------------------------------------------------------------------


def test_tag_executor_batches_tags_per_securable():
    """Multiple tags on the same securable should be batched into one ALTER."""
    uc_helper = MagicMock()
    diff = TagDiff(
        to_add={
            SecurableTag(
                securable_type=SecurableType.TABLE,
                securable_full_name="cat.schema.table",
                tag_name="a",
                tag_value="1",
            ),
            SecurableTag(
                securable_type=SecurableType.TABLE,
                securable_full_name="cat.schema.table",
                tag_name="b",
                tag_value="2",
            ),
        },
    )

    stmts = execute_tag_diff(uc_helper, diff, ChangeLogger())

    # Only one statement should be generated for the single securable.
    assert len(stmts) == 1
    sql = stmts[0]

    _assert_sql_contains(sql, "SET TAGS", "cat.schema.table")
    # Both tag keys must appear in the same statement.
    _assert_sql_contains(sql, "'a'", "'b'")

    uc_helper.execute_sql.assert_called_once()


# ---------------------------------------------------------------------------
# SQL statement execution
# ---------------------------------------------------------------------------


def test_tag_executor_returns_all_executed_statements():
    """The return list contains every SQL statement that was executed."""
    uc_helper = MagicMock()
    diff = TagDiff(
        to_add={
            SecurableTag(
                securable_type=SecurableType.CATALOG,
                securable_full_name="cat_a",
                tag_name="env",
                tag_value="dev",
            ),
        },
        to_remove={
            SecurableTag(
                securable_type=SecurableType.SCHEMA,
                securable_full_name="cat_b.schema_b",
                tag_name="deprecated",
                tag_value="true",
            ),
        },
    )

    stmts = execute_tag_diff(uc_helper, diff, ChangeLogger())

    # Exactly two statements: one SET TAGS, one UNSET TAGS.
    assert len(stmts) == 2

    set_stmts = [s for s in stmts if "SET TAGS" in s.upper() and "UNSET" not in s.upper()]
    unset_stmts = [s for s in stmts if "UNSET TAGS" in s.upper()]

    assert len(set_stmts) == 1, f"Expected exactly one SET TAGS statement, got {len(set_stmts)}"
    assert len(unset_stmts) == 1, f"Expected exactly one UNSET TAGS statement, got {len(unset_stmts)}"

    # Every returned statement must have been passed to execute_sql.
    executed_sqls = [call.args[0] for call in uc_helper.execute_sql.call_args_list]
    assert set(stmts) == set(executed_sqls)


def test_tag_executor_executes_nothing_given_empty_diff():
    """An empty TagDiff should produce no SQL and no execute_sql calls."""
    uc_helper = MagicMock()
    diff = TagDiff()

    stmts = execute_tag_diff(uc_helper, diff, ChangeLogger())

    assert stmts == []
    uc_helper.execute_sql.assert_not_called()


def test_tag_executor_executes_sql_in_securable_order():
    """SQL statements are executed ordered by securable type then full name."""
    uc_helper = MagicMock()
    diff = TagDiff(
        to_add={
            SecurableTag(
                securable_type=SecurableType.TABLE,
                securable_full_name="cat.s.table_b",
                tag_name="a",
                tag_value="1",
            ),
            SecurableTag(
                securable_type=SecurableType.CATALOG,
                securable_full_name="cat_a",
                tag_name="b",
                tag_value="2",
            ),
            SecurableTag(
                securable_type=SecurableType.TABLE,
                securable_full_name="cat.s.table_a",
                tag_name="c",
                tag_value="3",
            ),
            SecurableTag(
                securable_type=SecurableType.CATALOG,
                securable_full_name="cat_b",
                tag_name="d",
                tag_value="4",
            ),
        },
    )

    stmts = execute_tag_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 4

    # Normalise by removing backticks for easier assertions.
    normalised = [s.replace("`", "") for s in stmts]

    # Expected order: CATALOG cat_a, CATALOG cat_b, TABLE cat.s.table_a, TABLE cat.s.table_b
    assert "cat_a" in normalised[0], f"Expected cat_a in first stmt: {stmts[0]}"
    assert "cat_b" in normalised[1], f"Expected cat_b in second stmt: {stmts[1]}"
    assert "cat.s.table_a" in normalised[2], f"Expected cat.s.table_a in third stmt: {stmts[2]}"
    assert "cat.s.table_b" in normalised[3], f"Expected cat.s.table_b in fourth stmt: {stmts[3]}"


# ---------------------------------------------------------------------------
# Error collection
# ---------------------------------------------------------------------------


def test_tag_executor_continues_after_sql_failure():
    """When one SQL call fails, execution continues and the error is collected."""
    uc_helper = MagicMock()
    call_count = {"n": 0}

    def _fail_first(sql):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("SQL execution failed")

    uc_helper.execute_sql.side_effect = _fail_first

    change_logger = ChangeLogger()

    # Two tags on DIFFERENT securables so they produce two separate SQL statements
    diff = TagDiff(
        to_add={
            SecurableTag(
                securable_type=SecurableType.CATALOG,
                securable_full_name="cat_a",
                tag_name="env",
                tag_value="prod",
            ),
            SecurableTag(
                securable_type=SecurableType.SCHEMA,
                securable_full_name="cat_b.schema_b",
                tag_name="team",
                tag_value="data",
            ),
        },
    )

    stmts = execute_tag_diff(uc_helper, diff, change_logger)

    # Both calls were attempted
    assert uc_helper.execute_sql.call_count == 2
    # One error collected
    assert change_logger.has_errors is True
    assert len(change_logger.errors) == 1
    # Only the successful statement is returned
    assert len(stmts) == 1


def test_tag_executor_collects_all_errors():
    """When all SQL calls fail, all errors are collected and no statements returned."""
    uc_helper = MagicMock()
    uc_helper.execute_sql.side_effect = RuntimeError("SQL execution failed")

    change_logger = ChangeLogger()

    diff = TagDiff(
        to_add={
            SecurableTag(
                securable_type=SecurableType.CATALOG,
                securable_full_name="cat_a",
                tag_name="env",
                tag_value="prod",
            ),
            SecurableTag(
                securable_type=SecurableType.SCHEMA,
                securable_full_name="cat_b.schema_b",
                tag_name="team",
                tag_value="data",
            ),
        },
    )

    stmts = execute_tag_diff(uc_helper, diff, change_logger)

    # Both calls were attempted
    assert uc_helper.execute_sql.call_count == 2
    # Both errors collected
    assert len(change_logger.errors) == 2
    # No successful statements
    assert stmts == []


# ---------------------------------------------------------------------------
# Column tag SQL
# ---------------------------------------------------------------------------


def test_tag_executor_generates_alter_column_set_tags_sql():
    """A COLUMN tag in to_add produces ALTER TABLE ... ALTER COLUMN ... SET TAGS."""
    uc_helper = MagicMock()
    diff = TagDiff(
        to_add={
            SecurableTag(
                securable_type=SecurableType.COLUMN,
                securable_full_name="cat.schema.orders.email",
                tag_name="pii",
                tag_value="true",
            )
        },
    )

    stmts = execute_tag_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]

    _assert_sql_contains(sql, "ALTER TABLE", "ALTER COLUMN", "SET TAGS", "email", "pii")

    uc_helper.execute_sql.assert_called_once_with(sql)


# ---------------------------------------------------------------------------
# Dry-run mode
# ---------------------------------------------------------------------------


def test_tag_executor_logs_changes_in_dry_run():
    """dry_run=True logs all tag changes without executing any SQL."""
    uc_helper = MagicMock()
    change_logger = ChangeLogger()

    tag_add = SecurableTag(
        securable_type=SecurableType.CATALOG,
        securable_full_name="my_catalog",
        tag_name="env",
        tag_value="prod",
    )
    tag_update = SecurableTag(
        securable_type=SecurableType.TABLE,
        securable_full_name="cat.schema.orders",
        tag_name="pii",
        tag_value="true",
    )
    tag_remove = SecurableTag(
        securable_type=SecurableType.SCHEMA,
        securable_full_name="cat.schema",
        tag_name="deprecated",
        tag_value="",
    )

    diff = TagDiff(
        to_add={tag_add},
        to_update={tag_update},
        to_remove={tag_remove},
        old_values={
            (tag_update.securable_type, tag_update.securable_full_name, tag_update.tag_name): "false",
        },
    )

    stmts = execute_tag_diff(uc_helper, diff, change_logger, dry_run=True)

    # No SQL executed
    assert stmts == []
    uc_helper.execute_sql.assert_not_called()

    # All three changes were logged (counts tracked on the ChangeLogger)
    assert change_logger._tags_added == 1
    assert change_logger._tags_updated == 1
    assert change_logger._tags_removed == 1


def test_tag_executor_generates_alter_column_unset_tags_sql():
    """A COLUMN tag in to_remove produces ALTER TABLE ... ALTER COLUMN ... UNSET TAGS."""
    uc_helper = MagicMock()
    diff = TagDiff(
        to_remove={
            SecurableTag(
                securable_type=SecurableType.COLUMN,
                securable_full_name="cat.schema.orders.email",
                tag_name="pii",
                tag_value="true",
            )
        },
    )

    stmts = execute_tag_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]

    _assert_sql_contains(sql, "ALTER TABLE", "ALTER COLUMN", "UNSET TAGS", "email", "pii")

    uc_helper.execute_sql.assert_called_once_with(sql)


# ---------------------------------------------------------------------------
# Governed-tag removal confirmation prompt
# ---------------------------------------------------------------------------


def _governed_remove(tag_name: str = "uc_gov_pii") -> SecurableTag:
    return SecurableTag(
        securable_type=SecurableType.TABLE,
        securable_full_name="cat.schema.orders",
        tag_name=tag_name,
        tag_value="email",
    )


def _nongoverned_remove() -> SecurableTag:
    return SecurableTag(
        securable_type=SecurableType.TABLE,
        securable_full_name="cat.schema.orders",
        tag_name="free_form_label",
        tag_value="stale",
    )


def test_tag_executor_prompts_before_removing_governed_tag(monkeypatch):
    """A removal whose tag_name is in governed_tag_names triggers an interactive
    prompt. Accepting (``y``) proceeds with the UNSET TAGS SQL."""
    uc_helper = MagicMock()
    calls = {"n": 0}

    def _fake_input(_prompt):
        calls["n"] += 1
        return "y"

    monkeypatch.setattr("builtins.input", _fake_input)

    diff = TagDiff(to_remove={_governed_remove()})

    stmts = execute_tag_diff(
        uc_helper, diff, ChangeLogger(),
        governed_tag_names={"uc_gov_pii"},
    )

    assert calls["n"] == 1, "Expected input() to be called exactly once"
    assert len(stmts) == 1
    _assert_sql_contains(stmts[0], "UNSET TAGS", "uc_gov_pii")


def test_tag_executor_exits_when_prompt_rejected(monkeypatch):
    """When the prompt is rejected, the whole program aborts via SystemExit;
    the governed UNSET TAGS SQL is not executed."""
    uc_helper = MagicMock()
    monkeypatch.setattr("builtins.input", lambda _p: "n")

    diff = TagDiff(to_remove={_governed_remove()})

    with pytest.raises(SystemExit):
        execute_tag_diff(
            uc_helper, diff, ChangeLogger(),
            governed_tag_names={"uc_gov_pii"},
        )

    # No SQL for the governed tag should have been executed.
    executed = [c.args[0] for c in uc_helper.execute_sql.call_args_list]
    for stmt in executed:
        assert "uc_gov_pii" not in stmt, (
            f"Expected SystemExit to fire before governed UNSET SQL ran, got: {stmt}"
        )


def test_tag_executor_does_not_prompt_when_no_governed_tags_in_removes(monkeypatch):
    """If no removal targets a governed tag key, input() is never called."""
    uc_helper = MagicMock()
    called = {"n": 0}

    def _fake_input(_p):
        called["n"] += 1
        return "y"

    monkeypatch.setattr("builtins.input", _fake_input)

    diff = TagDiff(to_remove={_nongoverned_remove()})

    execute_tag_diff(
        uc_helper, diff, ChangeLogger(),
        governed_tag_names={"uc_gov_pii"},
    )

    assert called["n"] == 0, "Expected input() never to be called"


def test_tag_executor_bypasses_prompt_when_force_true(monkeypatch):
    """force=True bypasses the prompt and proceeds with governed-tag removal."""
    uc_helper = MagicMock()
    called = {"n": 0}

    def _fake_input(_p):
        called["n"] += 1
        return "n"  # would reject if called

    monkeypatch.setattr("builtins.input", _fake_input)

    diff = TagDiff(to_remove={_governed_remove()})

    stmts = execute_tag_diff(
        uc_helper, diff, ChangeLogger(),
        governed_tag_names={"uc_gov_pii"},
        force=True,
    )

    assert called["n"] == 0, "Expected no prompt when force=True"
    assert len(stmts) == 1
    _assert_sql_contains(stmts[0], "UNSET TAGS", "uc_gov_pii")


def test_tag_executor_skips_prompt_in_dry_run(monkeypatch):
    """dry_run=True logs the removal without prompting; no SQL is executed."""
    uc_helper = MagicMock()
    called = {"n": 0}

    def _fake_input(_p):
        called["n"] += 1
        return "n"

    monkeypatch.setattr("builtins.input", _fake_input)

    change_logger = ChangeLogger()
    diff = TagDiff(to_remove={_governed_remove()})

    stmts = execute_tag_diff(
        uc_helper, diff, change_logger,
        governed_tag_names={"uc_gov_pii"},
        dry_run=True,
    )

    assert called["n"] == 0, "Expected no prompt in dry-run"
    assert stmts == []
    uc_helper.execute_sql.assert_not_called()
    # Dry-run still logs the removal for visibility.
    assert change_logger._tags_removed == 1


def test_tag_executor_raises_interactive_confirmation_required_on_non_tty(monkeypatch):
    """In a non-interactive context (input() raises EOFError), a governed-tag
    removal without force raises InteractiveConfirmationRequiredError."""
    uc_helper = MagicMock()

    def _raise_eof(_p):
        raise EOFError()

    monkeypatch.setattr("builtins.input", _raise_eof)

    diff = TagDiff(to_remove={_governed_remove()})

    with pytest.raises(InteractiveConfirmationRequiredError):
        execute_tag_diff(
            uc_helper, diff, ChangeLogger(),
            governed_tag_names={"uc_gov_pii"},
        )
