from __future__ import annotations

from unittest.mock import MagicMock

from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.securables.executor import execute_securable_diff
from uc_declarative_abac.securables.state import (
    AttributeUpdate,
    Column,
    Function,
    Securable,
    SecurableDiff,
    Table,
)
from uc_declarative_abac.principals.state import Principal
from uc_declarative_abac.types import PrincipalType, SecurableType


def _assert_sql_contains(sql: str, *fragments: str):
    """Assert that every fragment appears in the SQL string (case-insensitive, ignoring backticks)."""
    normalised = sql.upper().replace("`", "")
    for fragment in fragments:
        assert fragment.upper() in normalised, (
            f"Expected {fragment!r} in SQL: {sql}"
        )


# ---------------------------------------------------------------------------
# SQL generation tests
# ---------------------------------------------------------------------------


def test_securable_executor_generates_create_function_sql():
    """A Function in securables_to_create produces CREATE FUNCTION SQL."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_create=[
            Function(
                securable_type=SecurableType.FUNCTION,
                full_name="cat.schema.func",
                parameters=(("col", "STRING"),),
                definition="CASE WHEN is_member('admins') THEN col ELSE '***' END",
            ),
        ],
    )

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]

    _assert_sql_contains(sql, "CREATE FUNCTION", "CAT.SCHEMA.FUNC", "COL STRING", "RETURN")
    # Name should be backtick-quoted
    assert "`cat`.`schema`.`func`" in sql

    uc_helper.execute_sql.assert_called_once_with(sql)


def test_securable_executor_generates_replace_function_sql():
    """A Function in securables_to_replace produces CREATE OR REPLACE FUNCTION SQL."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_replace=[
            Function(
                securable_type=SecurableType.FUNCTION,
                full_name="cat.schema.func",
                parameters=(("col", "STRING"),),
                definition="CASE WHEN is_member('admins') THEN col ELSE '***' END",
            ),
        ],
    )

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]

    _assert_sql_contains(sql, "CREATE OR REPLACE FUNCTION", "CAT.SCHEMA.FUNC", "RETURN")

    uc_helper.execute_sql.assert_called_once_with(sql)


def test_securable_executor_generates_create_function_sql_without_parameters():
    """A Function with no parameters produces empty parens before RETURN."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_create=[
            Function(
                securable_type=SecurableType.FUNCTION,
                full_name="c.s.f",
                parameters=(),
                definition="1",
            ),
        ],
    )

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]

    _assert_sql_contains(sql, "CREATE FUNCTION", "RETURN")

    # Verify empty parens appear before RETURN
    return_pos = sql.upper().index("RETURN")
    before_return = sql[:return_pos].rstrip()
    assert before_return.endswith("()"), (
        f"Expected empty parens '()' before RETURN, got: ...{before_return[-20:]}"
    )

    uc_helper.execute_sql.assert_called_once()


# ---------------------------------------------------------------------------
# API call tests
# ---------------------------------------------------------------------------


def test_securable_executor_calls_update_owner():
    """An owner AttributeUpdate calls uc_helper.update_owner, not execute_sql."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        attributes_to_update=[
            AttributeUpdate(
                securable_type=SecurableType.CATALOG,
                full_name="my_catalog",
                attribute="owner",
                old_value="old",
                new_value="new",
            ),
        ],
    )

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    # Owner updates are API calls, not SQL — returned list should be empty.
    assert stmts == []

    uc_helper.update_owner.assert_called_once_with(
        SecurableType.CATALOG, "my_catalog", "new"
    )
    uc_helper.execute_sql.assert_not_called()


# ---------------------------------------------------------------------------
# Error handling and dry-run tests
# ---------------------------------------------------------------------------


def test_securable_executor_continues_after_error():
    """When the first operation fails, execution continues to the second."""
    uc_helper = MagicMock()
    call_count = {"n": 0}

    def _fail_first(sql):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("SQL execution failed")

    uc_helper.execute_sql.side_effect = _fail_first

    change_logger = ChangeLogger()

    diff = SecurableDiff(
        securables_to_create=[
            Function(
                securable_type=SecurableType.FUNCTION,
                full_name="cat.schema.func_a",
                parameters=(("col", "STRING"),),
                definition="col",
            ),
            Function(
                securable_type=SecurableType.FUNCTION,
                full_name="cat.schema.func_b",
                parameters=(("col", "STRING"),),
                definition="col",
            ),
        ],
    )

    stmts = execute_securable_diff(uc_helper, diff, change_logger)

    # Both calls were attempted
    assert uc_helper.execute_sql.call_count == 2
    # One error collected
    assert change_logger.has_errors is True
    assert len(change_logger.errors) == 1
    # Only the successful statement is returned
    assert len(stmts) == 1


def test_securable_executor_executes_nothing_given_empty_diff():
    """An empty SecurableDiff should produce no SQL and no API calls."""
    uc_helper = MagicMock()
    diff = SecurableDiff()

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert stmts == []
    uc_helper.execute_sql.assert_not_called()
    uc_helper.update_owner.assert_not_called()


def test_securable_executor_logs_changes_in_dry_run():
    """dry_run=True logs all changes without executing any SQL or API calls."""
    uc_helper = MagicMock()
    change_logger = ChangeLogger()

    diff = SecurableDiff(
        securables_to_create=[
            Function(
                securable_type=SecurableType.FUNCTION,
                full_name="cat.schema.func_create",
                parameters=(("col", "STRING"),),
                definition="col",
            ),
        ],
        securables_to_replace=[
            Function(
                securable_type=SecurableType.FUNCTION,
                full_name="cat.schema.func_replace",
                parameters=(("col", "STRING"),),
                definition="col",
            ),
        ],
        attributes_to_update=[
            AttributeUpdate(
                securable_type=SecurableType.CATALOG,
                full_name="my_catalog",
                attribute="owner",
                old_value="old",
                new_value="new",
            ),
        ],
    )

    stmts = execute_securable_diff(uc_helper, diff, change_logger, dry_run=True)

    # No SQL or API calls executed
    assert stmts == []
    uc_helper.execute_sql.assert_not_called()
    uc_helper.update_owner.assert_not_called()

    # All three changes were logged (counts tracked on the ChangeLogger)
    assert change_logger._securables_created == 1
    assert change_logger._securables_replaced == 1
    assert change_logger._attributes_updated == 1


# ---------------------------------------------------------------------------
# Principal-based owner updates
# ---------------------------------------------------------------------------


def test_securable_executor_extracts_identifier_from_principal():
    """When new_value is a Principal, the executor passes .identifier to update_owner."""
    uc_helper = MagicMock()
    sp_principal = Principal(PrincipalType.SERVICE_PRINCIPAL, "72a5956b-app-id", "sp_display_name")

    diff = SecurableDiff(
        attributes_to_update=[
            AttributeUpdate(
                securable_type=SecurableType.FUNCTION,
                full_name="cat.schema.my_func",
                attribute="owner",
                old_value="old_owner",
                new_value=sp_principal,
            ),
        ],
    )

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert stmts == []
    uc_helper.update_owner.assert_called_once_with(
        SecurableType.FUNCTION, "cat.schema.my_func", "72a5956b-app-id"
    )


# ---------------------------------------------------------------------------
# Function comments
# ---------------------------------------------------------------------------


def test_securable_executor_create_function_includes_comment_when_set():
    """CREATE FUNCTION SQL includes a COMMENT clause when Function.comment is set."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_create=[
            Function(
                securable_type=SecurableType.FUNCTION,
                full_name="cat.s.f",
                parameters=(("x", "STRING"),),
                definition="x",
                comment="Identity function",
            ),
        ],
    )

    (sql,) = execute_securable_diff(uc_helper, diff, ChangeLogger())
    _assert_sql_contains(sql, "CREATE FUNCTION", "COMMENT 'Identity function'")


def test_securable_executor_create_function_omits_comment_clause_when_unset():
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_create=[
            Function(
                securable_type=SecurableType.FUNCTION,
                full_name="cat.s.f",
                parameters=(("x", "STRING"),),
                definition="x",
            ),
        ],
    )

    (sql,) = execute_securable_diff(uc_helper, diff, ChangeLogger())
    assert "COMMENT" not in sql.upper()


def test_securable_executor_replace_function_includes_comment_when_set():
    """CREATE OR REPLACE FUNCTION also includes the COMMENT clause."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_replace=[
            Function(
                securable_type=SecurableType.FUNCTION,
                full_name="cat.s.f",
                parameters=(("x", "STRING"),),
                definition="x",
                comment="Updated docs",
            ),
        ],
    )

    (sql,) = execute_securable_diff(uc_helper, diff, ChangeLogger())
    _assert_sql_contains(sql, "CREATE OR REPLACE FUNCTION", "COMMENT 'Updated docs'")


def test_securable_executor_escapes_single_quotes_in_comment():
    """Single quotes in a comment are escaped so the SQL doesn't break."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_create=[
            Function(
                securable_type=SecurableType.FUNCTION,
                full_name="cat.s.f",
                parameters=(),
                definition="'x'",
                comment="It's a comment",
            ),
        ],
    )

    (sql,) = execute_securable_diff(uc_helper, diff, ChangeLogger())
    assert "COMMENT 'It\\'s a comment'" in sql


# ---------------------------------------------------------------------------
# Taggable creation: catalog / schema / table / volume
# ---------------------------------------------------------------------------


def test_securable_executor_builds_create_catalog_sql():
    """A base Securable(CATALOG, ...) in to_create produces CREATE CATALOG SQL."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_create=[Securable(securable_type=SecurableType.CATALOG, full_name="new_cat")],
    )

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    _assert_sql_contains(stmts[0], "CREATE CATALOG", "IF NOT EXISTS", "new_cat")


def test_securable_executor_builds_create_schema_sql_with_full_name():
    """A base Securable(SCHEMA, ...) in to_create produces CREATE SCHEMA <full_name> SQL."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_create=[Securable(securable_type=SecurableType.SCHEMA, full_name="cat.new_sch")],
    )

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    _assert_sql_contains(stmts[0], "CREATE SCHEMA", "IF NOT EXISTS", "cat.new_sch")


def test_securable_executor_builds_create_volume_sql():
    """A base Securable(VOLUME, ...) in to_create produces a managed CREATE VOLUME statement."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_create=[Securable(securable_type=SecurableType.VOLUME, full_name="cat.sch.vol")],
    )

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    _assert_sql_contains(stmts[0], "CREATE VOLUME", "IF NOT EXISTS", "cat.sch.vol")
    # Managed-only: no LOCATION clause.
    assert "LOCATION" not in stmts[0].upper()


def test_securable_executor_builds_create_table_sql_with_columns():
    """A Table in to_create produces CREATE TABLE SQL with typed columns in declaration order."""
    uc_helper = MagicMock()
    table = Table(
        securable_type=SecurableType.TABLE,
        full_name="cat.sch.orders",
        columns=(
            Column(securable_type=SecurableType.COLUMN, full_name="cat.sch.orders.email", data_type="STRING"),
            Column(securable_type=SecurableType.COLUMN, full_name="cat.sch.orders.amount", data_type="DECIMAL(18,2)"),
        ),
    )
    diff = SecurableDiff(securables_to_create=[table])

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]
    _assert_sql_contains(sql, "CREATE TABLE", "IF NOT EXISTS", "cat.sch.orders")
    # Columns appear with their types, in declaration order.
    assert "email" in sql and "STRING" in sql
    assert "amount" in sql and "DECIMAL(18,2)" in sql
    assert sql.index("email") < sql.index("amount")


def test_securable_executor_orders_creations_parent_first():
    """Catalogs come before schemas before tables/volumes/functions in the SQL order."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_create=[
            # Deliberately out of order.
            Table(securable_type=SecurableType.TABLE, full_name="cat.sch.tbl",
                  columns=(Column(securable_type=SecurableType.COLUMN, full_name="cat.sch.tbl.a", data_type="STRING"),)),
            Securable(securable_type=SecurableType.SCHEMA, full_name="cat.sch"),
            Securable(securable_type=SecurableType.VOLUME, full_name="cat.sch.vol"),
            Securable(securable_type=SecurableType.CATALOG, full_name="cat"),
        ],
    )

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    idx_catalog = next(i for i, s in enumerate(stmts) if "CREATE CATALOG" in s.upper())
    idx_schema = next(i for i, s in enumerate(stmts) if "CREATE SCHEMA" in s.upper())
    idx_table = next(i for i, s in enumerate(stmts) if "CREATE TABLE" in s.upper())
    idx_volume = next(i for i, s in enumerate(stmts) if "CREATE VOLUME" in s.upper())
    assert idx_catalog < idx_schema < idx_table, f"expected catalog < schema < table, got {[idx_catalog, idx_schema, idx_table]}"
    assert idx_schema < idx_volume, f"expected schema < volume, got schema={idx_schema}, volume={idx_volume}"


# ---------------------------------------------------------------------------
# COLUMN dispatch: ALTER TABLE ADD COLUMN
# ---------------------------------------------------------------------------


def test_securable_executor_builds_alter_table_add_column_sql_for_column():
    """A standalone Column in securables_to_create produces ALTER TABLE ADD COLUMN SQL."""
    uc_helper = MagicMock()
    column = Column(
        securable_type=SecurableType.COLUMN,
        full_name="cat.sch.orders.email",
        data_type="STRING",
    )
    diff = SecurableDiff(securables_to_create=[column])

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]
    _assert_sql_contains(sql, "ALTER TABLE", "ADD COLUMN", "cat.sch.orders", "email", "STRING")
    # Backtick quoting on parent table and column name.
    assert "`cat`.`sch`.`orders`" in sql
    assert "`email`" in sql


def test_securable_executor_emits_one_alter_per_column():
    """Multiple Column entries each produce their own ALTER TABLE ADD COLUMN statement."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_create=[
            Column(securable_type=SecurableType.COLUMN, full_name="cat.sch.orders.email", data_type="STRING"),
            Column(securable_type=SecurableType.COLUMN, full_name="cat.sch.orders.amount", data_type="DECIMAL(18,2)"),
        ],
    )

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 2
    assert all("ALTER TABLE" in s.upper() and "ADD COLUMN" in s.upper() for s in stmts)
    sql_blob = " ".join(stmts)
    assert "email" in sql_blob and "STRING" in sql_blob
    assert "amount" in sql_blob and "DECIMAL(18,2)" in sql_blob


def test_securable_executor_preserves_column_declaration_order_within_a_table():
    """Multiple Columns for the same parent table are emitted in their input-list
    order — not alphabetised by column name. The list order ultimately reflects
    the user's YAML declaration order."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_create=[
            Column(securable_type=SecurableType.COLUMN, full_name="cat.sch.t.zebra", data_type="STRING"),
            Column(securable_type=SecurableType.COLUMN, full_name="cat.sch.t.apple", data_type="STRING"),
            Column(securable_type=SecurableType.COLUMN, full_name="cat.sch.t.mango", data_type="STRING"),
        ],
    )

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    column_names = [s.split("ADD COLUMN `")[1].split("`")[0] for s in stmts]
    assert column_names == ["zebra", "apple", "mango"]


def test_securable_executor_groups_columns_by_parent_table_in_order():
    """Across multiple parent tables, columns are grouped together by parent;
    within each parent, the input-list order is preserved."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_create=[
            # Interleaved input order across two tables.
            Column(securable_type=SecurableType.COLUMN, full_name="cat.sch.t1.b", data_type="STRING"),
            Column(securable_type=SecurableType.COLUMN, full_name="cat.sch.t2.x", data_type="STRING"),
            Column(securable_type=SecurableType.COLUMN, full_name="cat.sch.t1.a", data_type="STRING"),
            Column(securable_type=SecurableType.COLUMN, full_name="cat.sch.t2.y", data_type="STRING"),
        ],
    )

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    column_names = [s.split("ADD COLUMN `")[1].split("`")[0] for s in stmts]
    # t1 columns appear together (in their input order: b then a),
    # then t2 columns together (x then y). Cross-table grouping protects
    # against parent-table interleaving — the SQL DDL is per-table anyway.
    t1_indices = [i for i, name in enumerate(column_names) if name in ("b", "a")]
    t2_indices = [i for i, name in enumerate(column_names) if name in ("x", "y")]
    assert max(t1_indices) < min(t2_indices) or max(t2_indices) < min(t1_indices), (
        f"Expected per-table grouping; got {column_names}"
    )
    # Within each parent, input order is preserved.
    assert column_names[t1_indices[0]] == "b" and column_names[t1_indices[1]] == "a"
    assert column_names[t2_indices[0]] == "x" and column_names[t2_indices[1]] == "y"


def test_securable_executor_alter_table_add_column_targets_parent_table():
    """The column's parent table (everything up to the last '.') is the ALTER TABLE target."""
    uc_helper = MagicMock()
    column = Column(
        securable_type=SecurableType.COLUMN,
        full_name="my_catalog.my_schema.my_table.my_col",
        data_type="INT",
    )
    diff = SecurableDiff(securables_to_create=[column])

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    sql = stmts[0]
    # Parent is my_catalog.my_schema.my_table; column is my_col
    assert "`my_catalog`.`my_schema`.`my_table`" in sql
    assert "`my_col` INT" in sql


def test_securable_executor_skips_alter_table_in_dry_run():
    """In dry-run mode, ALTER TABLE ADD COLUMN is not invoked on the SDK."""
    uc_helper = MagicMock()
    column = Column(
        securable_type=SecurableType.COLUMN,
        full_name="cat.sch.orders.email",
        data_type="STRING",
    )
    diff = SecurableDiff(securables_to_create=[column])

    execute_securable_diff(uc_helper, diff, ChangeLogger(dry_run=True), dry_run=True)

    uc_helper.execute_sql.assert_not_called()


def test_securable_executor_logs_error_and_continues_on_alter_table_failure():
    """An exception during one ALTER TABLE ADD COLUMN does not abort subsequent columns."""
    uc_helper = MagicMock()
    uc_helper.execute_sql.side_effect = [Exception("boom"), None]
    cl = ChangeLogger()
    diff = SecurableDiff(
        securables_to_create=[
            Column(securable_type=SecurableType.COLUMN, full_name="cat.sch.orders.fail", data_type="STRING"),
            Column(securable_type=SecurableType.COLUMN, full_name="cat.sch.orders.succeed", data_type="STRING"),
        ],
    )

    execute_securable_diff(uc_helper, diff, cl)

    assert uc_helper.execute_sql.call_count == 2
    assert cl.has_errors


def test_securable_executor_orders_columns_after_their_parent_table():
    """When a Column and its parent Table are both in to_create, the table is created first."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_create=[
            # Out of order on purpose.
            Column(securable_type=SecurableType.COLUMN, full_name="cat.sch.tbl.new_col", data_type="STRING"),
            Table(securable_type=SecurableType.TABLE, full_name="cat.sch.tbl",
                  columns=(Column(securable_type=SecurableType.COLUMN, full_name="cat.sch.tbl.a", data_type="STRING"),)),
        ],
    )

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    idx_table = next(i for i, s in enumerate(stmts) if "CREATE TABLE" in s.upper())
    idx_alter = next(i for i, s in enumerate(stmts) if "ALTER TABLE" in s.upper())
    assert idx_table < idx_alter


# ---------------------------------------------------------------------------
# CREATE SQL: comment + location embedding
# ---------------------------------------------------------------------------


def test_securable_executor_builds_create_catalog_sql_with_managed_location_and_comment():
    """CREATE CATALOG embeds MANAGED LOCATION and COMMENT when set on the Securable."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_create=[Securable(
            securable_type=SecurableType.CATALOG,
            full_name="my_cat",
            comment="Prod",
            location="s3://prod/my_cat",
        )],
    )

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    _assert_sql_contains(stmts[0], "CREATE CATALOG", "my_cat", "MANAGED LOCATION", "s3://prod/my_cat", "COMMENT", "Prod")


def test_securable_executor_builds_create_catalog_sql_minimal_when_no_attributes_set():
    """Regression: a catalog with no comment/location keeps the existing CREATE form."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_create=[Securable(securable_type=SecurableType.CATALOG, full_name="my_cat")],
    )

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    assert "MANAGED LOCATION" not in stmts[0].upper()
    assert "COMMENT" not in stmts[0].upper()


def test_securable_executor_builds_create_schema_sql_with_managed_location_and_comment():
    """CREATE SCHEMA embeds MANAGED LOCATION and COMMENT when set."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_create=[Securable(
            securable_type=SecurableType.SCHEMA,
            full_name="my_cat.sales",
            comment="Sales data",
            location="s3://prod/sales",
        )],
    )

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    _assert_sql_contains(stmts[0], "CREATE SCHEMA", "my_cat.sales", "MANAGED LOCATION", "s3://prod/sales", "COMMENT", "Sales data")


def test_securable_executor_builds_create_table_sql_with_external_location_and_comment():
    """CREATE TABLE with a LOCATION makes it external; embeds COMMENT when set."""
    uc_helper = MagicMock()
    table = Table(
        securable_type=SecurableType.TABLE,
        full_name="cat.sch.orders",
        columns=(Column(securable_type=SecurableType.COLUMN, full_name="cat.sch.orders.id", data_type="BIGINT"),),
        comment="Orders fact",
        location="s3://ext/orders",
    )
    diff = SecurableDiff(securables_to_create=[table])

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    _assert_sql_contains(stmts[0], "CREATE TABLE", "cat.sch.orders", "COMMENT", "Orders fact", "LOCATION", "s3://ext/orders")


def test_securable_executor_builds_create_table_sql_omits_location_when_unset():
    """CREATE TABLE without LOCATION stays managed — no LOCATION clause emitted."""
    uc_helper = MagicMock()
    table = Table(
        securable_type=SecurableType.TABLE,
        full_name="cat.sch.orders",
        columns=(Column(securable_type=SecurableType.COLUMN, full_name="cat.sch.orders.id", data_type="BIGINT"),),
    )
    diff = SecurableDiff(securables_to_create=[table])

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    assert " LOCATION " not in stmts[0].upper()


def test_securable_executor_builds_create_external_volume_sql_when_location_is_set():
    """A Volume Securable with LOCATION produces CREATE EXTERNAL VOLUME with the LOCATION clause."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_create=[Securable(
            securable_type=SecurableType.VOLUME,
            full_name="cat.sch.raw",
            comment="Raw landing",
            location="s3://ext/raw",
        )],
    )

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    _assert_sql_contains(stmts[0], "CREATE EXTERNAL VOLUME", "cat.sch.raw", "LOCATION", "s3://ext/raw", "COMMENT", "Raw landing")


def test_securable_executor_builds_create_managed_volume_sql_when_location_is_unset():
    """A Volume Securable without LOCATION produces a managed CREATE VOLUME (no EXTERNAL keyword)."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_create=[Securable(securable_type=SecurableType.VOLUME, full_name="cat.sch.raw")],
    )

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    assert "EXTERNAL VOLUME" not in stmts[0].upper()
    _assert_sql_contains(stmts[0], "CREATE VOLUME", "cat.sch.raw")


# ---------------------------------------------------------------------------
# ALTER comment via SQL
# ---------------------------------------------------------------------------


def test_securable_executor_alters_catalog_comment_via_alter_sql():
    """A comment AttributeUpdate on a CATALOG produces ALTER CATALOG ... SET COMMENT '...'."""
    uc_helper = MagicMock()
    diff = SecurableDiff(attributes_to_update=[AttributeUpdate(
        securable_type=SecurableType.CATALOG,
        full_name="my_cat",
        attribute="comment",
        old_value="Old",
        new_value="New",
    )])

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    _assert_sql_contains(stmts[0], "ALTER CATALOG", "my_cat", "SET COMMENT", "New")


def test_securable_executor_alters_schema_comment_via_alter_sql():
    uc_helper = MagicMock()
    diff = SecurableDiff(attributes_to_update=[AttributeUpdate(
        securable_type=SecurableType.SCHEMA,
        full_name="cat.sales",
        attribute="comment",
        old_value="Old",
        new_value="New",
    )])

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    _assert_sql_contains(stmts[0], "ALTER SCHEMA", "cat.sales", "SET COMMENT", "New")


def test_securable_executor_alters_table_comment_via_comment_on_sql():
    """Table comment uses COMMENT ON TABLE ... IS '...' (not ALTER TABLE SET COMMENT)."""
    uc_helper = MagicMock()
    diff = SecurableDiff(attributes_to_update=[AttributeUpdate(
        securable_type=SecurableType.TABLE,
        full_name="cat.sales.orders",
        attribute="comment",
        old_value="Old",
        new_value="New",
    )])

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    _assert_sql_contains(stmts[0], "COMMENT ON TABLE", "cat.sales.orders", "IS", "New")


def test_securable_executor_alters_volume_comment_via_comment_on_sql():
    uc_helper = MagicMock()
    diff = SecurableDiff(attributes_to_update=[AttributeUpdate(
        securable_type=SecurableType.VOLUME,
        full_name="cat.landing.raw",
        attribute="comment",
        old_value="Old",
        new_value="New",
    )])

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    _assert_sql_contains(stmts[0], "COMMENT ON VOLUME", "cat.landing.raw", "IS", "New")


def test_securable_executor_escapes_single_quotes_in_comment_update():
    """Comments with single quotes are SQL-escaped before embedding."""
    uc_helper = MagicMock()
    diff = SecurableDiff(attributes_to_update=[AttributeUpdate(
        securable_type=SecurableType.CATALOG,
        full_name="my_cat",
        attribute="comment",
        old_value="",
        new_value="It's risky",
    )])

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    assert "It\\'s risky" in stmts[0]


# ---------------------------------------------------------------------------
# Dry-run + error continuation for new attribute paths
# ---------------------------------------------------------------------------


def test_securable_executor_skips_alter_comment_in_dry_run():
    """In dry-run mode, comment ALTER statements are not executed against the helper."""
    uc_helper = MagicMock()
    diff = SecurableDiff(attributes_to_update=[AttributeUpdate(
        securable_type=SecurableType.CATALOG,
        full_name="my_cat",
        attribute="comment",
        old_value="Old",
        new_value="New",
    )])

    stmts = execute_securable_diff(uc_helper, diff, ChangeLogger(), dry_run=True)

    assert stmts == []
    uc_helper.execute_sql.assert_not_called()


def test_securable_executor_logs_error_and_continues_on_alter_comment_failure():
    """If the SQL ALTER fails, log an ExecutionError and continue to the next update."""
    uc_helper = MagicMock()
    uc_helper.execute_sql.side_effect = [RuntimeError("boom"), None]
    logger = ChangeLogger()
    diff = SecurableDiff(attributes_to_update=[
        AttributeUpdate(
            securable_type=SecurableType.CATALOG,
            full_name="bad_cat",
            attribute="comment",
            old_value="Old",
            new_value="New",
        ),
        AttributeUpdate(
            securable_type=SecurableType.SCHEMA,
            full_name="good.sch",
            attribute="comment",
            old_value="Old",
            new_value="New",
        ),
    ])

    stmts = execute_securable_diff(uc_helper, diff, logger)

    assert len(stmts) == 1
    _assert_sql_contains(stmts[0], "ALTER SCHEMA", "good.sch")
    assert len(logger.errors) == 1
    assert "ALTER CATALOG" in logger.errors[0].context
