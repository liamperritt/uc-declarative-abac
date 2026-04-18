from __future__ import annotations

from unittest.mock import MagicMock

from uc_abac_governor.logger import ChangeLogger
from uc_abac_governor.securables.executor import execute_securable_diff
from uc_abac_governor.securables.state import (
    AttributeUpdate,
    FunctionInfo,
    SecurableDiff,
)
from uc_abac_governor.principals.state import Principal
from uc_abac_governor.types import PrincipalType, SecurableType


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
    """A FunctionInfo in securables_to_create produces CREATE FUNCTION SQL."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_create=[
            FunctionInfo(
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
    """A FunctionInfo in securables_to_replace produces CREATE OR REPLACE FUNCTION SQL."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_replace=[
            FunctionInfo(
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
    """A FunctionInfo with no parameters produces empty parens before RETURN."""
    uc_helper = MagicMock()
    diff = SecurableDiff(
        securables_to_create=[
            FunctionInfo(
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
            FunctionInfo(
                securable_type=SecurableType.FUNCTION,
                full_name="cat.schema.func_a",
                parameters=(("col", "STRING"),),
                definition="col",
            ),
            FunctionInfo(
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
            FunctionInfo(
                securable_type=SecurableType.FUNCTION,
                full_name="cat.schema.func_create",
                parameters=(("col", "STRING"),),
                definition="col",
            ),
        ],
        securables_to_replace=[
            FunctionInfo(
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
