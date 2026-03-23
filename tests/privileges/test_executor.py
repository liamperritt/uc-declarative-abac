from __future__ import annotations

from unittest.mock import MagicMock

from uc_governor.logger import ChangeLogger
from uc_governor.privileges.executor import execute_privilege_diff
from uc_governor.privileges.state import PrivilegeDiff, SecurablePrivilege
from uc_governor.types import PrincipalValidationError, SecurableType


def _assert_sql_contains(sql: str, *fragments: str):
    """Assert that every fragment appears in the SQL string (case-insensitive, ignoring backticks)."""
    normalised = sql.upper().replace("`", "")
    for fragment in fragments:
        assert fragment.upper() in normalised, (
            f"Expected {fragment!r} in SQL: {sql}"
        )


def _make_acct_helper(sp_mapping: dict[str, str] | None = None):
    """Create a mock AccountHelper.

    *sp_mapping* maps service-principal display names to application IDs.
    Principals not in the mapping raise PrincipalValidationError (i.e. they
    are not service principals).
    """
    sp_mapping = sp_mapping or {}
    acct_helper = MagicMock()

    def _resolve(display_name: str) -> str:
        if display_name in sp_mapping:
            return sp_mapping[display_name]
        raise PrincipalValidationError(
            f"{display_name} is not a service principal"
        )

    acct_helper.get_sp_application_id.side_effect = _resolve
    return acct_helper


# ---------------------------------------------------------------------------
# 1. GRANT SQL generation
# ---------------------------------------------------------------------------


def test_privilege_executor_generates_grant_sql():
    """to_grant privileges produce GRANT statements with correct components."""
    uc_helper = MagicMock()
    acct_helper = _make_acct_helper()

    diff = PrivilegeDiff(
        to_grant={
            SecurablePrivilege(
                securable_type=SecurableType.TABLE,
                securable_full_name="catalog.schema.orders",
                principal="data_analysts",
                privilege_type="SELECT",
            ),
        },
    )

    stmts = execute_privilege_diff(uc_helper, acct_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]

    _assert_sql_contains(sql, "GRANT", "SELECT", "TABLE", "catalog.schema.orders", "data_analysts")
    _assert_sql_contains(sql, "TO")
    # Securable name should be backtick-quoted
    assert "`catalog`.`schema`.`orders`" in sql
    uc_helper.execute_sql.assert_called_once_with(sql)


# ---------------------------------------------------------------------------
# 2. REVOKE SQL generation
# ---------------------------------------------------------------------------


def test_privilege_executor_generates_revoke_sql():
    """to_revoke privileges produce REVOKE statements with correct components."""
    uc_helper = MagicMock()
    acct_helper = _make_acct_helper()

    diff = PrivilegeDiff(
        to_revoke={
            SecurablePrivilege(
                securable_type=SecurableType.SCHEMA,
                securable_full_name="catalog.sales",
                principal="temp_users",
                privilege_type="USE_SCHEMA",
            ),
        },
    )

    stmts = execute_privilege_diff(uc_helper, acct_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]

    _assert_sql_contains(sql, "REVOKE", "USE_SCHEMA", "SCHEMA", "catalog.sales", "temp_users")
    # REVOKE statements use the FROM keyword
    _assert_sql_contains(sql, "FROM")
    uc_helper.execute_sql.assert_called_once_with(sql)


# ---------------------------------------------------------------------------
# 3. Service principal resolution — display name → application ID
# ---------------------------------------------------------------------------


def test_privilege_executor_resolves_sp_display_name_to_application_id():
    """When a principal is a service principal, the executor uses its application_id."""
    uc_helper = MagicMock()
    acct_helper = _make_acct_helper(
        sp_mapping={"my-etl-service": "abcd1234-0000-0000-0000-000000000001"}
    )

    diff = PrivilegeDiff(
        to_grant={
            SecurablePrivilege(
                securable_type=SecurableType.CATALOG,
                securable_full_name="my_catalog",
                principal="my-etl-service",
                privilege_type="USE_CATALOG",
            ),
        },
    )

    stmts = execute_privilege_diff(uc_helper, acct_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]

    # The application ID should appear in the SQL, not the display name
    _assert_sql_contains(sql, "abcd1234-0000-0000-0000-000000000001")
    _assert_sql_contains(sql, "GRANT", "USE_CATALOG", "CATALOG", "my_catalog")
    uc_helper.execute_sql.assert_called_once_with(sql)


# ---------------------------------------------------------------------------
# 4. Return value contains every executed SQL statement
# ---------------------------------------------------------------------------


def test_privilege_executor_returns_all_executed_statements():
    """The return list contains every SQL statement that was executed."""
    uc_helper = MagicMock()
    acct_helper = _make_acct_helper()

    diff = PrivilegeDiff(
        to_grant={
            SecurablePrivilege(
                securable_type=SecurableType.TABLE,
                securable_full_name="catalog.schema.orders",
                principal="data_analysts",
                privilege_type="SELECT",
            ),
        },
        to_revoke={
            SecurablePrivilege(
                securable_type=SecurableType.VOLUME,
                securable_full_name="catalog.landing.raw_events",
                principal="data_engineers",
                privilege_type="READ_VOLUME",
            ),
        },
    )

    stmts = execute_privilege_diff(uc_helper, acct_helper, diff, ChangeLogger())

    # Exactly two statements: one GRANT, one REVOKE.
    assert len(stmts) == 2

    grant_stmts = [s for s in stmts if "GRANT" in s.upper() and "REVOKE" not in s.upper()]
    revoke_stmts = [s for s in stmts if "REVOKE" in s.upper()]

    assert len(grant_stmts) == 1, f"Expected exactly one GRANT statement, got {len(grant_stmts)}"
    assert len(revoke_stmts) == 1, f"Expected exactly one REVOKE statement, got {len(revoke_stmts)}"

    # Every returned statement must have been passed to execute_sql.
    executed_sqls = [call.args[0] for call in uc_helper.execute_sql.call_args_list]
    assert set(stmts) == set(executed_sqls)


# ---------------------------------------------------------------------------
# 5. Empty diff — no execute_sql calls
# ---------------------------------------------------------------------------


def test_privilege_executor_executes_nothing_given_empty_diff():
    """An empty PrivilegeDiff should produce no SQL and no execute_sql calls."""
    uc_helper = MagicMock()
    acct_helper = _make_acct_helper()

    diff = PrivilegeDiff()

    stmts = execute_privilege_diff(uc_helper, acct_helper, diff, ChangeLogger())

    assert stmts == []
    uc_helper.execute_sql.assert_not_called()
