from __future__ import annotations

from unittest.mock import MagicMock

from uc_abac_governor.logger import ChangeLogger
from uc_abac_governor.privileges.executor import execute_privilege_diff
from uc_abac_governor.privileges.state import PrivilegeDiff, SecurablePrivilege
from uc_abac_governor.principals.state import Principal
from uc_abac_governor.types import PrincipalType, PrivilegeType, SecurableType


def _assert_sql_contains(sql: str, *fragments: str):
    """Assert that every fragment appears in the SQL string (case-insensitive, ignoring backticks)."""
    normalised = sql.upper().replace("`", "")
    for fragment in fragments:
        assert fragment.upper() in normalised, (
            f"Expected {fragment!r} in SQL: {sql}"
        )


# ---------------------------------------------------------------------------
# SQL generation
# ---------------------------------------------------------------------------


def test_privilege_executor_generates_grant_sql():
    """to_grant privileges produce GRANT statements with correct components."""
    uc_helper = MagicMock()


    diff = PrivilegeDiff(
        to_grant={
            SecurablePrivilege(
                securable_type=SecurableType.TABLE,
                securable_full_name="catalog.schema.orders",
                principal=Principal(PrincipalType.GROUP, "data_analysts", "data_analysts"),
                privilege_type=PrivilegeType.SELECT,
            ),
        },
    )

    stmts = execute_privilege_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]

    _assert_sql_contains(sql, "GRANT", "SELECT", "TABLE", "catalog.schema.orders", "data_analysts")
    _assert_sql_contains(sql, "TO")
    # Securable name should be backtick-quoted
    assert "`catalog`.`schema`.`orders`" in sql
    uc_helper.execute_sql.assert_called_once_with(sql)


def test_privilege_executor_generates_revoke_sql():
    """to_revoke privileges produce REVOKE statements with correct components."""
    uc_helper = MagicMock()


    diff = PrivilegeDiff(
        to_revoke={
            SecurablePrivilege(
                securable_type=SecurableType.SCHEMA,
                securable_full_name="catalog.sales",
                principal=Principal(PrincipalType.GROUP, "temp_users", "temp_users"),
                privilege_type=PrivilegeType.USE_SCHEMA,
            ),
        },
    )

    stmts = execute_privilege_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]

    _assert_sql_contains(sql, "REVOKE", "USE_SCHEMA", "SCHEMA", "catalog.sales", "temp_users")
    # REVOKE statements use the FROM keyword
    _assert_sql_contains(sql, "FROM")
    uc_helper.execute_sql.assert_called_once_with(sql)


# ---------------------------------------------------------------------------
# Principal resolution
# ---------------------------------------------------------------------------


def test_privilege_executor_resolves_sp_display_name_to_application_id():
    """When a principal is a service principal, the executor uses its application_id."""
    uc_helper = MagicMock()


    diff = PrivilegeDiff(
        to_grant={
            SecurablePrivilege(
                securable_type=SecurableType.CATALOG,
                securable_full_name="my_catalog",
                principal=Principal(PrincipalType.SERVICE_PRINCIPAL, "abcd1234-0000-0000-0000-000000000001", "my-etl-service"),
                privilege_type=PrivilegeType.USE_CATALOG,
            ),
        },
    )

    stmts = execute_privilege_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]

    # The application ID should appear in the SQL, not the display name
    _assert_sql_contains(sql, "abcd1234-0000-0000-0000-000000000001")
    _assert_sql_contains(sql, "GRANT", "USE_CATALOG", "CATALOG", "my_catalog")
    uc_helper.execute_sql.assert_called_once_with(sql)


def test_privilege_executor_uses_principal_identifier_in_grant_sql():
    """When principal is a Principal object, the SQL uses its identifier (not display_name)."""
    from uc_abac_governor.principals.state import Principal
    from uc_abac_governor.types import PrincipalType

    uc_helper = MagicMock()


    priv = SecurablePrivilege(
        securable_type=SecurableType.TABLE,
        securable_full_name="catalog.schema.orders",
        principal=Principal(PrincipalType.SERVICE_PRINCIPAL, "app-id-123", "my-etl-sp"),
        privilege_type=PrivilegeType.SELECT,
    )

    diff = PrivilegeDiff(to_grant={priv})

    stmts = execute_privilege_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]

    # The system identifier must appear in the SQL
    assert "app-id-123" in sql
    # The display name must NOT appear in the SQL
    assert "my-etl-sp" not in sql


# ---------------------------------------------------------------------------
# SQL statement executions
# ---------------------------------------------------------------------------


def test_privilege_executor_returns_all_executed_statements():
    """The return list contains every SQL statement that was executed."""
    uc_helper = MagicMock()


    diff = PrivilegeDiff(
        to_grant={
            SecurablePrivilege(
                securable_type=SecurableType.TABLE,
                securable_full_name="catalog.schema.orders",
                principal=Principal(PrincipalType.GROUP, "data_analysts", "data_analysts"),
                privilege_type=PrivilegeType.SELECT,
            ),
        },
        to_revoke={
            SecurablePrivilege(
                securable_type=SecurableType.VOLUME,
                securable_full_name="catalog.landing.raw_events",
                principal=Principal(PrincipalType.GROUP, "data_engineers", "data_engineers"),
                privilege_type=PrivilegeType.READ_VOLUME,
            ),
        },
    )

    stmts = execute_privilege_diff(uc_helper, diff, ChangeLogger())

    # Exactly two statements: one GRANT, one REVOKE.
    assert len(stmts) == 2

    grant_stmts = [s for s in stmts if "GRANT" in s.upper() and "REVOKE" not in s.upper()]
    revoke_stmts = [s for s in stmts if "REVOKE" in s.upper()]

    assert len(grant_stmts) == 1, f"Expected exactly one GRANT statement, got {len(grant_stmts)}"
    assert len(revoke_stmts) == 1, f"Expected exactly one REVOKE statement, got {len(revoke_stmts)}"

    # Every returned statement must have been passed to execute_sql.
    executed_sqls = [call.args[0] for call in uc_helper.execute_sql.call_args_list]
    assert set(stmts) == set(executed_sqls)


def test_privilege_executor_executes_nothing_given_empty_diff():
    """An empty PrivilegeDiff should produce no SQL and no execute_sql calls."""
    uc_helper = MagicMock()


    diff = PrivilegeDiff()

    stmts = execute_privilege_diff(uc_helper, diff, ChangeLogger())

    assert stmts == []
    uc_helper.execute_sql.assert_not_called()


def test_privilege_executor_executes_sql_in_securable_order():
    """Privileges are executed ordered by securable type then full name."""
    uc_helper = MagicMock()

    diff = PrivilegeDiff(
        to_grant={
            SecurablePrivilege(
                securable_type=SecurableType.TABLE,
                securable_full_name="cat.s.table_b",
                principal=Principal(PrincipalType.GROUP, "team_a", "team_a"),
                privilege_type=PrivilegeType.SELECT,
            ),
            SecurablePrivilege(
                securable_type=SecurableType.CATALOG,
                securable_full_name="cat_a",
                principal=Principal(PrincipalType.GROUP, "team_b", "team_b"),
                privilege_type=PrivilegeType.USE_CATALOG,
            ),
            SecurablePrivilege(
                securable_type=SecurableType.TABLE,
                securable_full_name="cat.s.table_a",
                principal=Principal(PrincipalType.GROUP, "team_c", "team_c"),
                privilege_type=PrivilegeType.SELECT,
            ),
            SecurablePrivilege(
                securable_type=SecurableType.CATALOG,
                securable_full_name="cat_b",
                principal=Principal(PrincipalType.GROUP, "team_d", "team_d"),
                privilege_type=PrivilegeType.USE_CATALOG,
            ),
        },
    )

    stmts = execute_privilege_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 4

    # Expected order: CATALOG cat_a, CATALOG cat_b, TABLE cat.s.table_a, TABLE cat.s.table_b
    assert "cat_a" in stmts[0]
    assert "cat_b" in stmts[1]
    assert "cat.s.table_a".replace(".", "`.`") in stmts[2] or "cat.s.table_a" in stmts[2].replace("`", "")
    assert "cat.s.table_b".replace(".", "`.`") in stmts[3] or "cat.s.table_b" in stmts[3].replace("`", "")


# ---------------------------------------------------------------------------
# Error collection
# ---------------------------------------------------------------------------


def test_privilege_executor_continues_after_sql_failure():
    """When one SQL call fails, execution continues and the error is collected."""
    uc_helper = MagicMock()

    call_count = {"n": 0}

    def _fail_first(sql):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("SQL execution failed")

    uc_helper.execute_sql.side_effect = _fail_first

    change_logger = ChangeLogger()

    diff = PrivilegeDiff(
        to_grant={
            SecurablePrivilege(
                securable_type=SecurableType.TABLE,
                securable_full_name="catalog.schema.orders",
                principal=Principal(PrincipalType.GROUP, "data_analysts", "data_analysts"),
                privilege_type=PrivilegeType.SELECT,
            ),
            SecurablePrivilege(
                securable_type=SecurableType.SCHEMA,
                securable_full_name="catalog.sales",
                principal=Principal(PrincipalType.GROUP, "data_engineers", "data_engineers"),
                privilege_type=PrivilegeType.USE_SCHEMA,
            ),
        },
    )

    stmts = execute_privilege_diff(uc_helper, diff, change_logger)

    # Both calls were attempted
    assert uc_helper.execute_sql.call_count == 2
    # One error collected
    assert change_logger.has_errors is True
    assert len(change_logger.errors) == 1
    # Only the successful statement is returned
    assert len(stmts) == 1


def test_privilege_executor_collects_all_errors():
    """When all SQL calls fail, all errors are collected and no statements returned."""
    uc_helper = MagicMock()

    uc_helper.execute_sql.side_effect = RuntimeError("SQL execution failed")

    change_logger = ChangeLogger()

    diff = PrivilegeDiff(
        to_grant={
            SecurablePrivilege(
                securable_type=SecurableType.TABLE,
                securable_full_name="catalog.schema.orders",
                principal=Principal(PrincipalType.GROUP, "data_analysts", "data_analysts"),
                privilege_type=PrivilegeType.SELECT,
            ),
            SecurablePrivilege(
                securable_type=SecurableType.SCHEMA,
                securable_full_name="catalog.sales",
                principal=Principal(PrincipalType.GROUP, "data_engineers", "data_engineers"),
                privilege_type=PrivilegeType.USE_SCHEMA,
            ),
        },
    )

    stmts = execute_privilege_diff(uc_helper, diff, change_logger)

    # Both calls were attempted
    assert uc_helper.execute_sql.call_count == 2
    # Both errors collected
    assert len(change_logger.errors) == 2
    # No successful statements
    assert stmts == []


# ---------------------------------------------------------------------------
# Dry-run mode
# ---------------------------------------------------------------------------


def test_privilege_executor_logs_changes_in_dry_run():
    """dry_run=True logs all privilege changes without executing any SQL."""
    uc_helper = MagicMock()
    change_logger = ChangeLogger()

    diff = PrivilegeDiff(
        to_grant={
            SecurablePrivilege(
                securable_type=SecurableType.SCHEMA,
                securable_full_name="catalog.sales",
                principal=Principal(PrincipalType.GROUP, "data_engineers", "data_engineers"),
                privilege_type=PrivilegeType.USE_SCHEMA,
            ),
        },
        to_revoke={
            SecurablePrivilege(
                securable_type=SecurableType.TABLE,
                securable_full_name="catalog.schema.orders",
                principal=Principal(PrincipalType.GROUP, "temp_users", "temp_users"),
                privilege_type=PrivilegeType.SELECT,
            ),
        },
    )

    stmts = execute_privilege_diff(uc_helper, diff, change_logger, dry_run=True)

    # No SQL executed
    assert stmts == []
    uc_helper.execute_sql.assert_not_called()

    # Both changes were logged
    assert change_logger._privileges_granted == 1
    assert change_logger._privileges_revoked == 1
