from __future__ import annotations

from uc_governor.privileges.differ import compute_privilege_diff
from uc_governor.privileges.state import PrivilegeDiff, SecurablePrivilege
from uc_governor.types import Principal, PrincipalType, PrivilegeType, SecurableType


# ---------------------------------------------------------------------------
# Privileges to grant
# ---------------------------------------------------------------------------


def test_privilege_differ_computes_privileges_to_grant():
    """A desired privilege not present in actual appears in to_grant."""
    desired = {
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
    }
    actual = {
        SecurablePrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="catalog.schema.orders",
            principal=Principal(PrincipalType.GROUP, "data_analysts", "data_analysts"),
            privilege_type=PrivilegeType.SELECT,
        ),
    }

    diff = compute_privilege_diff(desired, actual)

    assert diff.to_grant == {
        SecurablePrivilege(
            securable_type=SecurableType.SCHEMA,
            securable_full_name="catalog.sales",
            principal=Principal(PrincipalType.GROUP, "data_engineers", "data_engineers"),
            privilege_type=PrivilegeType.USE_SCHEMA,
        ),
    }
    assert diff.to_revoke == set()


# ---------------------------------------------------------------------------
# Privileges to revoke
# ---------------------------------------------------------------------------


def test_privilege_differ_computes_privileges_to_revoke():
    """An actual privilege not present in desired appears in to_revoke."""
    desired = {
        SecurablePrivilege(
            securable_type=SecurableType.CATALOG,
            securable_full_name="my_catalog",
            principal=Principal(PrincipalType.GROUP, "data_analysts", "data_analysts"),
            privilege_type=PrivilegeType.USE_CATALOG,
        ),
    }
    actual = {
        SecurablePrivilege(
            securable_type=SecurableType.CATALOG,
            securable_full_name="my_catalog",
            principal=Principal(PrincipalType.GROUP, "data_analysts", "data_analysts"),
            privilege_type=PrivilegeType.USE_CATALOG,
        ),
        SecurablePrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="catalog.sales.orders",
            principal=Principal(PrincipalType.GROUP, "temp_users", "temp_users"),
            privilege_type=PrivilegeType.SELECT,
        ),
    }

    diff = compute_privilege_diff(desired, actual)

    assert diff.to_grant == set()
    assert diff.to_revoke == {
        SecurablePrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="catalog.sales.orders",
            principal=Principal(PrincipalType.GROUP, "temp_users", "temp_users"),
            privilege_type=PrivilegeType.SELECT,
        ),
    }


# ---------------------------------------------------------------------------
# In-sync — empty diff
# ---------------------------------------------------------------------------


def test_privilege_differ_returns_empty_diff_when_in_sync():
    """Identical desired and actual sets produce an entirely empty diff."""
    privileges = {
        SecurablePrivilege(
            securable_type=SecurableType.CATALOG,
            securable_full_name="my_catalog",
            principal=Principal(PrincipalType.GROUP, "data_analysts", "data_analysts"),
            privilege_type=PrivilegeType.USE_CATALOG,
        ),
        SecurablePrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="catalog.sales.orders",
            principal=Principal(PrincipalType.GROUP, "data_engineers", "data_engineers"),
            privilege_type=PrivilegeType.SELECT,
        ),
    }

    diff = compute_privilege_diff(privileges, privileges)

    assert diff == PrivilegeDiff()


# ---------------------------------------------------------------------------
# Empty desired
# ---------------------------------------------------------------------------


def test_privilege_differ_handles_empty_desired():
    """Empty desired with non-empty actual produces only to_revoke entries."""
    actual = {
        SecurablePrivilege(
            securable_type=SecurableType.VOLUME,
            securable_full_name="catalog.landing.raw_events",
            principal=Principal(PrincipalType.GROUP, "data_engineers", "data_engineers"),
            privilege_type=PrivilegeType.READ_VOLUME,
        ),
        SecurablePrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="catalog.sales.orders",
            principal=Principal(PrincipalType.GROUP, "data_analysts", "data_analysts"),
            privilege_type=PrivilegeType.SELECT,
        ),
    }

    diff = compute_privilege_diff(set(), actual)

    assert diff.to_revoke == actual
    assert diff.to_grant == set()


# ---------------------------------------------------------------------------
# Empty actual
# ---------------------------------------------------------------------------


def test_privilege_differ_handles_empty_actual():
    """Non-empty desired with empty actual produces only to_grant entries."""
    desired = {
        SecurablePrivilege(
            securable_type=SecurableType.CATALOG,
            securable_full_name="my_catalog",
            principal=Principal(PrincipalType.GROUP, "data_analysts", "data_analysts"),
            privilege_type=PrivilegeType.USE_CATALOG,
        ),
        SecurablePrivilege(
            securable_type=SecurableType.SCHEMA,
            securable_full_name="my_catalog.sales",
            principal=Principal(PrincipalType.GROUP, "data_engineers", "data_engineers"),
            privilege_type=PrivilegeType.USE_SCHEMA,
        ),
    }

    diff = compute_privilege_diff(desired, set())

    assert diff.to_grant == desired
    assert diff.to_revoke == set()
