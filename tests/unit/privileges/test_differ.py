from __future__ import annotations

from unittest.mock import MagicMock

from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.principals import (
    Principal,
    PrincipalResolver,
)
from uc_declarative_abac.privileges import (
    compute_privilege_diff,
    PrivilegeDiff,
    SecurablePrivilege,
)
from uc_declarative_abac.types import (
    PrincipalType,
    PrivilegeType,
    SecurableType,
)


def _resolver() -> PrincipalResolver:
    """A resolver whose ws_helper is never consulted — test inputs are already resolved."""
    return PrincipalResolver(MagicMock())


def _failing_resolver() -> PrincipalResolver:
    """A resolver whose ws_helper raises PrincipalValidationError for any lookup —
    used to exercise the unresolvable-principal paths."""
    from uc_declarative_abac.utils import PrincipalValidationError

    ws_helper = MagicMock()
    ws_helper.resolve_by_name.side_effect = lambda n: (_ for _ in ()).throw(
        PrincipalValidationError(f"Principal not found: {n}")
    )
    ws_helper.resolve_by_identifier.side_effect = lambda i: (_ for _ in ()).throw(
        PrincipalValidationError(f"Principal not found by identifier: {i}")
    )
    return PrincipalResolver(ws_helper)


def _change_logger() -> ChangeLogger:
    return ChangeLogger()


# ---------------------------------------------------------------------------
# Unresolvable principals: actual-side is a non-fatal warning, desired-side fatal
# ---------------------------------------------------------------------------


def test_privilege_differ_actual_side_unresolvable_principal_is_warning_not_error():
    """A privilege in ACTUAL state whose identifier-only principal (e.g. a
    Databricks system service principal) cannot be resolved is dropped from
    to_revoke and logged as a non-fatal warning — the run does not fail."""
    actual = {
        SecurablePrivilege(
            securable_type=SecurableType.SCHEMA,
            securable_full_name="liam_perritt.lff_sqlserver_bronze",
            principal=Principal(
                PrincipalType.UNKNOWN, identifier="dd4ded68-9a65-4df9-ad70-832718d36e10"
            ),
            privilege_type=PrivilegeType.USE_SCHEMA,
        ),
    }
    change_logger = _change_logger()

    diff = compute_privilege_diff(set(), actual, _failing_resolver(), change_logger)

    assert diff.to_revoke == set()
    assert change_logger.has_errors is False
    assert len(change_logger.warnings) == 1


def test_privilege_differ_suppresses_warning_for_ignored_unresolvable_principal():
    """An unresolvable actual-state principal whose identifier is in
    ignore_unresolvable is still dropped from to_revoke, but its resolution-failure
    warning is suppressed."""
    ignored_id = "dd4ded68-9a65-4df9-ad70-832718d36e10"
    actual = {
        SecurablePrivilege(
            securable_type=SecurableType.SCHEMA,
            securable_full_name="liam_perritt.lff_sqlserver_bronze",
            principal=Principal(PrincipalType.UNKNOWN, identifier=ignored_id),
            privilege_type=PrivilegeType.USE_SCHEMA,
        ),
    }
    change_logger = _change_logger()

    diff = compute_privilege_diff(
        set(), actual, _failing_resolver(), change_logger,
        ignore_unresolvable=frozenset({ignored_id}),
    )

    assert diff.to_revoke == set()
    assert change_logger.has_errors is False
    assert change_logger.warnings == []


def test_privilege_differ_resolvable_ignored_principal_still_processed():
    """A principal listed in ignore_unresolvable that DOES resolve is unaffected —
    it resolves normally and its privilege still flows into the diff (to_revoke
    here, since it's in actual but not desired)."""
    listed_id = "app-id-123"
    resolved = Principal(PrincipalType.SERVICE_PRINCIPAL, identifier=listed_id, name="sp_sales")
    ws_helper = MagicMock()
    ws_helper.resolve_by_identifier.return_value = resolved
    resolver = PrincipalResolver(ws_helper)

    actual = {
        SecurablePrivilege(
            securable_type=SecurableType.SCHEMA,
            securable_full_name="cat.sales",
            principal=Principal(PrincipalType.UNKNOWN, identifier=listed_id),
            privilege_type=PrivilegeType.USE_SCHEMA,
        ),
    }
    change_logger = _change_logger()

    diff = compute_privilege_diff(
        set(), actual, resolver, change_logger,
        ignore_unresolvable=frozenset({listed_id}),
    )

    assert len(diff.to_revoke) == 1
    revoked = next(iter(diff.to_revoke))
    assert revoked.principal == resolved
    assert change_logger.has_errors is False
    assert change_logger.warnings == []


def test_privilege_differ_desired_side_unresolvable_principal_is_error():
    """A privilege in DESIRED state (config) whose name-only principal cannot be
    resolved is dropped from to_grant and logged as a fatal error."""
    desired = {
        SecurablePrivilege(
            securable_type=SecurableType.SCHEMA,
            securable_full_name="cat.sales",
            principal=Principal(PrincipalType.UNKNOWN, name="typo_group"),
            privilege_type=PrivilegeType.USE_SCHEMA,
        ),
    }
    change_logger = _change_logger()

    diff = compute_privilege_diff(desired, set(), _failing_resolver(), change_logger)

    assert diff.to_grant == set()
    assert change_logger.has_errors is True


# ---------------------------------------------------------------------------
# Privileges to grant and revoke
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

    diff = compute_privilege_diff(desired, actual, _resolver(), _change_logger())

    assert diff.to_grant == {
        SecurablePrivilege(
            securable_type=SecurableType.SCHEMA,
            securable_full_name="catalog.sales",
            principal=Principal(PrincipalType.GROUP, "data_engineers", "data_engineers"),
            privilege_type=PrivilegeType.USE_SCHEMA,
        ),
    }
    assert diff.to_revoke == set()


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

    diff = compute_privilege_diff(desired, actual, _resolver(), _change_logger())

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
# Empty sets
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

    diff = compute_privilege_diff(privileges, privileges, _resolver(), _change_logger())

    assert diff == PrivilegeDiff()


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

    diff = compute_privilege_diff(set(), actual, _resolver(), _change_logger())

    assert diff.to_revoke == actual
    assert diff.to_grant == set()


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

    diff = compute_privilege_diff(desired, set(), _resolver(), _change_logger())

    assert diff.to_grant == desired
    assert diff.to_revoke == set()
