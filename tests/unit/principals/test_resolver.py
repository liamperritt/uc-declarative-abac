from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from uc_abac_governor.helpers.workspace import WorkspaceHelper
from uc_abac_governor.principals.resolver import (
    PrincipalResolver,
    ensure_all_resolved,
    ensure_resolved,
)
from uc_abac_governor.principals.state import Principal
from uc_abac_governor.types import GovernorError, PrincipalType, PrincipalValidationError


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _make_ws_helper(
    users: list[str] | None = None,
    groups: list[str] | None = None,
    service_principals: dict[str, str] | None = None,
) -> WorkspaceHelper:
    """Build a WorkspaceHelper with pre-populated caches (bypasses SCIM fetch)."""
    helper = WorkspaceHelper(MagicMock())
    helper._users = set(users or [])
    helper._groups = set(groups or [])
    helper._service_principals = dict(service_principals or {})
    helper._sp_app_id_to_name = {v: k for k, v in (service_principals or {}).items()}
    return helper


# ---------------------------------------------------------------------------
# PrincipalResolver.resolve_principal
# ---------------------------------------------------------------------------


def test_principal_resolver_resolves_user_by_name():
    ws_helper = _make_ws_helper(users=["jdoe"])
    resolver = PrincipalResolver(ws_helper)

    unresolved = Principal(principal_type=PrincipalType.UNKNOWN, name="jdoe")
    resolved = resolver.resolve_principal(unresolved)

    assert resolved.principal_type == PrincipalType.USER
    assert resolved.name == "jdoe"
    assert resolved.identifier == "jdoe"


def test_principal_resolver_resolves_group_by_name():
    ws_helper = _make_ws_helper(groups=["data_engineers"])
    resolver = PrincipalResolver(ws_helper)

    unresolved = Principal(principal_type=PrincipalType.UNKNOWN, name="data_engineers")
    resolved = resolver.resolve_principal(unresolved)

    assert resolved.principal_type == PrincipalType.GROUP
    assert resolved.name == "data_engineers"
    assert resolved.identifier == "data_engineers"


def test_principal_resolver_resolves_sp_by_name():
    ws_helper = _make_ws_helper(service_principals={"sp_sales": "app-id-123"})
    resolver = PrincipalResolver(ws_helper)

    unresolved = Principal(principal_type=PrincipalType.UNKNOWN, name="sp_sales")
    resolved = resolver.resolve_principal(unresolved)

    assert resolved.principal_type == PrincipalType.SERVICE_PRINCIPAL
    assert resolved.name == "sp_sales"
    assert resolved.identifier == "app-id-123"


def test_principal_resolver_resolves_sp_by_identifier():
    """Actual-side: UC state gives app_id, we look it up to get display name."""
    ws_helper = _make_ws_helper(service_principals={"sp_sales": "app-id-123"})
    resolver = PrincipalResolver(ws_helper)

    unresolved = Principal(principal_type=PrincipalType.UNKNOWN, identifier="app-id-123")
    resolved = resolver.resolve_principal(unresolved)

    assert resolved.principal_type == PrincipalType.SERVICE_PRINCIPAL
    assert resolved.name == "sp_sales"
    assert resolved.identifier == "app-id-123"


def test_principal_resolver_resolves_user_by_identifier():
    ws_helper = _make_ws_helper(users=["jdoe"])
    resolver = PrincipalResolver(ws_helper)

    unresolved = Principal(principal_type=PrincipalType.UNKNOWN, identifier="jdoe")
    resolved = resolver.resolve_principal(unresolved)

    assert resolved.principal_type == PrincipalType.USER
    assert resolved.name == "jdoe"
    assert resolved.identifier == "jdoe"


def test_principal_resolver_passes_through_already_resolved():
    """An already-resolved Principal is returned unchanged."""
    ws_helper = _make_ws_helper(service_principals={"sp_sales": "app-id-123"})
    resolver = PrincipalResolver(ws_helper)

    resolved_input = Principal(
        principal_type=PrincipalType.SERVICE_PRINCIPAL,
        name="sp_sales",
        identifier="app-id-123",
    )
    result = resolver.resolve_principal(resolved_input)

    assert result == resolved_input


def test_principal_resolver_raises_for_unknown_name():
    ws_helper = _make_ws_helper()
    resolver = PrincipalResolver(ws_helper)

    with pytest.raises(PrincipalValidationError, match="ghost_team"):
        resolver.resolve_principal(Principal(principal_type=PrincipalType.UNKNOWN, name="ghost_team"))


def test_principal_resolver_raises_for_unknown_identifier():
    ws_helper = _make_ws_helper()
    resolver = PrincipalResolver(ws_helper)

    with pytest.raises(PrincipalValidationError, match="unknown-app-id"):
        resolver.resolve_principal(Principal(principal_type=PrincipalType.UNKNOWN, identifier="unknown-app-id"))


def test_principal_resolver_sp_round_trip_display_name_to_app_id():
    """Desired-side sees display name, actual-side sees app_id; both resolve to the same Principal."""
    ws_helper = _make_ws_helper(service_principals={"sp_sales": "app-id-123"})
    resolver = PrincipalResolver(ws_helper)

    from_name = resolver.resolve_principal(
        Principal(principal_type=PrincipalType.UNKNOWN, name="sp_sales")
    )
    from_id = resolver.resolve_principal(
        Principal(principal_type=PrincipalType.UNKNOWN, identifier="app-id-123")
    )
    assert from_name == from_id


# ---------------------------------------------------------------------------
# PrincipalResolver.resolve_principals (batch)
# ---------------------------------------------------------------------------


def test_principal_resolver_batch_resolves_all():
    ws_helper = _make_ws_helper(
        users=["jdoe"],
        groups=["data_engineers"],
        service_principals={"sp_sales": "app-id-123"},
    )
    resolver = PrincipalResolver(ws_helper)

    batch = [
        Principal(principal_type=PrincipalType.UNKNOWN, name="jdoe"),
        Principal(principal_type=PrincipalType.UNKNOWN, name="data_engineers"),
        Principal(principal_type=PrincipalType.UNKNOWN, identifier="app-id-123"),
    ]
    resolved = resolver.resolve_principals(batch)

    assert len(resolved) == 3
    types = {p.principal_type for p in resolved}
    assert types == {PrincipalType.USER, PrincipalType.GROUP, PrincipalType.SERVICE_PRINCIPAL}


def test_principal_resolver_batch_all_or_nothing_on_failure():
    """If any principal fails to resolve, raises aggregating all failures."""
    ws_helper = _make_ws_helper(users=["jdoe"])
    resolver = PrincipalResolver(ws_helper)

    batch = [
        Principal(principal_type=PrincipalType.UNKNOWN, name="jdoe"),  # ok
        Principal(principal_type=PrincipalType.UNKNOWN, name="ghost_team"),  # fails
        Principal(principal_type=PrincipalType.UNKNOWN, name="missing_user"),  # fails
    ]
    with pytest.raises(PrincipalValidationError) as exc_info:
        resolver.resolve_principals(batch)

    message = str(exc_info.value)
    assert "ghost_team" in message
    assert "missing_user" in message


def test_principal_resolver_batch_single_failure_listed():
    ws_helper = _make_ws_helper()
    resolver = PrincipalResolver(ws_helper)

    with pytest.raises(PrincipalValidationError) as exc_info:
        resolver.resolve_principals([
            Principal(principal_type=PrincipalType.UNKNOWN, name="ghost_team")
        ])

    assert "ghost_team" in str(exc_info.value)


def test_principal_resolver_batch_empty_returns_empty():
    ws_helper = _make_ws_helper()
    resolver = PrincipalResolver(ws_helper)

    assert resolver.resolve_principals([]) == []


# ---------------------------------------------------------------------------
# ensure_resolved / ensure_all_resolved
# ---------------------------------------------------------------------------


def test_ensure_resolved_returns_resolved_principal_unchanged():
    p = Principal(principal_type=PrincipalType.USER, name="x", identifier="x")
    assert ensure_resolved(p) is p


def test_ensure_resolved_raises_for_unresolved():
    p = Principal(principal_type=PrincipalType.UNKNOWN, name="x")
    with pytest.raises(GovernorError):
        ensure_resolved(p)


def test_ensure_all_resolved_maps_over_collection():
    a = Principal(principal_type=PrincipalType.USER, name="a", identifier="a")
    b = Principal(principal_type=PrincipalType.GROUP, name="b", identifier="b")
    result = ensure_all_resolved([a, b])
    assert result == [a, b]


def test_ensure_all_resolved_raises_on_first_unresolved():
    resolved = Principal(principal_type=PrincipalType.USER, name="a", identifier="a")
    unresolved = Principal(principal_type=PrincipalType.UNKNOWN, name="b")
    with pytest.raises(GovernorError):
        ensure_all_resolved([resolved, unresolved])
