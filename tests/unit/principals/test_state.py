from __future__ import annotations

import pytest

from uc_declarative_abac.principals.state import Principal
from uc_declarative_abac.types import PrincipalType


# ---------------------------------------------------------------------------
# Principal invariants
# ---------------------------------------------------------------------------


def test_principal_rejects_both_name_and_identifier_empty():
    """A Principal with neither name nor identifier set is invalid."""
    with pytest.raises(ValueError, match="at least one of name or identifier"):
        Principal(principal_type=PrincipalType.UNKNOWN)


def test_principal_rejects_both_name_and_identifier_empty_when_resolved():
    """Resolved Principal with both fields empty is invalid."""
    with pytest.raises(ValueError):
        Principal(principal_type=PrincipalType.USER)


def test_principal_rejects_resolved_with_empty_name():
    """A resolved Principal with an empty name raises."""
    with pytest.raises(ValueError, match="both name and identifier"):
        Principal(principal_type=PrincipalType.SERVICE_PRINCIPAL, name="", identifier="app-id")


def test_principal_rejects_resolved_with_empty_identifier():
    """A resolved Principal with an empty identifier raises."""
    with pytest.raises(ValueError, match="both name and identifier"):
        Principal(principal_type=PrincipalType.SERVICE_PRINCIPAL, name="sp_name", identifier="")


def test_principal_allows_unresolved_with_only_name():
    """An unresolved Principal (from config) has name set, identifier empty."""
    p = Principal(principal_type=PrincipalType.UNKNOWN, name="data_engineers")
    assert p.name == "data_engineers"
    assert p.identifier == ""
    assert p.principal_type == PrincipalType.UNKNOWN


def test_principal_allows_unresolved_with_only_identifier():
    """An unresolved Principal (from UC state) has identifier set, name empty."""
    p = Principal(principal_type=PrincipalType.UNKNOWN, identifier="app-id-123")
    assert p.name == ""
    assert p.identifier == "app-id-123"
    assert p.principal_type == PrincipalType.UNKNOWN


def test_principal_allows_resolved_with_both_fields():
    """A resolved Principal has type, name, and identifier all set."""
    p = Principal(
        principal_type=PrincipalType.SERVICE_PRINCIPAL,
        name="sp_sales",
        identifier="abc-123",
    )
    assert p.principal_type == PrincipalType.SERVICE_PRINCIPAL
    assert p.name == "sp_sales"
    assert p.identifier == "abc-123"


def test_principal_allows_user_with_same_name_and_identifier():
    """For users, name and identifier are the same username — valid."""
    p = Principal(principal_type=PrincipalType.USER, name="jdoe", identifier="jdoe")
    assert p.name == "jdoe"
    assert p.identifier == "jdoe"


# ---------------------------------------------------------------------------
# Frozen / hashable / equality
# ---------------------------------------------------------------------------


def test_principal_is_frozen():
    """Fields cannot be mutated after construction."""
    p = Principal(principal_type=PrincipalType.USER, name="x", identifier="x")
    with pytest.raises(Exception):
        p.name = "y"  # type: ignore[misc]


def test_principal_is_hashable():
    """Principal instances are usable as set members and dict keys."""
    p1 = Principal(principal_type=PrincipalType.USER, name="x", identifier="x")
    p2 = Principal(principal_type=PrincipalType.USER, name="x", identifier="x")
    assert p1 == p2
    assert {p1, p2} == {p1}


def test_principal_equality_by_field_values():
    """Two Principals with identical fields are equal regardless of construction path."""
    p1 = Principal(
        principal_type=PrincipalType.SERVICE_PRINCIPAL,
        name="sp_a",
        identifier="app-id",
    )
    p2 = Principal(
        principal_type=PrincipalType.SERVICE_PRINCIPAL,
        identifier="app-id",
        name="sp_a",
    )
    assert p1 == p2
    assert hash(p1) == hash(p2)


def test_principal_inequality_across_types():
    """Principals with different types are not equal even if name/identifier match."""
    u = Principal(principal_type=PrincipalType.USER, name="x", identifier="x")
    g = Principal(principal_type=PrincipalType.GROUP, name="x", identifier="x")
    assert u != g


def test_principal_inequality_across_resolution_states():
    """An unresolved Principal and a resolved Principal are not equal even with the same name."""
    unresolved = Principal(principal_type=PrincipalType.UNKNOWN, name="data_engineers")
    resolved = Principal(principal_type=PrincipalType.GROUP, name="data_engineers", identifier="data_engineers")
    assert unresolved != resolved
