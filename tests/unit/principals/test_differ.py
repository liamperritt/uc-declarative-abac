from __future__ import annotations

from unittest.mock import MagicMock

from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.principals import (
    compute_group_diff,
    Group,
    Principal,
    PrincipalResolver,
)
from uc_declarative_abac.types import PrincipalType
from uc_declarative_abac.utils import PrincipalValidationError


def _group(
    display_name: str,
    external_id: str = "",
    members: set[Principal] | None = None,
) -> Group:
    return Group(
        display_name=display_name,
        external_id=external_id,
        members=frozenset(members or set()),
    )


def _resolver_passthrough() -> PrincipalResolver:
    """A resolver whose ws_helper is never consulted — test inputs are already resolved."""
    return PrincipalResolver(MagicMock())


def _resolver(name_to_principal: dict[str, Principal] | None = None,
              identifier_to_principal: dict[str, Principal] | None = None) -> PrincipalResolver:
    """Build a resolver backed by a ws_helper mock that knows specific principals."""
    ws_helper = MagicMock()
    name_to_principal = name_to_principal or {}
    identifier_to_principal = identifier_to_principal or {}

    def _by_name(name: str) -> Principal:
        if name in name_to_principal:
            return name_to_principal[name]
        raise PrincipalValidationError(f"Principal not found: {name}")

    def _by_identifier(identifier: str) -> Principal:
        if identifier in identifier_to_principal:
            return identifier_to_principal[identifier]
        raise PrincipalValidationError(f"Principal not found by identifier: {identifier}")

    ws_helper.resolve_by_name.side_effect = _by_name
    ws_helper.resolve_by_identifier.side_effect = _by_identifier
    return PrincipalResolver(ws_helper)


_alice_resolved = Principal(PrincipalType.USER, identifier="alice@example.com", name="alice@example.com")
_bob_resolved = Principal(PrincipalType.USER, identifier="bob@example.com", name="bob@example.com")


# ---------------------------------------------------------------------------
# member additions for existing groups (under --enable-group-management)
# ---------------------------------------------------------------------------


def test_group_differ_adds_desired_member_missing_from_existing_group():
    """An existing group missing a desired member surfaces that member in members_to_add."""
    desired = {_group("analysts", members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")})}
    actual = {_group("analysts", members=set())}
    resolver = _resolver(name_to_principal={"alice@example.com": _alice_resolved})

    diff = compute_group_diff(desired, actual, resolver, ChangeLogger(), enable_group_management=True)

    assert _alice_resolved in diff.members_to_add["analysts"]


def test_group_differ_omits_group_when_all_desired_members_present():
    """When the existing group already holds all desired members, it is omitted from both maps."""
    desired = {_group("analysts", members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")})}
    actual = {_group("analysts", members={Principal(PrincipalType.UNKNOWN, identifier="alice@example.com")})}
    resolver = _resolver(
        name_to_principal={"alice@example.com": _alice_resolved},
        identifier_to_principal={"alice@example.com": _alice_resolved},
    )

    diff = compute_group_diff(desired, actual, resolver, ChangeLogger(), enable_group_management=True)

    assert "analysts" not in diff.members_to_add
    assert "analysts" not in diff.members_to_remove


def test_group_differ_resolves_both_sides_before_comparison():
    """A desired member by name and the same principal in actual by identifier yield no change."""
    desired = {_group("analysts", members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")})}
    actual = {_group("analysts", members={Principal(PrincipalType.UNKNOWN, identifier="alice@example.com")})}
    resolver = _resolver(
        name_to_principal={"alice@example.com": _alice_resolved},
        identifier_to_principal={"alice@example.com": _alice_resolved},
    )

    diff = compute_group_diff(desired, actual, resolver, ChangeLogger(), enable_group_management=True)

    assert "analysts" not in diff.members_to_add
    assert "analysts" not in diff.members_to_remove


# ---------------------------------------------------------------------------
# member removals for existing groups (under --enable-group-management)
# ---------------------------------------------------------------------------


def test_group_differ_removes_member_present_in_actual_but_not_desired():
    """A member on the group but absent from config surfaces in members_to_remove."""
    desired = {_group("analysts", members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")})}
    actual = {_group(
        "analysts",
        members={
            Principal(PrincipalType.UNKNOWN, identifier="alice@example.com"),
            Principal(PrincipalType.UNKNOWN, identifier="bob@example.com"),
        },
    )}
    resolver = _resolver(
        name_to_principal={"alice@example.com": _alice_resolved},
        identifier_to_principal={
            "alice@example.com": _alice_resolved,
            "bob@example.com": _bob_resolved,
        },
    )

    diff = compute_group_diff(desired, actual, resolver, ChangeLogger(), enable_group_management=True)

    # alice already present (no add); bob removed.
    assert "analysts" not in diff.members_to_add
    assert _bob_resolved in diff.members_to_remove["analysts"]


def test_group_differ_empty_desired_members_removes_all():
    """A configured group with no members removes every current member (config is absolute)."""
    desired = {_group("analysts", members=set())}
    actual = {_group("analysts", members={Principal(PrincipalType.UNKNOWN, identifier="alice@example.com")})}
    resolver = _resolver(identifier_to_principal={"alice@example.com": _alice_resolved})

    diff = compute_group_diff(desired, actual, resolver, ChangeLogger(), enable_group_management=True)

    assert _alice_resolved in diff.members_to_remove["analysts"]
    assert "analysts" not in diff.members_to_add


def test_group_differ_adds_and_removes_in_one_group():
    """A group needing both an addition and a removal populates both maps."""
    desired = {_group("analysts", members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")})}
    actual = {_group("analysts", members={Principal(PrincipalType.UNKNOWN, identifier="bob@example.com")})}
    resolver = _resolver(
        name_to_principal={"alice@example.com": _alice_resolved},
        identifier_to_principal={"bob@example.com": _bob_resolved},
    )

    diff = compute_group_diff(desired, actual, resolver, ChangeLogger(), enable_group_management=True)

    assert _alice_resolved in diff.members_to_add["analysts"]
    assert _bob_resolved in diff.members_to_remove["analysts"]


# ---------------------------------------------------------------------------
# management gating
# ---------------------------------------------------------------------------


def test_group_differ_leaves_existing_groups_untouched_when_management_disabled():
    """Without --enable-group-management, an existing group's membership is never diffed."""
    desired = {_group("analysts", members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")})}
    actual = {_group("analysts", members={Principal(PrincipalType.UNKNOWN, identifier="bob@example.com")})}
    resolver = _resolver(
        name_to_principal={"alice@example.com": _alice_resolved},
        identifier_to_principal={"bob@example.com": _bob_resolved},
    )
    change_logger = ChangeLogger()

    diff = compute_group_diff(desired, actual, resolver, change_logger)

    assert diff.members_to_add == {}
    assert diff.members_to_remove == {}
    assert change_logger.has_errors is False


# ---------------------------------------------------------------------------
# missing groups: creation vs management gating
# ---------------------------------------------------------------------------


def test_group_differ_errors_when_group_missing_and_creation_disabled_under_management():
    """A desired group with no actual counterpart is a fatal error when managing but
    creation is disabled."""
    desired = {_group("analysts", members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")})}
    actual: set[Group] = set()
    resolver = _resolver(name_to_principal={"alice@example.com": _alice_resolved})
    change_logger = ChangeLogger()

    diff = compute_group_diff(desired, actual, resolver, change_logger, enable_group_management=True)

    assert change_logger.has_errors
    assert "analysts" not in diff.groups_to_create
    assert "analysts" not in diff.members_to_add


def test_group_differ_creates_group_with_members_when_creation_enabled():
    """A missing group flows into groups_to_create (with resolved members) when creation
    is enabled — management does not separately process the new group."""
    desired = {_group("analysts", members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")})}
    actual: set[Group] = set()
    resolver = _resolver(name_to_principal={"alice@example.com": _alice_resolved})
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired, actual, resolver, change_logger,
        enable_group_creation=True, enable_group_management=True,
    )

    assert _alice_resolved in diff.groups_to_create["analysts"]
    assert "analysts" not in diff.members_to_add
    assert change_logger.has_errors is False


# ---------------------------------------------------------------------------
# externally-managed (IdP) groups
# ---------------------------------------------------------------------------


def test_group_differ_errors_when_managing_externally_managed_group():
    """An existing group with an external_id is a fatal error under management and is dropped."""
    desired = {_group("analysts", members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")})}
    actual = {_group("analysts", external_id="idp-123", members=set())}
    resolver = _resolver(name_to_principal={"alice@example.com": _alice_resolved})
    change_logger = ChangeLogger()

    diff = compute_group_diff(desired, actual, resolver, change_logger, enable_group_management=True)

    assert change_logger.has_errors
    assert "analysts" not in diff.members_to_add
    assert "analysts" not in diff.members_to_remove


# ---------------------------------------------------------------------------
# member resolution failures
# ---------------------------------------------------------------------------


def test_group_differ_actual_side_unresolvable_member_is_warning():
    """An actual-state member (identifier-only) that can't be resolved is dropped and logged as a warning."""
    desired = {_group("analysts", members=set())}
    actual = {_group(
        "analysts",
        members={Principal(PrincipalType.UNKNOWN, identifier="dd4ded68-9a65-4df9-ad70-832718d36e10")},
    )}
    resolver = _resolver()  # nothing resolves
    change_logger = ChangeLogger()

    diff = compute_group_diff(desired, actual, resolver, change_logger, enable_group_management=True)

    # Unresolvable actual member is dropped, so it is neither added nor removed.
    assert "analysts" not in diff.members_to_add
    assert "analysts" not in diff.members_to_remove
    assert change_logger.has_errors is False
    assert len(change_logger.warnings) == 1


def test_group_differ_suppresses_warning_for_ignored_unresolvable_member():
    """An unresolvable actual-state member in ignore_unresolvable is dropped without a warning."""
    ignored_id = "dd4ded68-9a65-4df9-ad70-832718d36e10"
    desired = {_group("analysts", members=set())}
    actual = {_group(
        "analysts",
        members={Principal(PrincipalType.UNKNOWN, identifier=ignored_id)},
    )}
    resolver = _resolver()  # nothing resolves
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired, actual, resolver, change_logger,
        enable_group_management=True,
        ignore_unresolvable=frozenset({ignored_id}),
    )

    assert "analysts" not in diff.members_to_remove
    assert change_logger.has_errors is False
    assert change_logger.warnings == []


def test_group_differ_desired_side_unresolvable_member_is_error():
    """A desired (config-side, name-only) member that can't be resolved is a fatal error and is dropped."""
    desired = {_group("analysts", members={Principal(PrincipalType.UNKNOWN, name="ghost_user")})}
    actual = {_group("analysts", members=set())}
    resolver = _resolver()  # nothing resolves
    change_logger = ChangeLogger()

    diff = compute_group_diff(desired, actual, resolver, change_logger, enable_group_management=True)

    assert change_logger.has_errors
    # No phantom addition — the unresolvable member was dropped from desired.
    assert "analysts" not in diff.members_to_add


# ---------------------------------------------------------------------------
# multiple groups
# ---------------------------------------------------------------------------


def test_group_differ_handles_multiple_groups_independently():
    """One group needing a member addition and one in sync are diffed independently."""
    desired = {
        _group("analysts", members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")}),
        _group("engineers", members={Principal(PrincipalType.UNKNOWN, name="bob@example.com")}),
    }
    actual = {
        _group("analysts", members=set()),
        _group("engineers", members={Principal(PrincipalType.UNKNOWN, identifier="bob@example.com")}),
    }
    resolver = _resolver(
        name_to_principal={
            "alice@example.com": _alice_resolved,
            "bob@example.com": _bob_resolved,
        },
        identifier_to_principal={
            "alice@example.com": _alice_resolved,
            "bob@example.com": _bob_resolved,
        },
    )

    diff = compute_group_diff(desired, actual, resolver, ChangeLogger(), enable_group_management=True)

    assert _alice_resolved in diff.members_to_add["analysts"]
    assert "engineers" not in diff.members_to_add
    assert "engineers" not in diff.members_to_remove
