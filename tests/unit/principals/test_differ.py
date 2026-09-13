from __future__ import annotations

from unittest.mock import MagicMock

from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.principals import (
    Group,
    GroupRename,
    Principal,
    PrincipalResolver,
    compute_group_diff,
    groups_pending_creation,
)
from uc_declarative_abac.types import PrincipalType
from uc_declarative_abac.utils import PrincipalValidationError, parse_flat_scope

# Sentinel for distinguishing "not provided" from "explicitly None" in _group().
_NOT_PROVIDED = object()


def _group(
    display_name: str,
    external_id: str = "",
    members: set[Principal] | frozenset[Principal] | None | object = _NOT_PROVIDED,
    assumers: set[Principal] | frozenset[Principal] | None | object = _NOT_PROVIDED,
) -> Group:
    """Build a test Group with optional members and assumers.

    - When members/assumers is not passed, defaults to frozenset() (managed, empty).
    - When members/assumers is explicitly None, uses None (unmanaged).
    - When members/assumers is a set or frozenset, converts to frozenset.
    """
    # Helper to convert input to frozenset or None, respecting the sentinel.
    def _to_frozenset_or_none(value):
        if value is _NOT_PROVIDED:
            return frozenset()  # Default: managed, empty
        if value is None:
            return None  # Explicitly unmanaged
        if isinstance(value, frozenset):
            return value
        return frozenset(value)

    return Group(
        display_name=display_name,
        external_id=external_id,
        members=_to_frozenset_or_none(members),
        assumers=_to_frozenset_or_none(assumers),
    )


def _group_with_id(
    display_name: str,
    group_id: str,
    external_id: str = "",
    members: set[Principal] | frozenset[Principal] | None | object = _NOT_PROVIDED,
    assumers: set[Principal] | frozenset[Principal] | None | object = _NOT_PROVIDED,
) -> Group:
    # Reuse the conversion logic from _group.
    def _to_frozenset_or_none(value):
        if value is _NOT_PROVIDED:
            return frozenset()
        if value is None:
            return None
        if isinstance(value, frozenset):
            return value
        return frozenset(value)

    return Group(
        display_name=display_name,
        external_id=external_id,
        members=_to_frozenset_or_none(members),
        assumers=_to_frozenset_or_none(assumers),
        id=group_id,
    )


def _resolver_passthrough() -> PrincipalResolver:
    """A resolver whose ws_helper is never consulted — test inputs are already resolved."""
    return PrincipalResolver(MagicMock())


def _resolver(
    name_to_principal: dict[str, Principal] | None = None,
    identifier_to_principal: dict[str, Principal] | None = None,
) -> PrincipalResolver:
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
        raise PrincipalValidationError(
            f"Principal not found by identifier: {identifier}"
        )

    ws_helper.resolve_by_name.side_effect = _by_name
    ws_helper.resolve_by_identifier.side_effect = _by_identifier
    return PrincipalResolver(ws_helper)


_alice_resolved = Principal(
    PrincipalType.USER, identifier="alice@example.com", name="alice@example.com"
)
_bob_resolved = Principal(
    PrincipalType.USER, identifier="bob@example.com", name="bob@example.com"
)


# ---------------------------------------------------------------------------
# member additions for existing groups (under --enable-group-management)
# ---------------------------------------------------------------------------


def test_group_differ_adds_desired_member_missing_from_existing_group():
    """An existing group missing a desired member surfaces that member in members_to_add."""
    desired = {
        _group(
            "analysts",
            members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")},
        )
    }
    actual = {_group("analysts", members=set())}
    resolver = _resolver(name_to_principal={"alice@example.com": _alice_resolved})

    diff = compute_group_diff(
        desired, actual, resolver, ChangeLogger(), enable_group_management=True
    )

    assert _alice_resolved in diff.members_to_add["analysts"]


def test_group_differ_omits_group_when_all_desired_members_present():
    """When the existing group already holds all desired members, it is omitted from both maps."""
    desired = {
        _group(
            "analysts",
            members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")},
        )
    }
    actual = {
        _group(
            "analysts",
            members={Principal(PrincipalType.UNKNOWN, identifier="alice@example.com")},
        )
    }
    resolver = _resolver(
        name_to_principal={"alice@example.com": _alice_resolved},
        identifier_to_principal={"alice@example.com": _alice_resolved},
    )

    diff = compute_group_diff(
        desired, actual, resolver, ChangeLogger(), enable_group_management=True
    )

    assert "analysts" not in diff.members_to_add
    assert "analysts" not in diff.members_to_remove


def test_group_differ_resolves_both_sides_before_comparison():
    """A desired member by name and the same principal in actual by identifier yield no change."""
    desired = {
        _group(
            "analysts",
            members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")},
        )
    }
    actual = {
        _group(
            "analysts",
            members={Principal(PrincipalType.UNKNOWN, identifier="alice@example.com")},
        )
    }
    resolver = _resolver(
        name_to_principal={"alice@example.com": _alice_resolved},
        identifier_to_principal={"alice@example.com": _alice_resolved},
    )

    diff = compute_group_diff(
        desired, actual, resolver, ChangeLogger(), enable_group_management=True
    )

    assert "analysts" not in diff.members_to_add
    assert "analysts" not in diff.members_to_remove


# ---------------------------------------------------------------------------
# member removals for existing groups (under --enable-group-management)
# ---------------------------------------------------------------------------


def test_group_differ_removes_member_present_in_actual_but_not_desired():
    """A member on the group but absent from config surfaces in members_to_remove."""
    desired = {
        _group(
            "analysts",
            members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")},
        )
    }
    actual = {
        _group(
            "analysts",
            members={
                Principal(PrincipalType.UNKNOWN, identifier="alice@example.com"),
                Principal(PrincipalType.UNKNOWN, identifier="bob@example.com"),
            },
        )
    }
    resolver = _resolver(
        name_to_principal={"alice@example.com": _alice_resolved},
        identifier_to_principal={
            "alice@example.com": _alice_resolved,
            "bob@example.com": _bob_resolved,
        },
    )

    diff = compute_group_diff(
        desired, actual, resolver, ChangeLogger(), enable_group_management=True
    )

    # alice already present (no add); bob removed.
    assert "analysts" not in diff.members_to_add
    assert _bob_resolved in diff.members_to_remove["analysts"]


def test_group_differ_empty_desired_members_removes_all():
    """A configured group with no members removes every current member (config is absolute)."""
    desired = {_group("analysts", members=set())}
    actual = {
        _group(
            "analysts",
            members={Principal(PrincipalType.UNKNOWN, identifier="alice@example.com")},
        )
    }
    resolver = _resolver(identifier_to_principal={"alice@example.com": _alice_resolved})

    diff = compute_group_diff(
        desired, actual, resolver, ChangeLogger(), enable_group_management=True
    )

    assert _alice_resolved in diff.members_to_remove["analysts"]
    assert "analysts" not in diff.members_to_add


def test_group_differ_adds_and_removes_in_one_group():
    """A group needing both an addition and a removal populates both maps."""
    desired = {
        _group(
            "analysts",
            members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")},
        )
    }
    actual = {
        _group(
            "analysts",
            members={Principal(PrincipalType.UNKNOWN, identifier="bob@example.com")},
        )
    }
    resolver = _resolver(
        name_to_principal={"alice@example.com": _alice_resolved},
        identifier_to_principal={"bob@example.com": _bob_resolved},
    )

    diff = compute_group_diff(
        desired, actual, resolver, ChangeLogger(), enable_group_management=True
    )

    assert _alice_resolved in diff.members_to_add["analysts"]
    assert _bob_resolved in diff.members_to_remove["analysts"]


# ---------------------------------------------------------------------------
# management gating
# ---------------------------------------------------------------------------


def test_group_differ_leaves_existing_groups_untouched_when_management_disabled():
    """Without --enable-group-management, an existing group's membership is never diffed."""
    desired = {
        _group(
            "analysts",
            members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")},
        )
    }
    actual = {
        _group(
            "analysts",
            members={Principal(PrincipalType.UNKNOWN, identifier="bob@example.com")},
        )
    }
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
    desired = {
        _group(
            "analysts",
            members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")},
        )
    }
    actual: set[Group] = set()
    resolver = _resolver(name_to_principal={"alice@example.com": _alice_resolved})
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired, actual, resolver, change_logger, enable_group_management=True
    )

    assert change_logger.has_errors
    assert "analysts" not in diff.groups_to_create
    assert "analysts" not in diff.members_to_add


def test_group_differ_creates_group_with_members_when_creation_enabled():
    """A missing group flows into groups_to_create (empty set) when creation is enabled
    with management on — the group's configured members land in members_to_add."""
    desired = {
        _group(
            "analysts",
            members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")},
        )
    }
    actual: set[Group] = set()
    resolver = _resolver(name_to_principal={"alice@example.com": _alice_resolved})
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired,
        actual,
        resolver,
        change_logger,
        enable_group_creation=True,
        enable_group_management=True,
    )

    # Group name is in groups_to_create (created empty), members flow through members_to_add.
    assert "analysts" in diff.groups_to_create
    assert _alice_resolved in diff.members_to_add["analysts"]
    assert change_logger.has_errors is False


# ---------------------------------------------------------------------------
# externally-managed (IdP) groups
# ---------------------------------------------------------------------------


def test_group_differ_errors_when_managing_externally_managed_group():
    """An existing group with an external_id is a fatal error under management and is dropped."""
    desired = {
        _group(
            "analysts",
            members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")},
        )
    }
    actual = {_group("analysts", external_id="idp-123", members=set())}
    resolver = _resolver(name_to_principal={"alice@example.com": _alice_resolved})
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired, actual, resolver, change_logger, enable_group_management=True
    )

    assert change_logger.has_errors
    assert "analysts" not in diff.members_to_add
    assert "analysts" not in diff.members_to_remove


# ---------------------------------------------------------------------------
# member resolution failures
# ---------------------------------------------------------------------------


def test_group_differ_actual_side_unresolvable_member_is_warning():
    """An actual-state member (identifier-only) that can't be resolved is dropped and logged as a warning."""
    desired = {_group("analysts", members=set())}
    actual = {
        _group(
            "analysts",
            members={
                Principal(
                    PrincipalType.UNKNOWN,
                    identifier="dd4ded68-9a65-4df9-ad70-832718d36e10",
                )
            },
        )
    }
    resolver = _resolver()  # nothing resolves
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired, actual, resolver, change_logger, enable_group_management=True
    )

    # Unresolvable actual member is dropped, so it is neither added nor removed.
    assert "analysts" not in diff.members_to_add
    assert "analysts" not in diff.members_to_remove
    assert change_logger.has_errors is False
    assert len(change_logger.warnings) == 1


def test_group_differ_suppresses_warning_for_ignored_unresolvable_member():
    """An unresolvable actual-state member in ignore_unresolvable is dropped without a warning."""
    ignored_id = "dd4ded68-9a65-4df9-ad70-832718d36e10"
    desired = {_group("analysts", members=set())}
    actual = {
        _group(
            "analysts",
            members={Principal(PrincipalType.UNKNOWN, identifier=ignored_id)},
        )
    }
    resolver = _resolver()  # nothing resolves
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired,
        actual,
        resolver,
        change_logger,
        enable_group_management=True,
        ignore_unresolvable=frozenset({ignored_id}),
    )

    assert "analysts" not in diff.members_to_remove
    assert change_logger.has_errors is False
    assert change_logger.warnings == []


def test_group_differ_desired_side_unresolvable_member_is_error():
    """A desired (config-side, name-only) member that can't be resolved is a fatal error and is dropped."""
    desired = {
        _group(
            "analysts", members={Principal(PrincipalType.UNKNOWN, name="ghost_user")}
        )
    }
    actual = {_group("analysts", members=set())}
    resolver = _resolver()  # nothing resolves
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired, actual, resolver, change_logger, enable_group_management=True
    )

    assert change_logger.has_errors
    # No phantom addition — the unresolvable member was dropped from desired.
    assert "analysts" not in diff.members_to_add


# ---------------------------------------------------------------------------
# multiple groups
# ---------------------------------------------------------------------------


def test_group_differ_handles_multiple_groups_independently():
    """One group needing a member addition and one in sync are diffed independently."""
    desired = {
        _group(
            "analysts",
            members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")},
        ),
        _group(
            "engineers",
            members={Principal(PrincipalType.UNKNOWN, name="bob@example.com")},
        ),
    }
    actual = {
        _group("analysts", members=set()),
        _group(
            "engineers",
            members={Principal(PrincipalType.UNKNOWN, identifier="bob@example.com")},
        ),
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

    diff = compute_group_diff(
        desired, actual, resolver, ChangeLogger(), enable_group_management=True
    )

    assert _alice_resolved in diff.members_to_add["analysts"]
    assert "engineers" not in diff.members_to_add
    assert "engineers" not in diff.members_to_remove


# ---------------------------------------------------------------------------
# group renaming via id matching (under --enable-group-management)
# ---------------------------------------------------------------------------


def test_group_differ_matches_by_id_when_id_present():
    """A desired group carrying an id matches the actual group with the same id
    (regardless of name) rather than being treated as a brand-new group."""
    desired = {
        _group_with_id(
            "analysts_new",
            "id-X",
            members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")},
        )
    }
    actual = {
        _group_with_id(
            "analysts_old",
            "id-X",
            members={Principal(PrincipalType.UNKNOWN, identifier="alice@example.com")},
        )
    }
    resolver = _resolver(
        name_to_principal={"alice@example.com": _alice_resolved},
        identifier_to_principal={"alice@example.com": _alice_resolved},
    )
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired, actual, resolver, change_logger, enable_group_management=True
    )

    # Matched by id, so not a creation; members are identical, so no membership churn.
    assert "analysts_new" not in diff.groups_to_create
    assert "analysts_old" not in diff.groups_to_create
    assert change_logger.has_errors is False


def test_group_differ_emits_rename_when_id_matches_and_name_differs():
    """When the id matches but the display name differs, a GroupRename is recorded."""
    desired = {_group_with_id("analysts_new", "id-X", members=set())}
    actual = {_group_with_id("analysts_old", "id-X", members=set())}
    resolver = _resolver_passthrough()
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired, actual, resolver, change_logger, enable_group_management=True
    )

    assert (
        GroupRename(
            id="id-X",
            old_display_name="analysts_old",
            new_display_name="analysts_new",
        )
        in diff.groups_to_rename
    )
    assert change_logger.has_errors is False


def test_group_differ_no_rename_when_id_matches_and_name_same():
    """When the id matches and the display name is unchanged, no rename is recorded."""
    desired = {_group_with_id("team", "id-X", members=set())}
    actual = {_group_with_id("team", "id-X", members=set())}
    resolver = _resolver_passthrough()
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired, actual, resolver, change_logger, enable_group_management=True
    )

    assert diff.groups_to_rename == []
    assert change_logger.has_errors is False


def test_group_differ_reconciles_membership_under_new_name_when_renamed():
    """A renamed group's membership changes are keyed by the new display name, not the old."""
    desired = {
        _group_with_id(
            "analysts_new",
            "id-X",
            members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")},
        )
    }
    actual = {
        _group_with_id(
            "analysts_old",
            "id-X",
            members={Principal(PrincipalType.UNKNOWN, identifier="bob@example.com")},
        )
    }
    resolver = _resolver(
        name_to_principal={"alice@example.com": _alice_resolved},
        identifier_to_principal={"bob@example.com": _bob_resolved},
    )
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired, actual, resolver, change_logger, enable_group_management=True
    )

    assert _alice_resolved in diff.members_to_add["analysts_new"]
    assert _bob_resolved in diff.members_to_remove["analysts_new"]
    assert "analysts_old" not in diff.members_to_add
    assert "analysts_old" not in diff.members_to_remove


def test_group_differ_errors_when_id_has_no_matching_actual_group():
    """A desired group declaring an id with no matching actual group is a fatal error."""
    desired = {_group_with_id("analysts", "id-X", members=set())}
    actual = {_group_with_id("other", "id-Y", members=set())}
    resolver = _resolver_passthrough()
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired, actual, resolver, change_logger, enable_group_management=True
    )

    assert change_logger.has_errors
    assert change_logger.errors
    assert diff.groups_to_rename == []
    assert diff.groups_to_create == set()


def test_group_differ_errors_when_rename_target_name_already_taken():
    """Renaming to a display name already held by a different actual group is a fatal error."""
    desired = {_group_with_id("taken", "id-X", members=set())}
    actual = {
        _group_with_id("analysts_old", "id-X", members=set()),
        _group_with_id("taken", "id-Y", members=set()),
    }
    resolver = _resolver_passthrough()
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired, actual, resolver, change_logger, enable_group_management=True
    )

    assert change_logger.has_errors
    assert change_logger.errors
    assert not any(r.id == "id-X" for r in diff.groups_to_rename)


def test_group_differ_errors_when_renaming_externally_managed_group():
    """Renaming a group matched by id that has an external_id is a fatal error."""
    desired = {_group_with_id("analysts_new", "id-X", members=set())}
    actual = {
        _group_with_id("analysts_old", "id-X", external_id="idp-123", members=set())
    }
    resolver = _resolver_passthrough()
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired, actual, resolver, change_logger, enable_group_management=True
    )

    assert change_logger.has_errors
    assert change_logger.errors
    assert diff.groups_to_rename == []


def test_group_differ_omits_rename_when_management_disabled():
    """Without --enable-group-management, an id-matched name difference yields no rename and no error."""
    desired = {_group_with_id("analysts_new", "id-X", members=set())}
    actual = {_group_with_id("analysts_old", "id-X", members=set())}
    resolver = _resolver_passthrough()
    change_logger = ChangeLogger()

    diff = compute_group_diff(desired, actual, resolver, change_logger)

    assert diff.groups_to_rename == []
    assert change_logger.has_errors is False


def test_group_differ_falls_back_to_name_match_when_id_absent():
    """A desired group with no id still matches the actual group by display name and
    reconciles membership, recording no rename and no error (existing behavior)."""
    desired = {
        _group(
            "analysts",
            members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")},
        )
    }
    actual = {_group("analysts", members=set())}
    resolver = _resolver(name_to_principal={"alice@example.com": _alice_resolved})
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired, actual, resolver, change_logger, enable_group_management=True
    )

    assert _alice_resolved in diff.members_to_add["analysts"]
    assert diff.groups_to_rename == []
    assert change_logger.has_errors is False


# ---------------------------------------------------------------------------
# assumers reconciliation
# ---------------------------------------------------------------------------


def test_group_differ_reconciles_assumers_when_desired_differs_from_actual():
    """A group with desired assumers differing from actual has the full resolved
    desired set in assumers_to_set, with add/remove deltas for logging."""
    desired = {
        _group(
            "analysts",
            members=set(),
            assumers={Principal(PrincipalType.UNKNOWN, name="alice@example.com")},
        )
    }
    actual = {_group("analysts", members=set(), assumers=frozenset())}
    resolver = _resolver(name_to_principal={"alice@example.com": _alice_resolved})
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired, actual, resolver, change_logger, enable_group_management=True
    )

    # Full desired set in assumers_to_set.
    assert diff.assumers_to_set["analysts"] == frozenset({_alice_resolved})
    # Delta for logging: alice was added.
    assert _alice_resolved in diff.assumers_to_add["analysts"]
    assert "analysts" not in diff.assumers_to_remove


def test_group_differ_omits_assumers_when_desired_and_actual_are_identical():
    """When actual assumers match desired assumers, the group is omitted from
    assumers_to_set (idempotent)."""
    desired = {
        _group(
            "analysts",
            members=set(),
            assumers={Principal(PrincipalType.UNKNOWN, name="alice@example.com")},
        )
    }
    actual = {
        _group(
            "analysts",
            members=set(),
            assumers=frozenset({Principal(PrincipalType.UNKNOWN, identifier="alice@example.com")}),
        )
    }
    resolver = _resolver(
        name_to_principal={"alice@example.com": _alice_resolved},
        identifier_to_principal={"alice@example.com": _alice_resolved},
    )
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired, actual, resolver, change_logger, enable_group_management=True
    )

    # Identical, so not in assumers_to_set (idempotent).
    assert "analysts" not in diff.assumers_to_set


def test_group_differ_skips_assumers_when_desired_assumers_is_none():
    """When desired.assumers is None, the group's assumers are unmanaged and left untouched."""
    desired = {_group("analysts", members=set(), assumers=None)}
    actual = {
        _group(
            "analysts",
            members=set(),
            assumers=frozenset({Principal(PrincipalType.UNKNOWN, identifier="alice@example.com")}),
        )
    }
    resolver = _resolver(identifier_to_principal={"alice@example.com": _alice_resolved})
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired, actual, resolver, change_logger, enable_group_management=True
    )

    # Unmanaged (None), so not reconciled.
    assert "analysts" not in diff.assumers_to_set
    assert "analysts" not in diff.assumers_to_add
    assert "analysts" not in diff.assumers_to_remove


def test_group_differ_skips_members_when_desired_members_is_none():
    """When desired.members is None, the group's membership is unmanaged and left untouched."""
    desired = {_group("analysts", members=None)}
    actual = {
        _group(
            "analysts",
            members=frozenset({Principal(PrincipalType.UNKNOWN, identifier="alice@example.com")}),
        )
    }
    resolver = _resolver(identifier_to_principal={"alice@example.com": _alice_resolved})
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired, actual, resolver, change_logger, enable_group_management=True
    )

    # Unmanaged (None), so membership not touched.
    assert "analysts" not in diff.members_to_add
    assert "analysts" not in diff.members_to_remove


def test_group_differ_removes_all_members_when_desired_is_empty_frozenset():
    """When desired.members is an empty frozenset (not None), all actual members are removed."""
    desired = {_group("analysts", members=frozenset())}
    actual = {
        _group(
            "analysts",
            members=frozenset({Principal(PrincipalType.UNKNOWN, identifier="alice@example.com")}),
        )
    }
    resolver = _resolver(identifier_to_principal={"alice@example.com": _alice_resolved})
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired, actual, resolver, change_logger, enable_group_management=True
    )

    # Empty desired is authoritative, so all members removed.
    assert _alice_resolved in diff.members_to_remove["analysts"]
    assert "analysts" not in diff.members_to_add


def test_group_differ_errors_when_external_group_has_members_supplied():
    """An existing external (IdP-provisioned) group with supplied members is a fatal error."""
    desired = {
        _group(
            "analysts",
            members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")},
        )
    }
    actual = {_group("analysts", external_id="ext-idp-123", members=frozenset())}
    resolver = _resolver(name_to_principal={"alice@example.com": _alice_resolved})
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired, actual, resolver, change_logger, enable_group_management=True
    )

    # Error logged, group dropped from membership reconciliation.
    assert change_logger.has_errors
    assert "analysts" not in diff.members_to_add
    assert "analysts" not in diff.members_to_remove


def test_group_differ_reconciles_assumers_for_external_group_with_members_none():
    """An existing external group with members=None (unmanaged) can have its assumers managed."""
    desired = {
        _group(
            "analysts",
            members=None,
            assumers={Principal(PrincipalType.UNKNOWN, name="alice@example.com")},
        )
    }
    actual = {_group("analysts", external_id="ext-idp-123", members=frozenset(), assumers=frozenset())}
    resolver = _resolver(name_to_principal={"alice@example.com": _alice_resolved})
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired, actual, resolver, change_logger, enable_group_management=True
    )

    # No error, no membership changes, but assumers are reconciled.
    assert change_logger.has_errors is False
    assert "analysts" not in diff.members_to_add
    assert "analysts" not in diff.members_to_remove
    assert diff.assumers_to_set["analysts"] == frozenset({_alice_resolved})


def test_group_differ_creates_and_manages_group_with_members_and_assumers():
    """A missing group created this run with both members and assumers (creation + management)
    has its name in groups_to_create (empty) and its members/assumers in the respective
    management maps."""
    desired = {
        _group(
            "analysts",
            members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")},
            assumers={Principal(PrincipalType.UNKNOWN, name="bob@example.com")},
        )
    }
    actual: set[Group] = set()
    resolver = _resolver(
        name_to_principal={
            "alice@example.com": _alice_resolved,
            "bob@example.com": _bob_resolved,
        }
    )
    change_logger = ChangeLogger()

    diff = compute_group_diff(
        desired,
        actual,
        resolver,
        change_logger,
        enable_group_creation=True,
        enable_group_management=True,
    )

    # Group queued for creation (empty).
    assert "analysts" in diff.groups_to_create
    # Members and assumers flow through management.
    assert _alice_resolved in diff.members_to_add["analysts"]
    assert diff.assumers_to_set["analysts"] == frozenset({_bob_resolved})
    assert change_logger.has_errors is False


# ---------------------------------------------------------------------------
# group deletion (under --enable-group-deletion)
# ---------------------------------------------------------------------------


def test_group_differ_does_not_delete_when_flag_disabled():
    """Default behaviour (flag off): undeclared account groups are left alone."""
    desired = {_group_with_id("analysts", "1")}
    all_account_groups = {
        _group_with_id("analysts", "1"),
        _group_with_id("legacy", "2"),
    }

    diff = compute_group_diff(
        desired,
        set(),
        _resolver_passthrough(),
        ChangeLogger(),
        all_account_groups=all_account_groups,
    )

    assert diff.groups_to_delete == set()


def test_group_differ_deletes_undeclared_managed_group_when_flag_enabled():
    """With enable_group_deletion, a Databricks-managed account group absent from config
    flows into groups_to_delete."""
    legacy = _group_with_id("legacy", "2")
    desired = {_group_with_id("analysts", "1")}
    all_account_groups = {_group_with_id("analysts", "1"), legacy}

    diff = compute_group_diff(
        desired,
        set(),
        _resolver_passthrough(),
        ChangeLogger(),
        enable_group_deletion=True,
        all_account_groups=all_account_groups,
    )

    assert legacy in diff.groups_to_delete
    assert _group_with_id("analysts", "1") not in diff.groups_to_delete


def test_group_differ_does_not_delete_external_group_when_flag_enabled():
    """An external (IdP-provisioned) group absent from config is never deleted."""
    external = _group_with_id("idp-group", "2", external_id="ext-abc")
    desired = {_group_with_id("analysts", "1")}
    all_account_groups = {_group_with_id("analysts", "1"), external}

    diff = compute_group_diff(
        desired,
        set(),
        _resolver_passthrough(),
        ChangeLogger(),
        enable_group_deletion=True,
        all_account_groups=all_account_groups,
    )

    assert external not in diff.groups_to_delete
    assert diff.groups_to_delete == set()


def test_group_differ_does_not_delete_account_system_group_when_flag_enabled():
    """The Databricks account system groups (account users / account admins) are never
    deletion candidates, even when absent from config."""
    system_group = _group_with_id("account users", "2")
    desired = {_group_with_id("analysts", "1")}
    all_account_groups = {_group_with_id("analysts", "1"), system_group}

    diff = compute_group_diff(
        desired,
        set(),
        _resolver_passthrough(),
        ChangeLogger(),
        enable_group_deletion=True,
        all_account_groups=all_account_groups,
    )

    assert system_group not in diff.groups_to_delete
    assert diff.groups_to_delete == set()


def test_group_differ_does_not_delete_group_matched_by_desired_id_on_rename():
    """A group pending a rename (config holds the new name, the account still the old one,
    matched by id) is not treated as undeclared and is never deleted."""
    # Config declares the group under its new name but keeps its id.
    desired = {_group_with_id("analysts_renamed", "1")}
    # The account still carries the old display name under the same id.
    all_account_groups = {_group_with_id("analysts_old", "1")}

    diff = compute_group_diff(
        desired,
        set(),
        _resolver_passthrough(),
        ChangeLogger(),
        enable_group_deletion=True,
        all_account_groups=all_account_groups,
    )

    assert diff.groups_to_delete == set()


# ---------------------------------------------------------------------------
# Per-scope filtering (creation / management / deletion)
# ---------------------------------------------------------------------------


def test_group_differ_creation_scope_filters_by_display_name():
    """Only desired groups matching the creation scope are created."""
    desired = {_group("team_data", members=set()), _group("analysts", members=set())}

    diff = compute_group_diff(
        desired,
        set(),
        _resolver_passthrough(),
        ChangeLogger(),
        enable_group_creation=True,
        creation_scope=parse_flat_scope("team_*"),
    )

    assert set(diff.groups_to_create) == {"team_data"}


def test_group_differ_management_scope_filters_reconciliation():
    """An existing group outside the management scope is left untouched."""
    desired = {
        _group(
            "team_data",
            members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")},
        ),
        _group(
            "analysts",
            members={Principal(PrincipalType.UNKNOWN, name="alice@example.com")},
        ),
    }
    actual = {_group("team_data", members=set()), _group("analysts", members=set())}

    diff = compute_group_diff(
        desired,
        actual,
        _resolver(name_to_principal={"alice@example.com": _alice_resolved}),
        ChangeLogger(),
        enable_group_management=True,
        management_scope=parse_flat_scope("team_*"),
    )

    assert "team_data" in diff.members_to_add
    assert "analysts" not in diff.members_to_add


def test_group_differ_deletion_scope_filters_candidates():
    """Only undeclared managed groups matching the deletion scope are deleted."""
    legacy_a = _group_with_id("legacy_a", "2")
    temp_b = _group_with_id("temp_b", "3")
    desired = {_group_with_id("analysts", "1")}
    all_account_groups = {_group_with_id("analysts", "1"), legacy_a, temp_b}

    diff = compute_group_diff(
        desired,
        set(),
        _resolver_passthrough(),
        ChangeLogger(),
        enable_group_deletion=True,
        all_account_groups=all_account_groups,
        deletion_scope=parse_flat_scope("legacy_*"),
    )

    assert diff.groups_to_delete == {legacy_a}


# ---
# groups_pending_creation
# ---


def test_group_differ_groups_pending_creation_returns_missing_in_scope_groups():
    """Configured groups absent from the account are pending creation."""
    desired = {_group("analysts"), _group("engineers")}
    actual = {_group("engineers")}

    pending = groups_pending_creation(desired, actual, enable_group_creation=True)

    assert pending == {"analysts"}


def test_group_differ_groups_pending_creation_is_empty_when_creation_disabled():
    """With creation disabled, nothing is pending creation."""
    pending = groups_pending_creation(
        {_group("analysts")}, set(), enable_group_creation=False
    )

    assert pending == set()


def test_group_differ_groups_pending_creation_excludes_out_of_scope_groups():
    """A missing group outside the creation scope is not pending creation."""
    desired = {_group("analysts"), _group("team_data")}

    pending = groups_pending_creation(
        desired,
        set(),
        enable_group_creation=True,
        creation_scope=parse_flat_scope("team_*"),
    )

    assert pending == {"team_data"}


def test_group_differ_groups_pending_creation_excludes_groups_declaring_an_id():
    """A group declaring an id is an existing group matched for rename, never a
    creation candidate — even when absent by that id."""
    pending = groups_pending_creation(
        {_group_with_id("analysts", "id-X")}, set(), enable_group_creation=True
    )

    assert pending == set()
