from __future__ import annotations

from unittest.mock import MagicMock

from uc_declarative_abac.governed_tags import (
    compute_governed_tag_diff,
    GovernedTag,
)
from uc_declarative_abac.utils import PrincipalValidationError
from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.principals import (
    Principal,
    PrincipalResolver,
)
from uc_declarative_abac.types import PrincipalType


def _gt(
    name: str,
    description: str = "",
    values: set[str] | None = None,
    assigners: set[Principal] | None = None,
) -> GovernedTag:
    return GovernedTag(
        name=name,
        description=description,
        allowed_values=frozenset(values or set()),
        assigners=frozenset(assigners or set()),
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


def test_governed_tag_differ_creates_tag_when_missing_in_actual():
    """A desired tag with no matching actual tag produces a to_create entry."""
    desired = {_gt("pii", "PII", {"name", "email"})}
    actual: set[GovernedTag] = set()

    diff = compute_governed_tag_diff(desired, actual, _resolver_passthrough(), ChangeLogger())

    assert _gt("pii", "PII", {"name", "email"}) in diff.to_create
    assert diff.to_update == set()


def test_governed_tag_differ_updates_tag_when_description_changes():
    """An existing tag with a changed description produces a to_update entry."""
    desired = {_gt("pii", "Updated description", {"name"})}
    actual = {_gt("pii", "Original description", {"name"})}

    diff = compute_governed_tag_diff(desired, actual, _resolver_passthrough(), ChangeLogger())

    assert _gt("pii", "Updated description", {"name"}) in diff.to_update
    assert diff.to_create == set()


def test_governed_tag_differ_updates_tag_when_allowed_values_change():
    """An existing tag with a different allowed_values set produces a to_update entry."""
    desired = {_gt("pii", "PII", {"name", "email", "phone"})}
    actual = {_gt("pii", "PII", {"name", "email"})}

    diff = compute_governed_tag_diff(desired, actual, _resolver_passthrough(), ChangeLogger())

    update = next(iter(diff.to_update))
    assert update.name == "pii"
    assert update.allowed_values == frozenset({"name", "email", "phone"})


def test_governed_tag_differ_treats_reordered_allowed_values_as_unchanged():
    """allowed_values is set-equal — reordering alone does not produce an update."""
    # frozensets inherently ignore order; this test pins the behaviour against
    # a future change that might switch to a tuple/list comparison.
    desired = {_gt("pii", "PII", {"phone", "name", "email"})}
    actual = {_gt("pii", "PII", {"email", "name", "phone"})}

    diff = compute_governed_tag_diff(desired, actual, _resolver_passthrough(), ChangeLogger())

    assert diff.to_update == set()
    assert diff.to_create == set()


def test_governed_tag_differ_ignores_tag_when_in_actual_but_not_desired():
    """A tag present in the account but absent from YAML is left alone — no-delete invariant."""
    desired: set[GovernedTag] = set()
    actual = {_gt("legacy", "legacy tag", {"a", "b"})}

    diff = compute_governed_tag_diff(desired, actual, _resolver_passthrough(), ChangeLogger())

    assert diff.to_create == set()
    assert diff.to_update == set()


def test_governed_tag_differ_produces_empty_diff_when_in_sync():
    """When desired == actual, both to_create and to_update are empty."""
    gt = _gt("pii", "PII", {"name", "email"})

    diff = compute_governed_tag_diff({gt}, {gt}, _resolver_passthrough(), ChangeLogger())

    assert diff.to_create == set()
    assert diff.to_update == set()


def test_governed_tag_differ_records_old_values_for_updates():
    """old_values captures the actual state pre-update, keyed by tag name."""
    desired = {_gt("pii", "New comment", {"name"})}
    actual = {_gt("pii", "Old comment", {"name"})}

    diff = compute_governed_tag_diff(desired, actual, _resolver_passthrough(), ChangeLogger())

    assert diff.old_values["pii"] == _gt("pii", "Old comment", {"name"})


# ---------------------------------------------------------------------------
# --enable-governed-tag-deletion gating
# ---------------------------------------------------------------------------


def test_governed_tag_differ_does_not_mark_for_deletion_when_flag_disabled():
    """Default behaviour (flag off): actual-only tags are left alone, to_delete stays empty."""
    desired = {_gt("pii", "PII", {"name"})}
    actual = {
        _gt("pii", "PII", {"name"}),
        _gt("legacy_tag", "legacy", set()),  # present in UC only
    }

    diff = compute_governed_tag_diff(desired, actual, _resolver_passthrough(), ChangeLogger())

    assert diff.to_delete == set()


def test_governed_tag_differ_marks_tag_for_deletion_when_flag_enabled_and_tag_absent_from_desired():
    """With enable_deletion=True, tags in actual but not in desired flow into to_delete."""
    legacy = _gt("legacy_tag", "legacy", {"a", "b"})
    desired = {_gt("pii", "PII", {"name"})}
    actual = {
        _gt("pii", "PII", {"name"}),
        legacy,
    }

    diff = compute_governed_tag_diff(desired, actual, _resolver_passthrough(), ChangeLogger(), enable_deletion=True)

    assert legacy in diff.to_delete
    assert diff.to_create == set()
    assert diff.to_update == set()


def test_governed_tag_differ_does_not_mark_for_deletion_when_tag_is_in_desired():
    """Tags present on both sides never end up in to_delete, even with the flag on."""
    desired = {_gt("pii", "PII", {"name"})}
    actual = {_gt("pii", "PII", {"name"})}

    diff = compute_governed_tag_diff(desired, actual, _resolver_passthrough(), ChangeLogger(), enable_deletion=True)

    assert diff.to_delete == set()


# ---------------------------------------------------------------------------
# assigners resolution and diffing
# ---------------------------------------------------------------------------


_alice_resolved = Principal(PrincipalType.USER, identifier="alice@example.com", name="alice@example.com")
_engineers_resolved = Principal(PrincipalType.GROUP, identifier="data_engineers", name="data_engineers")


def test_governed_tag_differ_marks_update_when_only_assigners_change():
    """Adding an assigner on an otherwise unchanged tag triggers to_update."""
    desired = {_gt(
        "pii", "PII", {"name"},
        assigners={Principal(PrincipalType.UNKNOWN, name="data_engineers")},
    )}
    actual = {_gt("pii", "PII", {"name"}, assigners=set())}
    resolver = _resolver(name_to_principal={"data_engineers": _engineers_resolved})

    diff = compute_governed_tag_diff(desired, actual, resolver, ChangeLogger())

    assert any(gt.name == "pii" for gt in diff.to_update)
    update = next(gt for gt in diff.to_update if gt.name == "pii")
    assert _engineers_resolved in update.assigners


def test_governed_tag_differ_resolves_actual_principals_via_identifier():
    """Actual-state principals (UNKNOWN with identifier set) are resolved before equality comparison."""
    desired = {_gt(
        "pii", "PII", {"name"},
        assigners={Principal(PrincipalType.UNKNOWN, name="alice@example.com")},
    )}
    actual = {_gt(
        "pii", "PII", {"name"},
        assigners={Principal(PrincipalType.UNKNOWN, identifier="alice@example.com")},
    )}
    resolver = _resolver(
        name_to_principal={"alice@example.com": _alice_resolved},
        identifier_to_principal={"alice@example.com": _alice_resolved},
    )

    diff = compute_governed_tag_diff(desired, actual, resolver, ChangeLogger())

    # Both sides resolve to the same Principal — no diff.
    assert diff.to_update == set()
    assert diff.to_create == set()


def test_governed_tag_differ_drops_unresolvable_principal_and_logs_error():
    """A principal that can't be resolved is dropped from the tag's assigners
    and logged via change_logger.log_error — it never produces a phantom diff."""
    desired = {_gt(
        "pii", "PII", {"name"},
        assigners={Principal(PrincipalType.UNKNOWN, name="ghost_user")},
    )}
    actual = {_gt("pii", "PII", {"name"}, assigners=set())}
    resolver = _resolver()  # nothing resolves
    change_logger = ChangeLogger()

    diff = compute_governed_tag_diff(desired, actual, resolver, change_logger)

    # No phantom create/update — the unresolvable principal was dropped from desired.
    assert diff.to_create == set()
    assert diff.to_update == set()
    assert change_logger.has_errors


def test_governed_tag_differ_treats_reordered_assigners_as_unchanged():
    """assigners is a frozenset — order on either side is irrelevant."""
    p_alice = Principal(PrincipalType.UNKNOWN, name="alice@example.com")
    p_bob = Principal(PrincipalType.UNKNOWN, name="bob@example.com")
    bob_resolved = Principal(PrincipalType.USER, identifier="bob@example.com", name="bob@example.com")

    desired = {_gt("pii", "PII", {"name"}, assigners={p_alice, p_bob})}
    actual = {_gt("pii", "PII", {"name"}, assigners={p_bob, p_alice})}
    resolver = _resolver(
        name_to_principal={
            "alice@example.com": _alice_resolved,
            "bob@example.com": bob_resolved,
        },
        identifier_to_principal={
            "alice@example.com": _alice_resolved,
            "bob@example.com": bob_resolved,
        },
    )

    diff = compute_governed_tag_diff(desired, actual, resolver, ChangeLogger())

    assert diff.to_update == set()
