from __future__ import annotations

from uc_abac_governor.governed_tags.differ import compute_governed_tag_diff
from uc_abac_governor.governed_tags.state import GovernedTag


def _gt(name: str, comment: str = "", values: set[str] | None = None) -> GovernedTag:
    return GovernedTag(
        name=name,
        comment=comment,
        allowed_values=frozenset(values or set()),
    )


def test_governed_tag_differ_creates_tag_when_missing_in_actual():
    """A desired tag with no matching actual tag produces a to_create entry."""
    desired = {_gt("pii", "PII", {"name", "email"})}
    actual: set[GovernedTag] = set()

    diff = compute_governed_tag_diff(desired, actual)

    assert _gt("pii", "PII", {"name", "email"}) in diff.to_create
    assert diff.to_update == set()


def test_governed_tag_differ_updates_tag_when_comment_changes():
    """An existing tag with a changed comment produces a to_update entry."""
    desired = {_gt("pii", "Updated comment", {"name"})}
    actual = {_gt("pii", "Original comment", {"name"})}

    diff = compute_governed_tag_diff(desired, actual)

    assert _gt("pii", "Updated comment", {"name"}) in diff.to_update
    assert diff.to_create == set()


def test_governed_tag_differ_updates_tag_when_allowed_values_change():
    """An existing tag with a different allowed_values set produces a to_update entry."""
    desired = {_gt("pii", "PII", {"name", "email", "phone"})}
    actual = {_gt("pii", "PII", {"name", "email"})}

    diff = compute_governed_tag_diff(desired, actual)

    update = next(iter(diff.to_update))
    assert update.name == "pii"
    assert update.allowed_values == frozenset({"name", "email", "phone"})


def test_governed_tag_differ_treats_reordered_allowed_values_as_unchanged():
    """allowed_values is set-equal — reordering alone does not produce an update."""
    # frozensets inherently ignore order; this test pins the behaviour against
    # a future change that might switch to a tuple/list comparison.
    desired = {_gt("pii", "PII", {"phone", "name", "email"})}
    actual = {_gt("pii", "PII", {"email", "name", "phone"})}

    diff = compute_governed_tag_diff(desired, actual)

    assert diff.to_update == set()
    assert diff.to_create == set()


def test_governed_tag_differ_ignores_tag_when_in_actual_but_not_desired():
    """A tag present in the account but absent from YAML is left alone — no-delete invariant."""
    desired: set[GovernedTag] = set()
    actual = {_gt("legacy", "legacy tag", {"a", "b"})}

    diff = compute_governed_tag_diff(desired, actual)

    assert diff.to_create == set()
    assert diff.to_update == set()


def test_governed_tag_differ_produces_empty_diff_when_in_sync():
    """When desired == actual, both to_create and to_update are empty."""
    gt = _gt("pii", "PII", {"name", "email"})

    diff = compute_governed_tag_diff({gt}, {gt})

    assert diff.to_create == set()
    assert diff.to_update == set()


def test_governed_tag_differ_records_old_values_for_updates():
    """old_values captures the actual state pre-update, keyed by tag name."""
    desired = {_gt("pii", "New comment", {"name"})}
    actual = {_gt("pii", "Old comment", {"name"})}

    diff = compute_governed_tag_diff(desired, actual)

    assert diff.old_values["pii"] == _gt("pii", "Old comment", {"name"})
