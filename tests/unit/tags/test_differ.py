from __future__ import annotations

from uc_declarative_abac.tags import (
    compute_tag_diff,
    SecurableTag,
    TagDiff,
)
from uc_declarative_abac.types import SecurableType


# ---------------------------------------------------------------------------
# Tags to add, update and remove
# ---------------------------------------------------------------------------


def test_tag_differ_computes_tags_to_add():
    """A desired tag key not present in actual appears in to_add."""
    desired = {
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="catalog.schema.orders",
            tag_name="pii",
            tag_value="true",
        )
    }
    actual: set[SecurableTag] = set()

    diff = compute_tag_diff(desired, actual)

    assert diff.to_add == desired
    assert diff.to_update == set()
    assert diff.to_remove == set()


def test_tag_differ_computes_tags_to_update():
    """A tag key present in both sets with a different value appears in to_update
    carrying the desired value."""
    desired_tag = SecurableTag(
        securable_type=SecurableType.CATALOG,
        securable_full_name="my_catalog",
        tag_name="env",
        tag_value="prod",
    )
    actual_tag = SecurableTag(
        securable_type=SecurableType.CATALOG,
        securable_full_name="my_catalog",
        tag_name="env",
        tag_value="dev",
    )

    diff = compute_tag_diff({desired_tag}, {actual_tag})

    assert diff.to_update == {desired_tag}
    assert diff.to_add == set()
    assert diff.to_remove == set()


def test_tag_differ_computes_tags_to_remove():
    """A tag key present in actual but absent from desired appears in to_remove."""
    actual_tag = SecurableTag(
        securable_type=SecurableType.SCHEMA,
        securable_full_name="catalog.sales",
        tag_name="deprecated",
        tag_value="true",
    )

    diff = compute_tag_diff(set(), {actual_tag})

    assert diff.to_remove == {actual_tag}
    assert diff.to_add == set()
    assert diff.to_update == set()


# ---------------------------------------------------------------------------
# Empty sets
# ---------------------------------------------------------------------------


def test_tag_differ_returns_empty_diff_when_in_sync():
    """Identical desired and actual sets produce an entirely empty diff."""
    tags = {
        SecurableTag(
            securable_type=SecurableType.CATALOG,
            securable_full_name="my_catalog",
            tag_name="env",
            tag_value="prod",
        ),
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_catalog.sales.orders",
            tag_name="pii",
            tag_value="true",
        ),
    }

    diff = compute_tag_diff(tags, tags)

    assert diff == TagDiff()


def test_tag_differ_handles_empty_desired():
    """Empty desired with non-empty actual produces only to_remove entries."""
    actual = {
        SecurableTag(
            securable_type=SecurableType.VOLUME,
            securable_full_name="catalog.landing.files",
            tag_name="zone",
            tag_value="raw",
        ),
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="catalog.sales.orders",
            tag_name="pii",
            tag_value="true",
        ),
    }

    diff = compute_tag_diff(set(), actual)

    assert diff.to_remove == actual
    assert diff.to_add == set()
    assert diff.to_update == set()


def test_tag_differ_handles_empty_actual():
    """Non-empty desired with empty actual produces only to_add entries."""
    desired = {
        SecurableTag(
            securable_type=SecurableType.CATALOG,
            securable_full_name="my_catalog",
            tag_name="env",
            tag_value="prod",
        ),
        SecurableTag(
            securable_type=SecurableType.SCHEMA,
            securable_full_name="my_catalog.sales",
            tag_name="team",
            tag_value="revenue",
        ),
    }

    diff = compute_tag_diff(desired, set())

    assert diff.to_add == desired
    assert diff.to_update == set()
    assert diff.to_remove == set()


# ---------------------------------------------------------------------------
# Distinguishes add from update on the same securable
# ---------------------------------------------------------------------------


def test_tag_differ_distinguishes_add_from_update():
    """On the same securable, a new tag key lands in to_add while a changed
    value for an existing tag key lands in to_update."""
    common_type = SecurableType.TABLE
    common_name = "catalog.sales.orders"

    # Existing tag whose value will change
    desired_updated = SecurableTag(
        securable_type=common_type,
        securable_full_name=common_name,
        tag_name="env",
        tag_value="prod",
    )
    actual_outdated = SecurableTag(
        securable_type=common_type,
        securable_full_name=common_name,
        tag_name="env",
        tag_value="staging",
    )

    # Brand-new tag
    desired_new = SecurableTag(
        securable_type=common_type,
        securable_full_name=common_name,
        tag_name="pii",
        tag_value="true",
    )

    # Tag that should stay unchanged
    unchanged = SecurableTag(
        securable_type=common_type,
        securable_full_name=common_name,
        tag_name="team",
        tag_value="revenue",
    )

    desired = {desired_updated, desired_new, unchanged}
    actual = {actual_outdated, unchanged}

    diff = compute_tag_diff(desired, actual)

    assert diff.to_add == {desired_new}
    assert diff.to_update == {desired_updated}
    assert diff.to_remove == set()
