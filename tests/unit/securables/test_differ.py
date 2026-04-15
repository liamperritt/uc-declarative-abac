from __future__ import annotations

from uc_abac_governor.securables.differ import compute_securable_diff
from uc_abac_governor.securables.state import (
    AttributeUpdate,
    FunctionInfo,
    SecurableAttributes,
    SecurableDiff,
)
from uc_abac_governor.types import Principal, PrincipalType, SecurableType


def _make_function(
    full_name: str = "catalog.schema.my_func",
    parameters: tuple[tuple[str, str], ...] = (("x", "STRING"),),
    definition: str = "RETURN x",
) -> FunctionInfo:
    """Helper to build a FunctionInfo with sensible defaults."""
    return FunctionInfo(
        securable_type=SecurableType.FUNCTION,
        full_name=full_name,
        parameters=parameters,
        definition=definition,
    )


# ---------------------------------------------------------------------------
# Attribute diff tests
# ---------------------------------------------------------------------------


def test_securable_differ_detects_owner_change():
    """An owner difference between desired and actual emits an AttributeUpdate."""
    desired_attrs = {
        SecurableAttributes(
            securable_type=SecurableType.CATALOG,
            full_name="my_catalog",
            owner="new_owner",
        )
    }
    actual_attrs = {
        SecurableAttributes(
            securable_type=SecurableType.CATALOG,
            full_name="my_catalog",
            owner="old_owner",
        )
    }

    diff = compute_securable_diff(desired_attrs, actual_attrs, set(), set())

    assert diff.attributes_to_update == [
        AttributeUpdate(
            securable_type=SecurableType.CATALOG,
            full_name="my_catalog",
            attribute="owner",
            old_value="old_owner",
            new_value="new_owner",
        )
    ]


def test_securable_differ_ignores_matching_owners():
    """Identical owners produce no attribute updates."""
    attrs = {
        SecurableAttributes(
            securable_type=SecurableType.CATALOG,
            full_name="my_catalog",
            owner="same_owner",
        )
    }

    diff = compute_securable_diff(attrs, attrs, set(), set())

    assert diff.attributes_to_update == []


def test_securable_differ_ignores_desired_only_attributes():
    """An attribute in desired but not in actual (non-function securable that
    doesn't exist yet) produces no attribute update."""
    desired_attrs = {
        SecurableAttributes(
            securable_type=SecurableType.CATALOG,
            full_name="my_catalog",
            owner="new_owner",
        )
    }
    actual_attrs: set[SecurableAttributes] = set()

    diff = compute_securable_diff(desired_attrs, actual_attrs, set(), set())

    assert diff.attributes_to_update == []


def test_securable_differ_records_old_and_new_values():
    """AttributeUpdate carries the correct old_value and new_value."""
    desired_attrs = {
        SecurableAttributes(
            securable_type=SecurableType.SCHEMA,
            full_name="catalog.my_schema",
            owner="team_b",
        )
    }
    actual_attrs = {
        SecurableAttributes(
            securable_type=SecurableType.SCHEMA,
            full_name="catalog.my_schema",
            owner="team_a",
        )
    }

    diff = compute_securable_diff(desired_attrs, actual_attrs, set(), set())

    assert len(diff.attributes_to_update) == 1
    update = diff.attributes_to_update[0]
    assert update.old_value == "team_a"
    assert update.new_value == "team_b"
    assert update.attribute == "owner"
    assert update.securable_type == SecurableType.SCHEMA
    assert update.full_name == "catalog.my_schema"


# ---------------------------------------------------------------------------
# Securable (function) diff tests
# ---------------------------------------------------------------------------


def test_securable_differ_detects_new_function():
    """A FunctionInfo in desired but not in actual appears in securables_to_create."""
    func = _make_function(full_name="catalog.schema.new_func")

    diff = compute_securable_diff(set(), set(), {func}, set())

    assert diff.securables_to_create == [func]
    assert diff.securables_to_replace == []


def test_securable_differ_detects_changed_definition():
    """Same full_name with a different definition lands in securables_to_replace."""
    desired_func = _make_function(
        full_name="catalog.schema.my_func",
        definition="RETURN UPPER(x)",
    )
    actual_func = _make_function(
        full_name="catalog.schema.my_func",
        definition="RETURN x",
    )

    diff = compute_securable_diff(set(), set(), {desired_func}, {actual_func})

    assert diff.securables_to_replace == [desired_func]
    assert diff.securables_to_create == []


def test_securable_differ_detects_changed_parameters():
    """Same full_name with different parameters lands in securables_to_replace."""
    desired_func = _make_function(
        full_name="catalog.schema.my_func",
        parameters=(("x", "STRING"), ("y", "INT")),
    )
    actual_func = _make_function(
        full_name="catalog.schema.my_func",
        parameters=(("x", "STRING"),),
    )

    diff = compute_securable_diff(set(), set(), {desired_func}, {actual_func})

    assert diff.securables_to_replace == [desired_func]
    assert diff.securables_to_create == []


def test_securable_differ_ignores_matching_functions():
    """Identical FunctionInfo in both sets produces no create or replace entries."""
    func = _make_function(full_name="catalog.schema.stable_func")

    diff = compute_securable_diff(set(), set(), {func}, {func})

    assert diff.securables_to_create == []
    assert diff.securables_to_replace == []


# ---------------------------------------------------------------------------
# Create + attribute interaction
# ---------------------------------------------------------------------------


def test_securable_differ_emits_attribute_update_for_created_securable():
    """A new function with a desired owner emits both a create entry and an
    attribute update (owner is set after CREATE FUNCTION)."""
    func = _make_function(full_name="catalog.schema.new_func")

    desired_attrs = {
        SecurableAttributes(
            securable_type=SecurableType.FUNCTION,
            full_name="catalog.schema.new_func",
            owner="team_data",
        )
    }
    actual_attrs: set[SecurableAttributes] = set()

    diff = compute_securable_diff(desired_attrs, actual_attrs, {func}, set())

    assert diff.securables_to_create == [func]
    assert len(diff.attributes_to_update) == 1
    update = diff.attributes_to_update[0]
    assert update.full_name == "catalog.schema.new_func"
    assert update.attribute == "owner"
    assert update.new_value == "team_data"


# ---------------------------------------------------------------------------
# Principal-based owner comparison
# ---------------------------------------------------------------------------


def test_securable_differ_compares_owners_by_principal_identifier():
    """When principal mappings are provided, owners with the same identifier
    are considered equal even if the raw owner strings differ."""
    desired = {SecurableAttributes(SecurableType.CATALOG, "my_catalog", owner="sp_display_name")}
    actual = {SecurableAttributes(SecurableType.CATALOG, "my_catalog", owner="72a5956b-app-id")}

    # Both resolve to the same identifier
    sp_principal = Principal(PrincipalType.SERVICE_PRINCIPAL, "72a5956b-app-id", "sp_display_name")

    diff = compute_securable_diff(
        desired, actual, set(), set(),
        desired_owner_principals={"my_catalog": sp_principal},
        actual_owner_principals={"my_catalog": sp_principal},
    )

    assert diff.attributes_to_update == []


def test_securable_differ_emits_principal_values_in_attribute_update():
    """When principal mappings are provided, AttributeUpdate stores Principal objects."""
    desired = {SecurableAttributes(SecurableType.CATALOG, "my_catalog", owner="new_group")}
    actual = {SecurableAttributes(SecurableType.CATALOG, "my_catalog", owner="old_user")}

    new_principal = Principal(PrincipalType.GROUP, "new_group", "new_group")
    old_principal = Principal(PrincipalType.USER, "old_user", "old_user")

    diff = compute_securable_diff(
        desired, actual, set(), set(),
        desired_owner_principals={"my_catalog": new_principal},
        actual_owner_principals={"my_catalog": old_principal},
    )

    assert len(diff.attributes_to_update) == 1
    update = diff.attributes_to_update[0]
    assert isinstance(update.new_value, Principal)
    assert update.new_value == new_principal
    assert isinstance(update.old_value, Principal)
    assert update.old_value == old_principal
