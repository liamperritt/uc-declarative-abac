from __future__ import annotations

from unittest.mock import MagicMock

from uc_abac_governor.logger import ChangeLogger
from uc_abac_governor.principals.resolver import PrincipalResolver
from uc_abac_governor.principals.state import Principal
from uc_abac_governor.securables.differ import compute_securable_diff
from uc_abac_governor.securables.state import (
    AttributeUpdate,
    Function,
    SecurableAttributes,
    SecurableDiff,
)
from uc_abac_governor.types import PrincipalType, SecurableType


def _resolver() -> PrincipalResolver:
    """A resolver whose ws_helper is never consulted — test inputs are already resolved."""
    return PrincipalResolver(MagicMock())


def _change_logger() -> ChangeLogger:
    return ChangeLogger()


def _owner(name: str, principal_type: PrincipalType = PrincipalType.USER) -> Principal:
    """Shorthand for a resolved Principal suitable for owner fields."""
    return Principal(principal_type=principal_type, identifier=name, name=name)


def _make_function(
    full_name: str = "catalog.schema.my_func",
    parameters: tuple[tuple[str, str], ...] = (("x", "STRING"),),
    definition: str = "RETURN x",
) -> Function:
    """Helper to build a Function with sensible defaults."""
    return Function(
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
            owner=_owner("new_owner"),
        )
    }
    actual_attrs = {
        SecurableAttributes(
            securable_type=SecurableType.CATALOG,
            full_name="my_catalog",
            owner=_owner("old_owner"),
        )
    }

    diff = compute_securable_diff(desired_attrs, actual_attrs, set(), set(), _resolver(), _change_logger())

    assert diff.attributes_to_update == [
        AttributeUpdate(
            securable_type=SecurableType.CATALOG,
            full_name="my_catalog",
            attribute="owner",
            old_value=_owner("old_owner"),
            new_value=_owner("new_owner"),
        )
    ]


def test_securable_differ_ignores_matching_owners():
    """Identical owners produce no attribute updates."""
    attrs = {
        SecurableAttributes(
            securable_type=SecurableType.CATALOG,
            full_name="my_catalog",
            owner=_owner("same_owner"),
        )
    }

    diff = compute_securable_diff(attrs, attrs, set(), set(), _resolver(), _change_logger())

    assert diff.attributes_to_update == []


def test_securable_differ_ignores_desired_only_attributes():
    """An attribute in desired but not in actual (non-function securable that
    doesn't exist yet) produces no attribute update."""
    desired_attrs = {
        SecurableAttributes(
            securable_type=SecurableType.CATALOG,
            full_name="my_catalog",
            owner=_owner("new_owner"),
        )
    }
    actual_attrs: set[SecurableAttributes] = set()

    diff = compute_securable_diff(desired_attrs, actual_attrs, set(), set(), _resolver(), _change_logger())

    assert diff.attributes_to_update == []


def test_securable_differ_records_old_and_new_values():
    """AttributeUpdate carries the correct old_value and new_value."""
    desired_attrs = {
        SecurableAttributes(
            securable_type=SecurableType.SCHEMA,
            full_name="catalog.my_schema",
            owner=_owner("team_b"),
        )
    }
    actual_attrs = {
        SecurableAttributes(
            securable_type=SecurableType.SCHEMA,
            full_name="catalog.my_schema",
            owner=_owner("team_a"),
        )
    }

    diff = compute_securable_diff(desired_attrs, actual_attrs, set(), set(), _resolver(), _change_logger())

    assert len(diff.attributes_to_update) == 1
    update = diff.attributes_to_update[0]
    assert update.old_value == _owner("team_a")
    assert update.new_value == _owner("team_b")
    assert update.attribute == "owner"
    assert update.securable_type == SecurableType.SCHEMA
    assert update.full_name == "catalog.my_schema"


# ---------------------------------------------------------------------------
# Securable (function) diff tests
# ---------------------------------------------------------------------------


def test_securable_differ_detects_new_function():
    """A Function in desired but not in actual appears in securables_to_create."""
    func = _make_function(full_name="catalog.schema.new_func")

    diff = compute_securable_diff(set(), set(), {func}, set(), _resolver(), _change_logger())

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

    diff = compute_securable_diff(set(), set(), {desired_func}, {actual_func}, _resolver(), _change_logger())

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

    diff = compute_securable_diff(set(), set(), {desired_func}, {actual_func}, _resolver(), _change_logger())

    assert diff.securables_to_replace == [desired_func]
    assert diff.securables_to_create == []


def test_securable_differ_ignores_matching_functions():
    """Identical Function in both sets produces no create or replace entries."""
    func = _make_function(full_name="catalog.schema.stable_func")

    diff = compute_securable_diff(set(), set(), {func}, {func}, _resolver(), _change_logger())

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
            owner=_owner("team_data"),
        )
    }
    actual_attrs: set[SecurableAttributes] = set()

    diff = compute_securable_diff(desired_attrs, actual_attrs, {func}, set(), _resolver(), _change_logger())

    assert diff.securables_to_create == [func]
    assert len(diff.attributes_to_update) == 1
    update = diff.attributes_to_update[0]
    assert update.full_name == "catalog.schema.new_func"
    assert update.attribute == "owner"
    assert update.new_value == _owner("team_data")


# ---------------------------------------------------------------------------
# Principal-based owner comparison
# ---------------------------------------------------------------------------


def test_securable_differ_compares_owners_by_resolved_principal_equality():
    """Two resolved Principals with the same identifier compare equal, so no update is emitted."""
    sp_principal = Principal(PrincipalType.SERVICE_PRINCIPAL, "72a5956b-app-id", "sp_display_name")
    desired = {SecurableAttributes(SecurableType.CATALOG, "my_catalog", owner=sp_principal)}
    actual = {SecurableAttributes(SecurableType.CATALOG, "my_catalog", owner=sp_principal)}

    diff = compute_securable_diff(desired, actual, set(), set(), _resolver(), _change_logger())

    assert diff.attributes_to_update == []


def test_securable_differ_emits_principal_values_in_attribute_update():
    """When resolved owner Principals differ, the attribute update carries them directly."""
    new_principal = Principal(PrincipalType.GROUP, "new_group", "new_group")
    old_principal = Principal(PrincipalType.USER, "old_user", "old_user")
    desired = {SecurableAttributes(SecurableType.CATALOG, "my_catalog", owner=new_principal)}
    actual = {SecurableAttributes(SecurableType.CATALOG, "my_catalog", owner=old_principal)}

    diff = compute_securable_diff(desired, actual, set(), set(), _resolver(), _change_logger())

    assert len(diff.attributes_to_update) == 1
    update = diff.attributes_to_update[0]
    assert isinstance(update.new_value, Principal)
    assert update.new_value == new_principal
    assert isinstance(update.old_value, Principal)
    assert update.old_value == old_principal


# ---------------------------------------------------------------------------
# Function comment diffing
# ---------------------------------------------------------------------------


def test_securable_differ_comment_change_triggers_replace_not_attribute_update():
    """A change to Function.comment lands in securables_to_replace, not attributes_to_update."""
    desired_func = Function(
        securable_type=SecurableType.FUNCTION,
        full_name="catalog.schema.my_func",
        parameters=(("x", "STRING"),),
        definition="x",
        comment="new comment",
    )
    actual_func = Function(
        securable_type=SecurableType.FUNCTION,
        full_name="catalog.schema.my_func",
        parameters=(("x", "STRING"),),
        definition="x",
        comment="old comment",
    )

    diff = compute_securable_diff(
        set(), set(), {desired_func}, {actual_func}, _resolver(), _change_logger(),
    )

    assert diff.securables_to_replace == [desired_func]
    assert diff.attributes_to_update == []


def test_securable_differ_ignores_matching_function_comments():
    """Identical Function.comment values produce no diff."""
    func = Function(
        securable_type=SecurableType.FUNCTION,
        full_name="catalog.schema.my_func",
        parameters=(),
        definition="x",
        comment="same",
    )

    diff = compute_securable_diff(
        set(), set(), {func}, {func}, _resolver(), _change_logger(),
    )

    assert diff.securables_to_create == []
    assert diff.securables_to_replace == []
