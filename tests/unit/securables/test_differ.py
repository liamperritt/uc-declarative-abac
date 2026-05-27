from __future__ import annotations

from unittest.mock import MagicMock

from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.principals.resolver import PrincipalResolver
from uc_declarative_abac.principals.state import Principal
from uc_declarative_abac.securables.differ import compute_securable_diff
from uc_declarative_abac.securables.state import (
    AttributeUpdate,
    Column,
    Function,
    Securable,
    SecurableAttributes,
    SecurableDiff,
    Table,
)
from uc_declarative_abac.types import NonexistentSecurableError, PrincipalType, SecurableType

import pytest


# Catalogs referenced across the test fixtures. Tests opting into creation pass
# this set as ``creation_in_scope_catalogs`` — equivalent to "create everything"
# under the per-catalog model. Tests exercising the disabled path pass an
# explicit ``frozenset()`` instead.
_ALL_TEST_CATALOGS = frozenset(
    {"cat", "new_cat", "ghost", "ghost_catalog", "ghost_cat_a", "ghost_cat_b", "my_catalog", "catalog"}
)


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


# ---------------------------------------------------------------------------
# Comment + location attribute diffing
# ---------------------------------------------------------------------------


def _attrs(
    sec_type: SecurableType,
    full_name: str,
    *,
    owner: Principal | None = None,
    comment: str | None = None,
    location: str | None = None,
) -> SecurableAttributes:
    return SecurableAttributes(
        securable_type=sec_type,
        full_name=full_name,
        owner=owner,
        comment=comment,
        location=location,
    )


def test_securable_differ_detects_catalog_comment_change():
    """A comment difference on an existing catalog produces an AttributeUpdate."""
    desired = {_attrs(SecurableType.CATALOG, "my_catalog", comment="New")}
    actual = {_attrs(SecurableType.CATALOG, "my_catalog", comment="Old")}

    diff = compute_securable_diff(desired, actual, set(), set(), _resolver(), _change_logger())

    assert len(diff.attributes_to_update) == 1
    update = diff.attributes_to_update[0]
    assert update.attribute == "comment"
    assert update.old_value == "Old"
    assert update.new_value == "New"


def test_securable_differ_detects_schema_comment_change():
    desired = {_attrs(SecurableType.SCHEMA, "cat.sales", comment="New")}
    actual = {_attrs(SecurableType.SCHEMA, "cat.sales", comment="Old")}

    diff = compute_securable_diff(desired, actual, set(), set(), _resolver(), _change_logger())

    assert [(u.attribute, u.new_value) for u in diff.attributes_to_update] == [("comment", "New")]


def test_securable_differ_detects_table_comment_change_on_non_view_table():
    """Comment diff on a TABLE whose actual table_type is MANAGED flows through normally."""
    table = Table(
        securable_type=SecurableType.TABLE,
        full_name="cat.sales.orders",
        table_type="MANAGED",
    )
    desired = {_attrs(SecurableType.TABLE, "cat.sales.orders", comment="New")}
    actual = {_attrs(SecurableType.TABLE, "cat.sales.orders", comment="Old")}

    diff = compute_securable_diff(desired, actual, set(), {table}, _resolver(), _change_logger())

    assert [(u.attribute, u.new_value) for u in diff.attributes_to_update] == [("comment", "New")]


def test_securable_differ_detects_volume_comment_change():
    desired = {_attrs(SecurableType.VOLUME, "cat.landing.raw", comment="New")}
    actual = {_attrs(SecurableType.VOLUME, "cat.landing.raw", comment="Old")}

    diff = compute_securable_diff(desired, actual, set(), set(), _resolver(), _change_logger())

    assert [(u.attribute, u.new_value) for u in diff.attributes_to_update] == [("comment", "New")]


def test_securable_differ_ignores_matching_comments():
    """Identical comment on both sides produces no diff."""
    desired = {_attrs(SecurableType.CATALOG, "cat", comment="same")}
    actual = {_attrs(SecurableType.CATALOG, "cat", comment="same")}

    diff = compute_securable_diff(desired, actual, set(), set(), _resolver(), _change_logger())

    assert diff.attributes_to_update == []


def test_securable_differ_ignores_comment_when_config_does_not_specify():
    """Desired comment None + actual comment set → no diff (unmanaged direction)."""
    desired = {_attrs(SecurableType.CATALOG, "cat", comment=None)}
    actual = {_attrs(SecurableType.CATALOG, "cat", comment="some")}

    diff = compute_securable_diff(desired, actual, set(), set(), _resolver(), _change_logger())

    assert diff.attributes_to_update == []


def test_securable_differ_detects_catalog_managed_location_change():
    desired = {_attrs(SecurableType.CATALOG, "cat", location="s3://new")}
    actual = {_attrs(SecurableType.CATALOG, "cat", location="s3://old")}

    diff = compute_securable_diff(desired, actual, set(), set(), _resolver(), _change_logger())

    assert [(u.attribute, u.new_value) for u in diff.attributes_to_update] == [("location", "s3://new")]


def test_securable_differ_detects_schema_managed_location_change():
    desired = {_attrs(SecurableType.SCHEMA, "cat.sales", location="s3://new")}
    actual = {_attrs(SecurableType.SCHEMA, "cat.sales", location="s3://old")}

    diff = compute_securable_diff(desired, actual, set(), set(), _resolver(), _change_logger())

    assert [(u.attribute, u.new_value) for u in diff.attributes_to_update] == [("location", "s3://new")]


# ---------------------------------------------------------------------------
# View-comment guard
# ---------------------------------------------------------------------------


def test_securable_differ_logs_error_when_comment_change_targets_a_view():
    """Comment change on an actual-side view (table_type='VIEW') is refused via ChangeLogger."""
    view = Table(
        securable_type=SecurableType.TABLE,
        full_name="cat.sales.orders_v",
        table_type="VIEW",
    )
    desired = {_attrs(SecurableType.TABLE, "cat.sales.orders_v", comment="New")}
    actual = {_attrs(SecurableType.TABLE, "cat.sales.orders_v", comment="Old")}
    logger = _change_logger()

    diff = compute_securable_diff(desired, actual, set(), {view}, _resolver(), logger)

    assert diff.attributes_to_update == []
    assert len(logger.errors) == 1
    assert "comment" in logger.errors[0].context.lower()
    assert "TABLE" in logger.errors[0].context
    assert "VIEW" in str(logger.errors[0].exception)


# ---------------------------------------------------------------------------
# Table/volume external-location guard
# ---------------------------------------------------------------------------


def test_securable_differ_logs_error_when_existing_table_location_changes():
    """Location change on an existing table fails — external location is immutable."""
    table = Table(
        securable_type=SecurableType.TABLE,
        full_name="cat.sales.orders",
        table_type="EXTERNAL",
    )
    desired = {_attrs(SecurableType.TABLE, "cat.sales.orders", location="s3://new")}
    actual = {_attrs(SecurableType.TABLE, "cat.sales.orders", location="s3://old")}
    logger = _change_logger()

    diff = compute_securable_diff(desired, actual, set(), {table}, _resolver(), logger)

    assert diff.attributes_to_update == []
    assert len(logger.errors) == 1
    assert "location" in logger.errors[0].context.lower()
    assert "immutable" in str(logger.errors[0].exception).lower()


def test_securable_differ_logs_error_when_existing_volume_location_changes():
    """Location change on an existing volume fails — external location is immutable."""
    desired = {_attrs(SecurableType.VOLUME, "cat.landing.raw", location="s3://new")}
    actual = {_attrs(SecurableType.VOLUME, "cat.landing.raw", location="s3://old")}
    logger = _change_logger()

    diff = compute_securable_diff(desired, actual, set(), set(), _resolver(), logger)

    assert diff.attributes_to_update == []
    assert len(logger.errors) == 1
    assert "location" in logger.errors[0].context.lower()


def test_securable_differ_logs_error_when_config_sets_location_on_existing_managed_table():
    """Config declares external location on a table that exists in UC with no location → still an error."""
    table = Table(
        securable_type=SecurableType.TABLE,
        full_name="cat.sales.orders",
        table_type="MANAGED",
    )
    desired = {_attrs(SecurableType.TABLE, "cat.sales.orders", location="s3://new")}
    actual = {_attrs(SecurableType.TABLE, "cat.sales.orders", location=None)}
    logger = _change_logger()

    diff = compute_securable_diff(desired, actual, set(), {table}, _resolver(), logger)

    assert diff.attributes_to_update == []
    assert len(logger.errors) == 1


def test_securable_differ_does_not_log_error_when_config_omits_location_for_existing_external_table():
    """Config has no location, actual has one → no diff, no error (unmanaged direction)."""
    table = Table(
        securable_type=SecurableType.TABLE,
        full_name="cat.sales.orders",
        table_type="EXTERNAL",
    )
    desired = {_attrs(SecurableType.TABLE, "cat.sales.orders", location=None)}
    actual = {_attrs(SecurableType.TABLE, "cat.sales.orders", location="s3://existing")}
    logger = _change_logger()

    diff = compute_securable_diff(desired, actual, set(), {table}, _resolver(), logger)

    assert diff.attributes_to_update == []
    assert logger.errors == []


# ---------------------------------------------------------------------------
# Newly-created securables: comment/location handled by CREATE, not ALTER
# ---------------------------------------------------------------------------


def test_securable_differ_does_not_emit_comment_or_location_update_for_newly_created_catalog():
    """A new catalog's comment + location ride along on the CREATE — no AttributeUpdate."""
    catalog = Securable(
        securable_type=SecurableType.CATALOG,
        full_name="new_cat",
        comment="Brand new",
        location="s3://new_cat",
    )
    desired_attrs = {_attrs(SecurableType.CATALOG, "new_cat", comment="Brand new", location="s3://new_cat")}

    diff = compute_securable_diff(
        desired_attrs, set(), {catalog}, set(), _resolver(), _change_logger(),
        creation_in_scope_catalogs=frozenset({"new_cat"}),
    )

    assert catalog in diff.securables_to_create
    attribute_names = {u.attribute for u in diff.attributes_to_update}
    assert "comment" not in attribute_names
    assert "location" not in attribute_names


def test_securable_differ_does_not_emit_comment_or_location_update_for_newly_created_table():
    """A new table's comment + external location ride along on CREATE — no AttributeUpdate."""
    table = Table(
        securable_type=SecurableType.TABLE,
        full_name="new_cat.sales.orders",
        columns=(Column(securable_type=SecurableType.COLUMN, full_name="new_cat.sales.orders.id", data_type="BIGINT"),),
        comment="New table",
        location="s3://ext/orders",
    )
    desired_attrs = {_attrs(SecurableType.TABLE, "new_cat.sales.orders", comment="New table", location="s3://ext/orders")}

    diff = compute_securable_diff(
        desired_attrs, set(), {table}, set(), _resolver(), _change_logger(),
        creation_in_scope_catalogs=frozenset({"new_cat"}),
    )

    attribute_names = {u.attribute for u in diff.attributes_to_update}
    assert "comment" not in attribute_names
    assert "location" not in attribute_names


def test_securable_differ_still_emits_owner_update_for_newly_created_catalog():
    """Owner is set via SDK after CREATE (UC CREATE doesn't accept owner) — regression guard."""
    catalog = Securable(
        securable_type=SecurableType.CATALOG,
        full_name="new_cat",
    )
    desired_attrs = {_attrs(SecurableType.CATALOG, "new_cat", owner=_owner("team_data"))}

    diff = compute_securable_diff(
        desired_attrs, set(), {catalog}, set(), _resolver(), _change_logger(),
        creation_in_scope_catalogs=frozenset({"new_cat"}),
    )

    attribute_names = {u.attribute for u in diff.attributes_to_update}
    assert "owner" in attribute_names


# ---------------------------------------------------------------------------
# Owner-immutable table types (MATERIALIZED_VIEW, STREAMING_TABLE)
# ---------------------------------------------------------------------------


def test_securable_differ_logs_error_when_owner_change_targets_a_materialized_view():
    """Owner change on a Table whose actual table_type is MATERIALIZED_VIEW is refused."""
    mv = Table(
        securable_type=SecurableType.TABLE,
        full_name="cat.sales.orders_mv",
        table_type="MATERIALIZED_VIEW",
    )
    desired = {_attrs(SecurableType.TABLE, "cat.sales.orders_mv", owner=_owner("new_owner"))}
    actual = {_attrs(SecurableType.TABLE, "cat.sales.orders_mv", owner=_owner("old_owner"))}
    logger = _change_logger()

    diff = compute_securable_diff(desired, actual, set(), {mv}, _resolver(), logger)

    assert diff.attributes_to_update == []
    assert len(logger.errors) == 1
    assert "owner" in logger.errors[0].context.lower()
    assert "TABLE" in logger.errors[0].context
    assert "cat.sales.orders_mv" in logger.errors[0].context


def test_securable_differ_logs_error_when_owner_change_targets_a_streaming_table():
    """Owner change on a Table whose actual table_type is STREAMING_TABLE is refused."""
    st = Table(
        securable_type=SecurableType.TABLE,
        full_name="cat.sales.orders_st",
        table_type="STREAMING_TABLE",
    )
    desired = {_attrs(SecurableType.TABLE, "cat.sales.orders_st", owner=_owner("new_owner"))}
    actual = {_attrs(SecurableType.TABLE, "cat.sales.orders_st", owner=_owner("old_owner"))}
    logger = _change_logger()

    diff = compute_securable_diff(desired, actual, set(), {st}, _resolver(), logger)

    assert diff.attributes_to_update == []
    assert len(logger.errors) == 1
    assert "owner" in logger.errors[0].context.lower()


def test_securable_differ_emits_owner_change_for_view_table_type():
    """Regression guard: regular VIEWs support owner changes via ALTER VIEW … OWNER TO."""
    view = Table(
        securable_type=SecurableType.TABLE,
        full_name="cat.sales.orders_v",
        table_type="VIEW",
    )
    desired = {_attrs(SecurableType.TABLE, "cat.sales.orders_v", owner=_owner("new_owner"))}
    actual = {_attrs(SecurableType.TABLE, "cat.sales.orders_v", owner=_owner("old_owner"))}
    logger = _change_logger()

    diff = compute_securable_diff(desired, actual, set(), {view}, _resolver(), logger)

    assert [(u.attribute, u.new_value) for u in diff.attributes_to_update] == [
        ("owner", _owner("new_owner")),
    ]
    assert logger.errors == []


def test_securable_differ_emits_owner_change_for_managed_table():
    """Regression guard: MANAGED tables support owner changes normally."""
    table = Table(
        securable_type=SecurableType.TABLE,
        full_name="cat.sales.orders",
        table_type="MANAGED",
    )
    desired = {_attrs(SecurableType.TABLE, "cat.sales.orders", owner=_owner("new_owner"))}
    actual = {_attrs(SecurableType.TABLE, "cat.sales.orders", owner=_owner("old_owner"))}
    logger = _change_logger()

    diff = compute_securable_diff(desired, actual, set(), {table}, _resolver(), logger)

    assert [(u.attribute, u.new_value) for u in diff.attributes_to_update] == [
        ("owner", _owner("new_owner")),
    ]
    assert logger.errors == []


def test_securable_differ_does_not_log_error_when_owner_matches_on_materialized_view():
    """When desired and actual owners on an MV match, no diff is emitted and no error is logged."""
    mv = Table(
        securable_type=SecurableType.TABLE,
        full_name="cat.sales.orders_mv",
        table_type="MATERIALIZED_VIEW",
    )
    same_owner = _owner("same")
    desired = {_attrs(SecurableType.TABLE, "cat.sales.orders_mv", owner=same_owner)}
    actual = {_attrs(SecurableType.TABLE, "cat.sales.orders_mv", owner=same_owner)}
    logger = _change_logger()

    diff = compute_securable_diff(desired, actual, set(), {mv}, _resolver(), logger)

    assert diff.attributes_to_update == []
    assert logger.errors == []


def test_securable_differ_owner_guard_does_not_affect_non_owner_attributes_on_mv():
    """The owner-immutable guard fires only for `owner` — a comment update on an MV doesn't
    trigger the owner-immutable error (the MV's table_type is not VIEW, so the comment update
    flows through to the executor as an ALTER)."""
    mv = Table(
        securable_type=SecurableType.TABLE,
        full_name="cat.sales.orders_mv",
        table_type="MATERIALIZED_VIEW",
    )
    desired = {_attrs(SecurableType.TABLE, "cat.sales.orders_mv", comment="new")}
    actual = {_attrs(SecurableType.TABLE, "cat.sales.orders_mv", comment="old")}
    logger = _change_logger()

    diff = compute_securable_diff(desired, actual, set(), {mv}, _resolver(), logger)

    # The owner guard is not triggered. The comment update is emitted normally since
    # MATERIALIZED_VIEW is not in the comment-immutable (VIEW-only) set.
    assert [(u.attribute, u.new_value) for u in diff.attributes_to_update] == [("comment", "new")]
    assert logger.errors == []


# ---------------------------------------------------------------------------
# Nonexistent-securable existence enforcement
# ---------------------------------------------------------------------------


def _sec(sec_type: SecurableType, full_name: str) -> Securable:
    return Securable(securable_type=sec_type, full_name=full_name)


def _nonexistent_errors(change_logger: ChangeLogger) -> list:
    """Helper — extract the NonexistentSecurableError payloads from a ChangeLogger."""
    return [
        e.exception for e in change_logger.errors
        if isinstance(e.exception, NonexistentSecurableError)
    ]


def test_securable_differ_logs_nonexistent_securable_error_when_catalog_does_not_exist():
    """A desired catalog absent from actual is logged (not raised) as a NonexistentSecurableError."""
    desired = {_sec(SecurableType.CATALOG, "ghost_catalog")}
    change_logger = _change_logger()

    compute_securable_diff(set(), set(), desired, set(), _resolver(), change_logger)

    errors = _nonexistent_errors(change_logger)
    assert len(errors) == 1
    assert errors[0].securable_type == SecurableType.CATALOG
    assert errors[0].full_name == "ghost_catalog"


def test_securable_differ_logs_nonexistent_securable_error_when_schema_does_not_exist():
    """A desired schema absent from actual is logged as a NonexistentSecurableError."""
    desired = {
        _sec(SecurableType.CATALOG, "cat"),
        _sec(SecurableType.SCHEMA, "cat.ghost_schema"),
    }
    actual = {_sec(SecurableType.CATALOG, "cat")}
    change_logger = _change_logger()

    compute_securable_diff(set(), set(), desired, actual, _resolver(), change_logger)

    offenders = {(e.securable_type, e.full_name) for e in _nonexistent_errors(change_logger)}
    assert (SecurableType.SCHEMA, "cat.ghost_schema") in offenders


def test_securable_differ_logs_nonexistent_securable_error_when_table_does_not_exist():
    """A desired table absent from actual is logged as a NonexistentSecurableError."""
    desired = {
        _sec(SecurableType.CATALOG, "cat"),
        _sec(SecurableType.SCHEMA, "cat.sch"),
        _sec(SecurableType.TABLE, "cat.sch.ghost_table"),
    }
    actual = {
        _sec(SecurableType.CATALOG, "cat"),
        _sec(SecurableType.SCHEMA, "cat.sch"),
    }
    change_logger = _change_logger()

    compute_securable_diff(set(), set(), desired, actual, _resolver(), change_logger)

    offenders = {(e.securable_type, e.full_name) for e in _nonexistent_errors(change_logger)}
    assert (SecurableType.TABLE, "cat.sch.ghost_table") in offenders


def test_securable_differ_logs_nonexistent_securable_error_when_volume_does_not_exist():
    """A desired volume absent from actual is logged as a NonexistentSecurableError."""
    desired = {
        _sec(SecurableType.CATALOG, "cat"),
        _sec(SecurableType.SCHEMA, "cat.raw"),
        _sec(SecurableType.VOLUME, "cat.raw.ghost_volume"),
    }
    actual = {
        _sec(SecurableType.CATALOG, "cat"),
        _sec(SecurableType.SCHEMA, "cat.raw"),
    }
    change_logger = _change_logger()

    compute_securable_diff(set(), set(), desired, actual, _resolver(), change_logger)

    offenders = {(e.securable_type, e.full_name) for e in _nonexistent_errors(change_logger)}
    assert (SecurableType.VOLUME, "cat.raw.ghost_volume") in offenders


def test_securable_differ_logs_one_error_per_offender_when_multiple_nonexistent():
    """Every nonexistent non-function securable produces its own ExecutionError in the logger."""
    desired = {
        _sec(SecurableType.CATALOG, "ghost_cat_a"),
        _sec(SecurableType.CATALOG, "ghost_cat_b"),
        _sec(SecurableType.SCHEMA, "ghost_cat_a.ghost_sch"),
    }
    change_logger = _change_logger()

    compute_securable_diff(set(), set(), desired, set(), _resolver(), change_logger)

    offenders = {(e.securable_type, e.full_name) for e in _nonexistent_errors(change_logger)}
    assert offenders == {
        (SecurableType.CATALOG, "ghost_cat_a"),
        (SecurableType.CATALOG, "ghost_cat_b"),
        (SecurableType.SCHEMA, "ghost_cat_a.ghost_sch"),
    }


def test_securable_differ_drops_nonexistent_securables_from_to_create():
    """After logging, nonexistent non-function entries are dropped from
    securables_to_create so downstream executors don't attempt to touch them."""
    desired = {_sec(SecurableType.CATALOG, "ghost_catalog")}
    change_logger = _change_logger()

    diff = compute_securable_diff(set(), set(), desired, set(), _resolver(), change_logger)

    assert diff.securables_to_create == []


def test_securable_differ_does_not_log_error_when_function_is_nonexistent_in_actual():
    """A Function absent from actual is engine-created, not an error; it flows into
    securables_to_create so the executor can CREATE FUNCTION it, and nothing is
    logged in the ChangeLogger."""
    func = Function(
        securable_type=SecurableType.FUNCTION,
        full_name="cat.sch.new_func",
        parameters=(),
        definition="1",
    )
    desired = {
        _sec(SecurableType.CATALOG, "cat"),
        _sec(SecurableType.SCHEMA, "cat.sch"),
        func,
    }
    actual = {
        _sec(SecurableType.CATALOG, "cat"),
        _sec(SecurableType.SCHEMA, "cat.sch"),
    }
    change_logger = _change_logger()

    diff = compute_securable_diff(set(), set(), desired, actual, _resolver(), change_logger)

    assert func in diff.securables_to_create
    assert _nonexistent_errors(change_logger) == []


def test_securable_differ_returns_diff_normally_when_every_declared_securable_is_in_actual():
    """When every declared non-function securable exists in actual, the diff is computed
    normally and nothing is logged."""
    desired = {
        _sec(SecurableType.CATALOG, "cat"),
        _sec(SecurableType.SCHEMA, "cat.sch"),
        _sec(SecurableType.TABLE, "cat.sch.tbl"),
    }
    actual = set(desired)
    change_logger = _change_logger()

    diff = compute_securable_diff(set(), set(), desired, actual, _resolver(), change_logger)

    assert diff.securables_to_create == []
    assert diff.securables_to_replace == []
    assert _nonexistent_errors(change_logger) == []


# ---------------------------------------------------------------------------
# --enable-taggable-creation gating
# ---------------------------------------------------------------------------


def _typed_table(full_name: str, *col_names: str) -> Table:
    """Shorthand: build a Table with typed columns (STRING) for each declared name."""
    return Table(
        securable_type=SecurableType.TABLE,
        full_name=full_name,
        columns=tuple(
            Column(
                securable_type=SecurableType.COLUMN,
                full_name=f"{full_name}.{col_name}",
                data_type="STRING",
            )
            for col_name in col_names
        ),
    )


def test_securable_differ_emits_catalog_schema_volume_in_to_create_when_taggable_creation_enabled():
    """With creation enabled, missing non-function Securables flow into to_create."""
    desired = {
        _sec(SecurableType.CATALOG, "new_cat"),
        _sec(SecurableType.SCHEMA, "new_cat.sch"),
        _sec(SecurableType.VOLUME, "new_cat.sch.vol"),
    }
    change_logger = _change_logger()

    diff = compute_securable_diff(
        set(), set(), desired, set(), _resolver(), change_logger,
        creation_in_scope_catalogs=_ALL_TEST_CATALOGS,
    )

    assert _sec(SecurableType.CATALOG, "new_cat") in diff.securables_to_create
    assert _sec(SecurableType.SCHEMA, "new_cat.sch") in diff.securables_to_create
    assert _sec(SecurableType.VOLUME, "new_cat.sch.vol") in diff.securables_to_create
    assert _nonexistent_errors(change_logger) == []


def test_securable_differ_emits_table_in_to_create_when_columns_valid_and_taggable_creation_enabled():
    """A missing Table with ≥1 typed column flows into to_create, no errors logged."""
    table = _typed_table("cat.sch.orders", "email", "amount")
    change_logger = _change_logger()

    diff = compute_securable_diff(
        set(), set(), {table}, set(), _resolver(), change_logger,
        creation_in_scope_catalogs=_ALL_TEST_CATALOGS,
    )

    assert table in diff.securables_to_create
    assert _nonexistent_errors(change_logger) == []


def test_securable_differ_logs_error_when_table_has_no_columns_and_taggable_creation_enabled():
    """A missing Table with no columns fails validation — logged as a NonexistentSecurableError
    (aggregated later by ExecutionBatchError) and dropped from to_create."""
    empty_table = Table(
        securable_type=SecurableType.TABLE,
        full_name="cat.sch.empty",
        columns=(),
    )
    change_logger = _change_logger()

    diff = compute_securable_diff(
        set(), set(), {empty_table}, set(), _resolver(), change_logger,
        creation_in_scope_catalogs=_ALL_TEST_CATALOGS,
    )

    assert empty_table not in diff.securables_to_create
    errors = _nonexistent_errors(change_logger)
    assert len(errors) == 1
    assert errors[0].securable_type == SecurableType.TABLE
    assert errors[0].full_name == "cat.sch.empty"


def test_securable_differ_logs_error_when_any_column_missing_data_type_and_taggable_creation_enabled():
    """A missing Table with any column lacking a 'data_type' fails validation."""
    table = Table(
        securable_type=SecurableType.TABLE,
        full_name="cat.sch.partly_typed",
        columns=(
            Column(securable_type=SecurableType.COLUMN, full_name="cat.sch.partly_typed.a", data_type="STRING"),
            Column(securable_type=SecurableType.COLUMN, full_name="cat.sch.partly_typed.b", data_type=None),
        ),
    )
    change_logger = _change_logger()

    diff = compute_securable_diff(
        set(), set(), {table}, set(), _resolver(), change_logger,
        creation_in_scope_catalogs=_ALL_TEST_CATALOGS,
    )

    assert table not in diff.securables_to_create
    errors = _nonexistent_errors(change_logger)
    assert len(errors) == 1
    assert errors[0].securable_type == SecurableType.TABLE
    assert errors[0].full_name == "cat.sch.partly_typed"


def test_securable_differ_still_logs_error_when_taggable_creation_disabled():
    """Default behaviour: missing non-function securables are logged (old path)."""
    desired = {_sec(SecurableType.CATALOG, "ghost")}
    change_logger = _change_logger()

    diff = compute_securable_diff(
        set(), set(), desired, set(), _resolver(), change_logger,
    )

    assert diff.securables_to_create == []
    offenders = {(e.securable_type, e.full_name) for e in _nonexistent_errors(change_logger)}
    assert (SecurableType.CATALOG, "ghost") in offenders


def test_securable_differ_does_not_add_table_to_replace_when_desired_columns_differ_from_actual():
    """An existing TABLE on the actual side plus a desired Table with columns must
    not be marked for replacement — only Functions are replaceable. With taggable
    creation enabled and the desired column carrying a data_type, the missing
    column flows into securables_to_create instead."""
    desired_table = _typed_table("cat.sch.orders", "email")
    actual_table = _actual_table("cat.sch.orders")  # exists in UC, has no columns yet
    change_logger = _change_logger()

    diff = compute_securable_diff(
        set(), set(), {desired_table}, {actual_table}, _resolver(), change_logger,
        creation_in_scope_catalogs=_ALL_TEST_CATALOGS,
    )

    assert diff.securables_to_replace == []
    assert _nonexistent_errors(change_logger) == []
    # The missing column flows into securables_to_create as a Column with its data_type.
    assert any(
        isinstance(s, Column) and s.full_name == "cat.sch.orders.email"
        for s in diff.securables_to_create
    )


# ---------------------------------------------------------------------------
# Column-existence validation
# ---------------------------------------------------------------------------


def _actual_table(full_name: str, *col_names: str) -> Table:
    """Shorthand: build an actual-side Table with columns whose data_type is None
    (matches what fetch_actual_securables produces — actual-side never carries types)."""
    return Table(
        securable_type=SecurableType.TABLE,
        full_name=full_name,
        columns=tuple(
            Column(
                securable_type=SecurableType.COLUMN,
                full_name=f"{full_name}.{name}",
                data_type=None,
            )
            for name in col_names
        ),
    )


def test_securable_differ_logs_nonexistent_column_when_missing_and_taggable_creation_disabled():
    """A column declared in config but absent from actual is logged as NonexistentSecurableError(COLUMN)."""
    desired = {_typed_table("cat.sch.orders", "email", "amount")}
    actual = {_actual_table("cat.sch.orders", "amount")}  # 'email' is missing
    change_logger = _change_logger()

    diff = compute_securable_diff(
        set(), set(), desired, actual, _resolver(), change_logger,
    )

    offenders = {(e.securable_type, e.full_name) for e in _nonexistent_errors(change_logger)}
    assert (SecurableType.COLUMN, "cat.sch.orders.email") in offenders
    # No Column emitted when flag is off.
    assert not any(isinstance(s, Column) for s in diff.securables_to_create)


def test_securable_differ_emits_column_to_create_when_missing_and_taggable_creation_enabled_with_data_type():
    """Missing column + flag on + data_type set → Column appears in securables_to_create."""
    desired = {_typed_table("cat.sch.orders", "email")}
    actual = {_actual_table("cat.sch.orders")}  # no columns yet
    change_logger = _change_logger()

    diff = compute_securable_diff(
        set(), set(), desired, actual, _resolver(), change_logger,
        creation_in_scope_catalogs=_ALL_TEST_CATALOGS,
    )

    column_entries = [s for s in diff.securables_to_create if isinstance(s, Column)]
    assert len(column_entries) == 1
    assert column_entries[0].full_name == "cat.sch.orders.email"
    assert column_entries[0].data_type == "STRING"
    assert _nonexistent_errors(change_logger) == []


def test_securable_differ_logs_nonexistent_column_with_hint_when_taggable_creation_enabled_but_data_type_missing():
    """Missing column + flag on + data_type missing → NonexistentSecurableError logged with hint."""
    desired_table = Table(
        securable_type=SecurableType.TABLE,
        full_name="cat.sch.orders",
        columns=(
            Column(
                securable_type=SecurableType.COLUMN,
                full_name="cat.sch.orders.email",
                data_type=None,
            ),
        ),
    )
    actual = {_actual_table("cat.sch.orders")}
    change_logger = _change_logger()

    compute_securable_diff(
        set(), set(), {desired_table}, actual, _resolver(), change_logger,
        creation_in_scope_catalogs=_ALL_TEST_CATALOGS,
    )

    errors = _nonexistent_errors(change_logger)
    column_errors = [e for e in errors if e.securable_type == SecurableType.COLUMN]
    assert len(column_errors) == 1
    assert column_errors[0].full_name == "cat.sch.orders.email"
    assert column_errors[0].hint is not None
    assert "type" in column_errors[0].hint.lower()


def test_securable_differ_does_not_emit_column_when_already_present_in_actual():
    """A column declared in both desired and actual produces no diff entry."""
    desired = {_typed_table("cat.sch.orders", "email")}
    actual = {_actual_table("cat.sch.orders", "email")}
    change_logger = _change_logger()

    diff = compute_securable_diff(
        set(), set(), desired, actual, _resolver(), change_logger,
        creation_in_scope_catalogs=_ALL_TEST_CATALOGS,
    )

    assert not any(isinstance(s, Column) for s in diff.securables_to_create)
    assert _nonexistent_errors(change_logger) == []


def test_securable_differ_ignores_columns_present_only_in_actual():
    """Columns present in UC but not declared in config are left alone (additive only)."""
    desired = {_typed_table("cat.sch.orders", "email")}
    actual = {_actual_table("cat.sch.orders", "email", "legacy_field")}
    change_logger = _change_logger()

    diff = compute_securable_diff(
        set(), set(), desired, actual, _resolver(), change_logger,
        creation_in_scope_catalogs=_ALL_TEST_CATALOGS,
    )

    assert not any(isinstance(s, Column) for s in diff.securables_to_create)
    assert _nonexistent_errors(change_logger) == []


def test_securable_differ_skips_column_check_for_table_being_created():
    """When the table itself is in to_create (also missing from actual), the table's
    columns are not separately added — they'll be created via CREATE TABLE."""
    desired = {_typed_table("cat.sch.new_orders", "email", "amount")}
    actual: set[Securable] = set()  # neither table nor columns exist
    change_logger = _change_logger()

    diff = compute_securable_diff(
        set(), set(), desired, actual, _resolver(), change_logger,
        creation_in_scope_catalogs=_ALL_TEST_CATALOGS,
    )

    # Only the Table is in to_create — no separate Column entries.
    assert not any(isinstance(s, Column) for s in diff.securables_to_create)
    table_entries = [s for s in diff.securables_to_create if isinstance(s, Table)]
    assert len(table_entries) == 1
    # The table carries its columns inside (Table.columns) — that's how CREATE TABLE works.
    assert len(table_entries[0].columns) == 2


# ---------------------------------------------------------------------------
# NonexistentSecurableError message
# ---------------------------------------------------------------------------


def test_nonexistent_securable_error_message_recommends_enable_taggable_creation_flag():
    """Without a hint (flag off → existence check), the message tells the user to set
    --enable-taggable-creation rather than asking them to create the object manually."""
    desired = {_sec(SecurableType.CATALOG, "ghost_catalog")}
    change_logger = _change_logger()

    compute_securable_diff(set(), set(), desired, set(), _resolver(), change_logger)

    err = next(
        e.exception for e in change_logger.errors
        if isinstance(e.exception, NonexistentSecurableError)
    )
    msg = str(err)
    assert "--enable-taggable-creation" in msg
    # The old phrasing should be gone.
    assert "Either create it in UC" not in msg


def test_nonexistent_securable_error_uses_hint_when_provided_instead_of_flag_boilerplate():
    """When a hint is given (flag on but validation failed), the message uses the hint
    and does NOT also tell the user to set the flag (they already have it on)."""
    table = Table(
        securable_type=SecurableType.TABLE,
        full_name="cat.sch.empty",
        columns=(),  # no columns → blocker
    )
    change_logger = _change_logger()

    compute_securable_diff(
        set(), set(), {table}, set(), _resolver(), change_logger,
        creation_in_scope_catalogs=_ALL_TEST_CATALOGS,
    )

    err = next(
        e.exception for e in change_logger.errors
        if isinstance(e.exception, NonexistentSecurableError)
    )
    msg = str(err)
    # The hint is surfaced.
    assert "Configure at least one column" in msg
    # The flag-boilerplate should NOT appear when a hint is present.
    assert "--enable-taggable-creation" not in msg
