from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_declarative_abac.logger import ChangeLogger
    from uc_declarative_abac.principals.resolver import PrincipalResolver

from uc_declarative_abac.securables.state import (
    AttributeUpdate,
    Column,
    Function,
    SecurableAttributes,
    SecurableDiff,
    Securable,
    Table,
)
from uc_declarative_abac.types import SecurableType
from uc_declarative_abac.utils import ExecutionError, NonexistentSecurableError, OrchestratorError, PrincipalValidationError, catalog_of

_GOVERNED_ATTRIBUTES = ["owner", "comment", "rfa_destinations"]


def _to_frozenset(attr: str, value: object) -> frozenset:
    """Wrap a SecurableAttributes field value into a frozenset for diff comparison.

    Scalar fields (``owner``, ``comment``) become a 1-element frozenset, or
    an empty frozenset when the value is missing / empty. Collection fields
    (``rfa_destinations``) pass through as the natural frozenset (``None`` →
    empty). This keeps the diff loop attribute-agnostic and lets the executor
    take a uniform set-shaped value.
    """
    if attr == "rfa_destinations":
        return value if value is not None else frozenset()
    if value is None or value == "":
        return frozenset()
    return frozenset({value})

# ``information_schema.tables.table_type`` values that don't support ``COMMENT ON TABLE …``
# / ``ALTER TABLE … SET COMMENT`` via the path this engine uses. Today only regular VIEWs are
# affected.
_COMMENT_IMMUTABLE_TABLE_TYPES = frozenset({"VIEW", "METRIC_VIEW"})

# ``information_schema.tables.table_type`` values that don't support ``ALTER TABLE … OWNER TO``
# via the SDK paths this engine uses. Regular VIEW *does* support owner changes via
# ``ALTER VIEW … OWNER TO`` and is intentionally excluded.
_OWNER_IMMUTABLE_TABLE_TYPES = frozenset({"MATERIALIZED_VIEW", "STREAMING_TABLE"})


def compute_securable_diff(
    desired_attrs: set[SecurableAttributes],
    actual_attrs: set[SecurableAttributes],
    desired_securables: set[Securable],
    actual_securables: set[Securable],
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
    creation_in_scope_catalogs: frozenset[str] = frozenset(),
) -> SecurableDiff:
    """Compute the diff between desired and actual securable state.

    Resolves owner Principals on both sides before diffing. Owner-resolution
    failures are logged via change_logger and clear the owner field on the
    affected row (the SecurableAttributes itself is retained so the securable's
    create/replace info isn't lost).

    Non-function securables declared in config but absent from UC are created
    only if their catalog is in ``creation_in_scope_catalogs``; out-of-scope
    catalogs (and the all-empty set, which is the default and means "creation
    disabled for everything") log ``NonexistentSecurableError`` and are dropped
    from ``securables_to_create``. Functions are always engine-managed and flow
    through regardless of scope. Tables require ≥1 column and every column must
    have a non-None ``type``. In-scope tables that fail this check are logged
    as errors (with a hint explaining the requirement) and dropped, surfacing
    later via ``ExecutionBatchError``.
    """
    desired_attrs = _resolve_attribute_owners(desired_attrs, resolver, change_logger)
    actual_attrs = _resolve_attribute_owners(actual_attrs, resolver, change_logger)

    securables_to_create, securables_to_replace = _diff_securables(
        desired_securables, actual_securables
    )
    creatable, blocked = _partition_by_creation_scope(
        securables_to_create, creation_in_scope_catalogs,
    )
    creatable = _validate_tables_for_creation(creatable, change_logger)
    _log_nonexistent_non_function_securables(blocked, change_logger)
    securables_to_create = creatable

    table_full_names_being_created = {
        s.full_name for s in securables_to_create
        if s.securable_type == SecurableType.TABLE
    }
    columns_to_create = _diff_table_columns(
        desired_securables, actual_securables,
        table_full_names_being_created, change_logger, creation_in_scope_catalogs,
    )
    securables_to_create.extend(columns_to_create)

    created_full_names = {s.full_name for s in securables_to_create}

    view_full_names = {
        s.full_name for s in actual_securables
        if isinstance(s, Table) and s.table_type in _COMMENT_IMMUTABLE_TABLE_TYPES
    }
    owner_immutable_full_names = {
        s.full_name for s in actual_securables
        if isinstance(s, Table) and s.table_type in _OWNER_IMMUTABLE_TABLE_TYPES
    }

    attributes_to_update = _diff_attributes(
        desired_attrs, actual_attrs, created_full_names,
        view_full_names=view_full_names,
        owner_immutable_full_names=owner_immutable_full_names,
        change_logger=change_logger,
    )

    return SecurableDiff(
        attributes_to_update=attributes_to_update,
        securables_to_create=securables_to_create,
        securables_to_replace=securables_to_replace,
    )


def _resolve_attribute_owners(
    unresolved: set[SecurableAttributes],
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
) -> set[SecurableAttributes]:
    """Resolve owner Principals on a set of SecurableAttributes.

    On failure, clears the owner field but retains the SecurableAttributes —
    dropping it would lose the securable's create/replace info.

    Uses ``dataclasses.replace`` so every non-owner field (``comment``,
    ``rfa_destinations``, …) on the input survives owner resolution.
    Reconstructing from scratch here silently dropped those fields and broke
    idempotency for every managed attribute other than ``owner`` itself.
    """
    result: set[SecurableAttributes] = set()
    for attr in unresolved:
        if attr.owner is None:
            result.add(attr)
            continue
        try:
            resolved_owner = resolver.resolve_principal(attr.owner)
        except PrincipalValidationError as exc:
            change_logger.log_error(ExecutionError(
                context=f"Resolve owner for {attr.securable_type.value} {attr.full_name}",
                exception=exc,
            ))
            result.add(dataclasses.replace(attr, owner=None))
            continue
        result.add(dataclasses.replace(attr, owner=resolved_owner))
    return result


def _diff_securables(
    desired: set[Securable],
    actual: set[Securable],
) -> tuple[list[Securable], list[Securable]]:
    """Return (to_create, to_replace) lists by keying on (securable_type, full_name).

    Replacement is function-only: tables, volumes, catalogs, and schemas don't support
    in-place redefinition today, and a Table with declared columns can't be meaningfully
    compared to a base ``Securable`` fetched from UC (which lacks column info). Only
    ``Function`` enters ``to_replace`` when its definition or parameters change.
    """
    actual_by_key = {(s.securable_type, s.full_name): s for s in actual}

    to_create: list[Securable] = []
    to_replace: list[Securable] = []

    for desired_sec in desired:
        actual_sec = actual_by_key.get((desired_sec.securable_type, desired_sec.full_name))
        if actual_sec is None:
            to_create.append(desired_sec)
        elif isinstance(desired_sec, Function) and desired_sec != actual_sec:
            to_replace.append(desired_sec)

    return to_create, to_replace


def _table_creation_blocker(table: Table) -> str | None:
    """Return a reason string if ``table`` cannot be validly created, else None.

    A creatable Table must have at least one column and every column must declare
    its UC datatype via the ``data_type`` field.
    """
    if not table.columns:
        return "Configure at least one column with a 'type' to enable table creation."
    untyped = [c.full_name for c in table.columns if not c.data_type]
    if untyped:
        return (
            f"Column(s) {', '.join(repr(n) for n in untyped)} declared without a 'type' — "
            "every column must specify its UC datatype to enable table creation."
        )
    return None


def _column_creation_blocker(column: Column) -> str | None:
    """Return a reason string if ``column`` cannot be validly created via
    ALTER TABLE ADD COLUMN, else None. A creatable column must declare its
    UC datatype via the ``data_type`` field — ALTER TABLE syntax requires it."""
    if not column.data_type:
        return "Declare a 'type' on the column to enable creation."
    return None


def _diff_table_columns(
    desired: set[Securable],
    actual: set[Securable],
    table_full_names_being_created: set[str],
    change_logger: ChangeLogger,
    creation_in_scope_catalogs: frozenset[str],
) -> list[Column]:
    """For each desired Table that already exists in UC (i.e. NOT being created
    this run), compare its declared columns against the columns fetched from UC
    and return any columns that should be added via ALTER TABLE ADD COLUMN.

    Logs ``NonexistentSecurableError(COLUMN, ...)`` for missing columns that
    can't be created (catalog out of creation scope, or in scope but column
    lacks ``data_type``). Columns present in actual but absent from desired
    are ignored — additive only.
    """
    actual_tables_by_name = {
        s.full_name: s for s in actual
        if isinstance(s, Table)
    }

    columns_to_create: list[Column] = []
    for desired_sec in desired:
        if not isinstance(desired_sec, Table):
            continue
        if desired_sec.full_name in table_full_names_being_created:
            continue  # the CREATE TABLE path handles its columns
        actual_table = actual_tables_by_name.get(desired_sec.full_name)
        if actual_table is None:
            continue  # missing-table error is handled separately
        actual_column_names = {c.full_name for c in actual_table.columns}

        for col in desired_sec.columns:
            if col.full_name in actual_column_names:
                continue  # already exists in UC

            if catalog_of(col.full_name) in creation_in_scope_catalogs:
                blocker = _column_creation_blocker(col)
                if blocker is None:
                    columns_to_create.append(col)
                    continue
                change_logger.log_error(ExecutionError(
                    context=f"Validate ADD COLUMN {col.full_name}",
                    exception=NonexistentSecurableError(
                        SecurableType.COLUMN, col.full_name, hint=blocker,
                    ),
                ))
            else:
                change_logger.log_error(ExecutionError(
                    context=f"Existence check: COLUMN {col.full_name}",
                    exception=NonexistentSecurableError(
                        SecurableType.COLUMN, col.full_name,
                    ),
                ))

    return columns_to_create


def _partition_by_creation_scope(
    to_create: list[Securable],
    in_scope_catalogs: frozenset[str],
) -> tuple[list[Securable], list[Securable]]:
    """Split ``to_create`` into (creatable, blocked).

    Functions are always creatable — they're engine-managed and exempt from
    the catalog-scope gate. Other securables (catalogs, schemas, tables,
    volumes) are creatable only if their catalog is in ``in_scope_catalogs``.
    """
    creatable: list[Securable] = []
    blocked: list[Securable] = []
    for sec in to_create:
        if isinstance(sec, Function):
            creatable.append(sec)
        elif catalog_of(sec.full_name) in in_scope_catalogs:
            creatable.append(sec)
        else:
            blocked.append(sec)
    return creatable, blocked


def _validate_tables_for_creation(
    to_create: list[Securable],
    change_logger: ChangeLogger,
) -> list[Securable]:
    """Validate each Table in ``to_create`` and log errors for invalid ones.

    Non-Table securables pass through unchanged — with ``--enable-taggable-creation``
    on, catalogs, schemas, volumes, and valid tables all flow to the executor.
    Tables missing columns or column types are logged as ``NonexistentSecurableError``
    (with a hint explaining the requirement) so the orchestrator's end-of-run
    ``ExecutionBatchError`` gate picks them up alongside any other errors.
    """
    kept: list[Securable] = []
    for sec in to_create:
        if isinstance(sec, Table):
            reason = _table_creation_blocker(sec)
            if reason is not None:
                change_logger.log_error(ExecutionError(
                    context=f"Validate CREATE TABLE {sec.full_name}",
                    exception=NonexistentSecurableError(
                        sec.securable_type, sec.full_name, hint=reason,
                    ),
                ))
                continue
        kept.append(sec)
    return kept


def _log_nonexistent_non_function_securables(
    to_create: list[Securable],
    change_logger: ChangeLogger,
) -> list[Securable]:
    """Log one ``NonexistentSecurableError`` per non-function securable in ``to_create``
    and return the list filtered down to Functions only.

    Functions are engine-created, so they legitimately flow through ``to_create`` for
    the executor to ``CREATE FUNCTION``. Any other type in ``to_create`` means the
    config references a UC object that does not yet exist; the engine does not
    support creating those today. We log each offender via ``ChangeLogger.log_error``
    (so the orchestrator's final ``ExecutionBatchError`` gate surfaces them alongside
    any other accumulated errors) and drop them from the diff to prevent downstream
    executors from attempting to touch them.
    """
    nonexistent = sorted(
        [s for s in to_create if not isinstance(s, Function)],
        key=lambda s: (s.securable_type.value, s.full_name),
    )
    for sec in nonexistent:
        change_logger.log_error(ExecutionError(
            context=f"Existence check: {sec.securable_type.value} {sec.full_name}",
            exception=NonexistentSecurableError(sec.securable_type, sec.full_name),
        ))
    return [s for s in to_create if isinstance(s, Function)]


def _diff_attributes(
    desired_attrs: set[SecurableAttributes],
    actual_attrs: set[SecurableAttributes],
    created_full_names: set[str],
    view_full_names: set[str],
    owner_immutable_full_names: set[str],
    change_logger: ChangeLogger,
) -> list[AttributeUpdate]:
    """Return attribute updates by comparing desired vs actual attributes.

    Per-attribute rules:

    - ``owner`` — emitted as an SDK update even for newly-created securables
      (UC CREATE does not accept an owner). Refused for tables whose
      ``table_type`` is ``MATERIALIZED_VIEW`` or ``STREAMING_TABLE`` (the SDK
      ``tables.update(owner=...)`` path does not support them); logged as an
      ``ExecutionError`` and dropped.
    - ``comment`` — skipped for newly-created securables because the executor
      embeds the comment in the CREATE statement. For existing securables,
      comment on a view (``Table.table_type`` in ``_COMMENT_IMMUTABLE_TABLE_TYPES``)
      is refused — UC doesn't support ``COMMENT ON`` for views via this path;
      logged as an ``ExecutionError`` and dropped. Comments on other types flow
      through as ALTER updates.

    ``location`` is creation-only (see ``compile_desired_securables``) and is
    not in ``_GOVERNED_ATTRIBUTES`` — it's never diffed.

    For resolved Principals, equality uses dataclass field equality — two
    resolved principals with the same identifier + name + type compare equal.

    Desired-only attributes are skipped unless the securable is being created.
    """
    actual_by_key = {
        (a.securable_type, a.full_name): a for a in actual_attrs
    }

    updates: list[AttributeUpdate] = []

    for desired in desired_attrs:
        key = (desired.securable_type, desired.full_name)
        actual = actual_by_key.get(key)

        if actual is None and desired.full_name not in created_full_names:
            continue

        is_being_created = desired.full_name in created_full_names

        for attr in _GOVERNED_ATTRIBUTES:
            desired_raw = getattr(desired, attr)
            if desired_raw is None:
                continue

            actual_raw = getattr(actual, attr, None) if actual is not None else None
            new_value = _to_frozenset(attr, desired_raw)
            old_value = _to_frozenset(attr, actual_raw)
            if old_value == new_value:
                continue

            update = AttributeUpdate(
                securable_type=desired.securable_type,
                full_name=desired.full_name,
                attribute=attr,
                old_value=old_value,
                new_value=new_value,
            )

            if _should_skip_or_log(
                update, is_being_created,
                view_full_names, owner_immutable_full_names, change_logger,
            ):
                continue
            updates.append(update)

    return updates


def _should_skip_or_log(
    update: AttributeUpdate,
    is_being_created: bool,
    view_full_names: set[str],
    owner_immutable_full_names: set[str],
    change_logger: ChangeLogger,
) -> bool:
    """Return True if the update should be dropped (skipped silently or after logging).

    ``comment`` updates on a securable that's being created this run are dropped
    silently — the CREATE statement embeds the comment. For existing securables,
    the view-comment and immutable-owner rules log an error before dropping.
    """
    if is_being_created and update.attribute == "comment":
        return True

    if update.attribute == "comment" and update.full_name in view_full_names:
        change_logger.log_error(ExecutionError(
            context=f"Update comment on {update.securable_type.value} {update.full_name}",
            exception=OrchestratorError(
                "Cannot alter comment on a VIEW — only the view owner can alter comment."
            ),
        ))
        return True

    if update.attribute == "owner" and update.full_name in owner_immutable_full_names:
        change_logger.log_error(ExecutionError(
            context=f"Update owner on {update.securable_type.value} {update.full_name}",
            exception=OrchestratorError(
                "Materialized views and streaming tables do not support owner "
                "changes via this engine. Change ownership of the pipeline instead."
            ),
        ))
        return True

    return False
