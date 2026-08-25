from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_declarative_abac.helpers import UnityCatalogHelper
    from uc_declarative_abac.logger import ChangeLogger

from uc_declarative_abac.principals import (
    Principal,
    ensure_resolved,
)
from uc_declarative_abac.securables.state import (
    AttributeUpdate,
    Column,
    Function,
    Securable,
    SecurableDiff,
    Table,
)
from uc_declarative_abac.types import SecurableType
from uc_declarative_abac.utils import (
    ExecutionError,
    OrchestratorError,
    parallel_for_each,
    quote_securable,
)

# UC hierarchy depth: catalogs at the top, then schemas, then leaf types
# (tables/volumes/functions), then columns. This topology drives execution
# ordering both for creates (a parent must exist before its children) and for
# attribute updates (the engine may need to take ownership of a parent before
# it can alter children — see _bucket_attribute_updates).
_SECURABLE_DEPTH: dict[SecurableType, int] = {
    SecurableType.CATALOG: 0,
    SecurableType.SCHEMA: 1,
    SecurableType.TABLE: 2,
    SecurableType.VOLUME: 2,
    SecurableType.FUNCTION: 2,
    SecurableType.COLUMN: 3,
}

# ``information_schema.tables.table_type`` values that don't support
# ``ALTER TABLE … ALTER COLUMN … COMMENT``. Column comments on these are applied
# one-per-column via ``COMMENT ON COLUMN`` instead of a single batched ALTER.
_ALTER_COLUMN_UNSUPPORTED_TABLE_TYPES = frozenset(
    {"VIEW", "METRIC_VIEW", "MATERIALIZED_VIEW", "STREAMING_TABLE"}
)


def _escape_sql_string_literal(value: str) -> str:
    """Escape single quotes for embedding in a SQL string literal."""
    return value.replace("'", "\\'").replace('"', '\\"')


def _build_comment_clause(comment: str | None) -> str:
    """Return a `` COMMENT '<escaped>''`` suffix, or empty string if no comment."""
    if not comment:
        return ""
    return f' COMMENT "{_escape_sql_string_literal(comment)}"'


def _build_managed_location_clause(location: str | None) -> str:
    """Return a `` MANAGED LOCATION '<escaped>''`` suffix for catalogs/schemas, or empty string."""
    if not location:
        return ""
    return f" MANAGED LOCATION '{_escape_sql_string_literal(location)}'"


def _build_external_location_clause(location: str | None) -> str:
    """Return a `` LOCATION '<escaped>''`` suffix for tables/volumes, or empty string."""
    if not location:
        return ""
    return f" LOCATION '{_escape_sql_string_literal(location)}'"


def _creation_sort_key(info: Securable) -> tuple[int, str]:
    """Sort creates parent-first (by depth), then alphabetically by full_name.

    Columns are an exception: they share a key with every other column on the
    same parent table so that Python's stable sort preserves their input-list
    order (which traces back to the user's YAML declaration order). Sorting
    columns by their own full_name would silently re-order them alphabetically.
    """
    depth = _SECURABLE_DEPTH.get(info.securable_type, 99)
    if isinstance(info, Column):
        parent_full_name, _, _ = info.full_name.rpartition(".")
        return (depth, parent_full_name)
    return (depth, info.full_name)


def _build_create_sql(info: Securable) -> str:
    """Build a CREATE SQL statement for a securable."""
    match info:
        case Function():
            return _build_create_function_sql(info)
        case Table():
            return _build_create_table_sql(info)
        case Securable(securable_type=SecurableType.CATALOG):
            return _build_create_catalog_sql(info)
        case Securable(securable_type=SecurableType.SCHEMA):
            return _build_create_schema_sql(info)
        case Securable(securable_type=SecurableType.VOLUME):
            return _build_create_volume_sql(info)
        case _:
            raise NotImplementedError(f"Create not supported for {type(info).__name__}")


def _build_create_catalog_sql(info: Securable) -> str:
    """``CREATE CATALOG IF NOT EXISTS <name> [MANAGED LOCATION '...'] [COMMENT '...']``.

    When ``info.location`` is set it becomes the catalog's managed location.
    """
    return (
        f"CREATE CATALOG IF NOT EXISTS {quote_securable(info.full_name)}"
        f"{_build_managed_location_clause(info.location)}"
        f"{_build_comment_clause(info.comment)}"
    )


def _build_create_schema_sql(info: Securable) -> str:
    """``CREATE SCHEMA IF NOT EXISTS <catalog>.<schema> [MANAGED LOCATION '...'] [COMMENT '...']``.

    When ``info.location`` is set it becomes the schema's managed location.
    """
    return (
        f"CREATE SCHEMA IF NOT EXISTS {quote_securable(info.full_name)}"
        f"{_build_managed_location_clause(info.location)}"
        f"{_build_comment_clause(info.comment)}"
    )


def _build_create_volume_sql(info: Securable) -> str:
    """Build a CREATE VOLUME SQL statement.

    With no ``info.location``: ``CREATE VOLUME IF NOT EXISTS <full_name>`` (managed).
    With a location: ``CREATE EXTERNAL VOLUME IF NOT EXISTS <full_name> LOCATION '...'``.
    Optional ``COMMENT '...'`` suffix when ``info.comment`` is set.
    """
    if info.location:
        head = f"CREATE EXTERNAL VOLUME IF NOT EXISTS {quote_securable(info.full_name)}"
    else:
        head = f"CREATE VOLUME IF NOT EXISTS {quote_securable(info.full_name)}"
    return (
        f"{head}"
        f"{_build_external_location_clause(info.location)}"
        f"{_build_comment_clause(info.comment)}"
    )


def _build_create_table_sql(info: Table) -> str:
    """``CREATE TABLE IF NOT EXISTS <full_name> (col1 TYPE, ...) [COMMENT '...'] [LOCATION '...']``.

    When ``info.location`` is set, the LOCATION clause makes this an external table.
    The differ has already validated that every column has a non-None ``type`` before
    a Table reaches this builder, so it's safe to assume types are present.
    """
    column_defs = ", ".join(
        f"`{c.full_name.rsplit('.', 1)[-1]}` {c.data_type}{_build_comment_clause(c.comment)}"
        for c in info.columns
    )
    return (
        f"CREATE TABLE IF NOT EXISTS {quote_securable(info.full_name)} ({column_defs})"
        f"{_build_comment_clause(info.comment)}"
        f"{_build_external_location_clause(info.location)}"
    )


def _group_columns_by_parent(columns: list[Column]) -> list[tuple[str, list[Column]]]:
    """Group columns by parent table FQN, preserving the input list's order
    both for parent-group ordering and for column order within a group.

    The caller relies on this stable ordering: parents appear in the order
    their first column was seen; within each parent, columns appear in
    declaration order.
    """
    groups: dict[str, list[Column]] = {}
    for col in columns:
        parent, _, _ = col.full_name.rpartition(".")
        groups.setdefault(parent, []).append(col)
    return list(groups.items())


def _build_alter_table_add_columns_sql(
    parent_full_name: str, columns: list[Column]
) -> str:
    """``ALTER TABLE <parent> ADD COLUMNS (`c1` T1, `c2` T2, ...)`` — adds one or
    more columns to an existing table in a single atomic Delta commit. Batching
    eliminates ``DELTA_METADATA_CHANGED`` conflicts between concurrent ADD
    COLUMN operations on the same table. The differ has already validated that
    every column's ``data_type`` is set before they reach this builder."""
    column_defs = ", ".join(
        f"`{c.full_name.rpartition('.')[-1]}` {c.data_type}{_build_comment_clause(c.comment)}"
        for c in columns
    )
    return (
        f"ALTER TABLE {quote_securable(parent_full_name)} ADD COLUMNS ({column_defs})"
    )


def _build_replace_sql(info: Securable) -> str:
    """Build a CREATE OR REPLACE SQL statement for a securable."""
    match info:
        case Function():
            return _build_replace_function_sql(info)
        case _:
            raise NotImplementedError(
                f"Replace not supported for {type(info).__name__}"
            )


def _build_function_params(parameters: tuple[tuple[str, str], ...]) -> str:
    """Format function parameters as a parenthesised list."""
    if not parameters:
        return "()"
    entries = ", ".join(f"{name} {data_type}" for name, data_type in parameters)
    return f"({entries})"


def _build_function_comment_clause(comment: str | None) -> str:
    """Return a ' COMMENT '<escaped>'' suffix, or empty string if no comment.

    Function comments share the same escape rule as the other COMMENT clauses;
    they kept a dedicated builder for naming clarity at the CREATE/REPLACE
    FUNCTION call sites.
    """
    return _build_comment_clause(comment)


def _build_create_function_sql(info: Function) -> str:
    """Build CREATE FUNCTION SQL."""
    quoted = quote_securable(info.full_name)
    params = _build_function_params(info.parameters)
    comment = _build_function_comment_clause(info.comment)
    return f"CREATE FUNCTION {quoted}{params}{comment} RETURN {info.definition}"


def _build_replace_function_sql(info: Function) -> str:
    """Build CREATE OR REPLACE FUNCTION SQL."""
    quoted = quote_securable(info.full_name)
    params = _build_function_params(info.parameters)
    comment = _build_function_comment_clause(info.comment)
    return (
        f"CREATE OR REPLACE FUNCTION {quoted}{params}{comment} RETURN {info.definition}"
    )


def _build_comment_update_sql(
    securable_type: SecurableType, full_name: str, comment: str
) -> str:
    """Build a ``COMMENT ON <type> <name> IS "..."`` statement to set a securable's comment.

    Covers catalog/schema/table/volume, and columns (``COMMENT ON COLUMN`` — used for
    columns on views / materialized views / streaming tables, which don't support
    ``ALTER TABLE … ALTER COLUMN``). Functions carry their comment in the replaceable
    definition, so a comment update is never issued for them. The differ has already
    guarded against comment changes on views (table-level).
    """
    quoted = quote_securable(full_name)
    escaped = _escape_sql_string_literal(comment)
    if securable_type == SecurableType.FUNCTION:
        raise OrchestratorError(
            f"Comment updates not supported for {securable_type.value}."
        )
    return f'COMMENT ON {securable_type.name} {quoted} IS "{escaped}"'


def _column_comment_value(update: AttributeUpdate) -> str:
    """Unwrap the single desired comment string from a column comment update."""
    return str(next(iter(update.new_value)))


def _column_parent_table(update: AttributeUpdate) -> str:
    """Return the parent-table full name of a column-scoped update."""
    return update.full_name.rpartition(".")[0]


def _build_alter_table_column_comments_sql(
    parent_full_name: str, updates: list[AttributeUpdate]
) -> str:
    """Build one batched ``ALTER TABLE … ALTER COLUMN`` for a table's column comments.

    The ``ALTER COLUMN`` keyword appears once, followed by comma-separated
    ``<col> COMMENT "<escaped>"`` pairs — one statement per table rather than one per
    column. Used for base tables (types that support ``ALTER TABLE … ALTER COLUMN``).
    """
    clauses = ", ".join(
        f"`{u.full_name.rpartition('.')[-1]}` "
        f'COMMENT "{_escape_sql_string_literal(_column_comment_value(u))}"'
        for u in updates
    )
    return f"ALTER TABLE {quote_securable(parent_full_name)} ALTER COLUMN {clauses}"


def _group_comment_updates_by_parent(
    updates: list[AttributeUpdate],
) -> list[tuple[str, list[AttributeUpdate]]]:
    """Group column comment updates by parent table, preserving input order."""
    groups: dict[str, list[AttributeUpdate]] = {}
    for update in updates:
        groups.setdefault(_column_parent_table(update), []).append(update)
    return list(groups.items())


def _apply_owner_update(uc_helper: UnityCatalogHelper, update: AttributeUpdate) -> None:
    """Apply an owner change via the SDK ``update_owner`` dispatch.

    ``update.new_value`` is a single-element ``frozenset[Principal]``; we
    unwrap it here at the SDK boundary.
    """
    principal = next(iter(update.new_value))
    if isinstance(principal, Principal):
        owner_id = ensure_resolved(principal).identifier
    else:
        owner_id = principal
    uc_helper.update_owner(update.securable_type, update.full_name, owner_id)


def _attribute_update_context(update: AttributeUpdate, stmt: str | None) -> str:
    """Compose the ExecutionError ``context`` for a failed attribute update."""
    if stmt is not None:
        return stmt
    if update.attribute == "owner":
        return f"update_owner({update.securable_type.value}, {update.full_name})"
    if update.attribute == "rfa_destinations":
        return (
            f"update_rfa_destinations("
            f"{update.securable_type.value}, {update.full_name})"
        )
    return (
        f"Unknown attribute {update.attribute!r} on "
        f"{update.securable_type.value} {update.full_name}"
    )


def _run_attribute_update(
    uc_helper: UnityCatalogHelper,
    update: AttributeUpdate,
    stmt: str | None,
    dry_run: bool,
) -> None:
    """Worker: perform the SQL/SDK call for one AttributeUpdate.

    ``stmt`` is pre-built for the comment branch (so we can reference it in
    post-batch error logging); ``None`` for SDK-driven branches.
    """
    if dry_run:
        return
    if stmt is not None:
        uc_helper.execute_sql(stmt)
        return
    match update.attribute:
        case "owner":
            _apply_owner_update(uc_helper, update)
        case "rfa_destinations":
            uc_helper.update_rfa_destinations(
                update.securable_type,
                update.full_name,
                update.new_value,
            )
        case _:
            raise OrchestratorError(
                f"No executor branch for attribute {update.attribute!r}"
            )


def _bucket_creates_by_depth(diff: SecurableDiff) -> dict[int, list[Securable]]:
    """Bucket creates by depth, preserving the original (depth, sort_key) total order within each bucket."""
    by_depth: dict[int, list[Securable]] = defaultdict(list)
    for info in diff.securables_to_create:
        depth, _ = _creation_sort_key(info)
        by_depth[depth].append(info)
    for bucket in by_depth.values():
        bucket.sort(key=_creation_sort_key)
    return by_depth


def _run_column_create_batch(
    uc_helper: UnityCatalogHelper,
    columns: list[Column],
    change_logger: ChangeLogger,
    dry_run: bool,
    max_workers: int,
) -> list[str]:
    """Execute column adds as one ALTER per parent table, in parallel across tables.

    Same-table ADD COLUMNs cannot run concurrently against Delta (every commit
    bumps the table's metadata version, so two parallel ADDs collide with
    ``DELTA_METADATA_CHANGED``). This batches every column destined for the
    same parent into a single ALTER, preserving the operator's per-column log
    granularity while eliminating the conflict.
    """
    groups = _group_columns_by_parent(columns)
    work_items: list[tuple[str, list[Column], str]] = [
        (parent, cols, _build_alter_table_add_columns_sql(parent, cols))
        for parent, cols in groups
    ]

    def worker(item: tuple[str, list[Column], str]) -> None:
        _parent, _cols, stmt = item
        if not dry_run:
            uc_helper.execute_sql(stmt)

    def on_complete(item: tuple[str, list[Column], str], _result, error) -> None:
        _parent, cols, stmt = item
        if error is not None:
            change_logger.log_error(ExecutionError(context=stmt, exception=error))
            return
        for col in cols:
            change_logger.log_securable_create(col)

    results = parallel_for_each(
        work_items,
        worker,
        max_workers=max_workers,
        on_complete=on_complete,
    )
    if dry_run:
        return []
    return [stmt for (_p, _c, stmt), _r, error in results if error is None]


def _build_column_comment_work_items(
    updates: list[AttributeUpdate], fallback_tables: frozenset[str]
) -> list[tuple[list[AttributeUpdate], str]]:
    """Build ``(updates, sql)`` work items covering every column comment update.

    Base-table columns (types that support ``ALTER TABLE … ALTER COLUMN``) are grouped
    into one batched ALTER per parent table; columns on ``fallback_tables`` (views,
    metric/materialized views, streaming tables) get one ``COMMENT ON COLUMN`` each. Each
    item carries the update(s) it covers so the executor logs every column, even for a
    batched ALTER. Base items precede fallback items so the returned statement order is
    stable.
    """
    base = [u for u in updates if _column_parent_table(u) not in fallback_tables]
    fallback = [u for u in updates if _column_parent_table(u) in fallback_tables]

    items: list[tuple[list[AttributeUpdate], str]] = [
        (ups, _build_alter_table_column_comments_sql(parent, ups))
        for parent, ups in _group_comment_updates_by_parent(base)
    ]
    items.extend(
        (
            [update],
            _build_comment_update_sql(
                update.securable_type,
                update.full_name,
                _column_comment_value(update),
            ),
        )
        for update in fallback
    )
    return items


def _run_column_comment_batch(
    uc_helper: UnityCatalogHelper,
    updates: list[AttributeUpdate],
    fallback_tables: frozenset[str],
    change_logger: ChangeLogger,
    dry_run: bool,
    max_workers: int,
) -> list[str]:
    """Apply all column comment updates in a single parallel batch (width ``max_workers``).

    Base-table comments batch into one ``ALTER TABLE … ALTER COLUMN`` per table;
    view-family comments use ``COMMENT ON COLUMN`` per column. Both kinds run together in
    one thread pool — there is no sequential phase between them, so no statement waits on
    a separate sub-batch. Per-column log granularity is preserved via ``on_complete``.
    """
    work_items = _build_column_comment_work_items(updates, fallback_tables)

    def worker(item: tuple[list[AttributeUpdate], str]) -> None:
        _ups, stmt = item
        if not dry_run:
            uc_helper.execute_sql(stmt)

    def on_complete(item: tuple[list[AttributeUpdate], str], _result, error) -> None:
        ups, stmt = item
        if error is not None:
            change_logger.log_error(ExecutionError(context=stmt, exception=error))
            return
        for update in ups:
            change_logger.log_attribute_update(update)

    results = parallel_for_each(
        work_items,
        worker,
        max_workers=max_workers,
        on_complete=on_complete,
    )
    if dry_run:
        return []
    return [stmt for (_ups, stmt), _r, error in results if error is None]


def _run_create_batch(
    uc_helper: UnityCatalogHelper,
    creates: list[Securable],
    change_logger: ChangeLogger,
    dry_run: bool,
    max_workers: int,
) -> list[str]:
    """Execute one depth-bucket of creates in parallel.

    Columns are batched per parent table (one ALTER per parent) to avoid
    Delta metadata-commit conflicts; all other securable types run as
    one-securable-per-statement.
    """
    if creates and isinstance(creates[0], Column):
        # Re-narrow for type checkers; at depth 3 every item is a Column.
        return _run_column_create_batch(
            uc_helper,
            [c for c in creates if isinstance(c, Column)],
            change_logger,
            dry_run,
            max_workers,
        )

    work_items: list[tuple[Securable, str]] = [
        (info, _build_create_sql(info)) for info in creates
    ]

    def worker(item: tuple[Securable, str]) -> None:
        _info, stmt = item
        if not dry_run:
            uc_helper.execute_sql(stmt)

    def on_complete(item: tuple[Securable, str], _result, error) -> None:
        info, stmt = item
        if error is not None:
            change_logger.log_error(ExecutionError(context=stmt, exception=error))
            return
        change_logger.log_securable_create(info)

    results = parallel_for_each(
        work_items,
        worker,
        max_workers=max_workers,
        on_complete=on_complete,
    )
    if dry_run:
        return []
    return [stmt for (_info, stmt), _result, error in results if error is None]


def _run_replace_batch(
    uc_helper: UnityCatalogHelper,
    replaces: list[Securable],
    old_securables: dict[str, Securable],
    change_logger: ChangeLogger,
    dry_run: bool,
    max_workers: int,
) -> list[str]:
    """Execute the replaces batch in parallel; stream logs and return input-order statements."""
    work_items: list[tuple[Securable, str]] = [
        (info, _build_replace_sql(info)) for info in replaces
    ]

    def worker(item: tuple[Securable, str]) -> None:
        _info, stmt = item
        if not dry_run:
            uc_helper.execute_sql(stmt)

    def on_complete(item: tuple[Securable, str], _result, error) -> None:
        info, stmt = item
        if error is not None:
            change_logger.log_error(ExecutionError(context=stmt, exception=error))
            return
        change_logger.log_securable_replace(info, old_securables.get(info.full_name))

    results = parallel_for_each(
        work_items,
        worker,
        max_workers=max_workers,
        on_complete=on_complete,
    )
    if dry_run:
        return []
    return [stmt for (_info, stmt), _result, error in results if error is None]


def _attribute_update_stmt(update: AttributeUpdate) -> str | None:
    """Pre-build the SQL stmt for attribute updates that use SQL (just ``comment``)."""
    if update.attribute != "comment":
        return None
    new_comment = next(iter(update.new_value))
    return _build_comment_update_sql(
        update.securable_type,
        update.full_name,
        str(new_comment),
    )


def _attribute_update_sort_key(update: AttributeUpdate) -> tuple[int, int]:
    """Sort key for ordering attribute updates: ``(depth, owner-first)``.

    Depth uses the shared ``_SECURABLE_DEPTH`` topology so catalogs run before
    schemas, which run before tables/volumes/functions. Within each depth,
    owner updates sort before other attributes so the engine can take
    ownership of a securable before altering its other attributes.

    Unknown securable types fall back to depth 99, mirroring
    ``_creation_sort_key``.
    """
    depth = _SECURABLE_DEPTH.get(update.securable_type, 99)
    owner_priority = 0 if update.attribute == "owner" else 1
    return (depth, owner_priority)


def _bucket_attribute_updates(
    updates: list[AttributeUpdate],
) -> dict[tuple[int, int], list[AttributeUpdate]]:
    """Bucket attribute updates by ``(depth, owner-first)``, preserving input order within each bucket."""
    by_key: dict[tuple[int, int], list[AttributeUpdate]] = defaultdict(list)
    for update in updates:
        by_key[_attribute_update_sort_key(update)].append(update)
    return by_key


def _run_attribute_update_sub_batch(
    uc_helper: UnityCatalogHelper,
    updates: list[AttributeUpdate],
    change_logger: ChangeLogger,
    dry_run: bool,
    max_workers: int,
) -> list[str]:
    """Execute one (depth, owner|other) bucket of attribute updates in parallel; stream logs and return input-order statements."""
    work_items: list[tuple[AttributeUpdate, str | None]] = [
        (update, _attribute_update_stmt(update)) for update in updates
    ]

    def worker(item: tuple[AttributeUpdate, str | None]) -> None:
        update, stmt = item
        _run_attribute_update(uc_helper, update, stmt, dry_run)

    def on_complete(item: tuple[AttributeUpdate, str | None], _result, error) -> None:
        update, stmt = item
        if error is not None:
            change_logger.log_error(
                ExecutionError(
                    context=_attribute_update_context(update, stmt),
                    exception=error,
                )
            )
            return
        change_logger.log_attribute_update(update)

    results = parallel_for_each(
        work_items,
        worker,
        max_workers=max_workers,
        on_complete=on_complete,
    )
    if dry_run:
        return []
    return [
        stmt
        for (_update, stmt), _result, error in results
        if error is None and stmt is not None
    ]


def _is_column_comment_update(update: AttributeUpdate) -> bool:
    """True for a comment update on a column (routed via the column-comment batch)."""
    return (
        update.securable_type == SecurableType.COLUMN and update.attribute == "comment"
    )


def _column_comment_fallback_tables(
    actual_securables: set[Securable] | None,
) -> frozenset[str]:
    """Table full names whose ``table_type`` doesn't support ``ALTER TABLE … ALTER COLUMN``.

    Derived from the actual-state ``Table`` securables (which carry ``table_type``);
    columns on these tables get per-column ``COMMENT ON COLUMN`` instead of a batched
    ``ALTER TABLE``. An empty/absent actual set means every column takes the batched
    ALTER path (the common case).
    """
    return frozenset(
        s.full_name
        for s in (actual_securables or set())
        if isinstance(s, Table)
        and s.table_type in _ALTER_COLUMN_UNSUPPORTED_TABLE_TYPES
    )


def execute_securable_diff(
    uc_helper: UnityCatalogHelper,
    diff: SecurableDiff,
    change_logger: ChangeLogger,
    dry_run: bool = False,
    max_parallel_changes: int = 8,
    actual_securables: set[Securable] | None = None,
) -> list[str]:
    """Execute securable creates, replaces, and attribute updates from a SecurableDiff.

    Execution order: creates (SQL, parent-first by depth) → replaces (SQL) →
    attribute updates (depth-ordered, owner-first within each depth).

    Attribute updates are split into sub-batches keyed by
    ``(depth, owner-first)`` and run sequentially in that order — catalogs
    before schemas before tables/volumes/functions, and within each depth all
    owner changes complete before any comment/RFA change starts. This lets the
    engine take ownership of a parent before it tries to alter its children.

    Within each depth bucket of creates, and within each of the replaces and
    attribute-update sub-batches, items run in parallel up to
    ``max_parallel_changes``. Dry-run forces sequential execution so log
    output is identical to non-parallel mode.

    Column comment updates are handled in a dedicated final phase (after the
    generic attribute updates): they are batched into one
    ``ALTER TABLE … ALTER COLUMN`` per base table, except for columns whose
    parent table type doesn't support that (views, metric/materialized views,
    streaming tables), which fall back to one ``COMMENT ON COLUMN`` per column.
    ``actual_securables`` supplies the ``Table.table_type`` values used to make
    that routing decision; when omitted, every column takes the batched ALTER
    path.

    Returns the list of SQL statements that were successfully executed
    (empty in dry-run mode).
    """
    workers = 1 if dry_run else max_parallel_changes
    statements: list[str] = []

    creates_by_depth = _bucket_creates_by_depth(diff)
    for depth in sorted(creates_by_depth):
        statements.extend(
            _run_create_batch(
                uc_helper,
                creates_by_depth[depth],
                change_logger,
                dry_run,
                workers,
            )
        )

    statements.extend(
        _run_replace_batch(
            uc_helper,
            list(diff.securables_to_replace),
            diff.old_securables,
            change_logger,
            dry_run,
            workers,
        )
    )

    # Column comment updates are handled by a dedicated final phase (batched one ALTER
    # per base table; COMMENT ON COLUMN for view-family tables); every other attribute
    # update flows through the generic depth/owner-first bucketing.
    column_comment_updates = [
        u for u in diff.attributes_to_update if _is_column_comment_update(u)
    ]
    other_updates = [
        u for u in diff.attributes_to_update if not _is_column_comment_update(u)
    ]

    attribute_buckets = _bucket_attribute_updates(other_updates)
    for sort_key in sorted(attribute_buckets):
        statements.extend(
            _run_attribute_update_sub_batch(
                uc_helper,
                attribute_buckets[sort_key],
                change_logger,
                dry_run,
                workers,
            )
        )

    statements.extend(
        _run_column_comment_batch(
            uc_helper,
            column_comment_updates,
            _column_comment_fallback_tables(actual_securables),
            change_logger,
            dry_run,
            workers,
        )
    )

    return statements
