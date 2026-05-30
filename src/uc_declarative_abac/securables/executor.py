from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_declarative_abac.helpers import UnityCatalogHelper
    from uc_declarative_abac.logger import ChangeLogger

from uc_declarative_abac.utils import (
    ExecutionError,
    OrchestratorError,
    parallel_for_each,
    quote_securable,
)
from uc_declarative_abac.securables.state import (
    AttributeUpdate,
    Column,
    Function,
    Securable,
    SecurableDiff,
    Table,
)
from uc_declarative_abac.principals import (
    ensure_resolved,
    Principal,
)
from uc_declarative_abac.types import SecurableType


# Creation order: a parent must exist before any of its children can be created.
# Catalogs first, then schemas, then leaf types (tables/volumes/functions).
_CREATION_DEPTH: dict[SecurableType, int] = {
    SecurableType.CATALOG: 0,
    SecurableType.SCHEMA: 1,
    SecurableType.TABLE: 2,
    SecurableType.VOLUME: 2,
    SecurableType.FUNCTION: 2,
    SecurableType.COLUMN: 3,
}


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
    depth = _CREATION_DEPTH.get(info.securable_type, 99)
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
        case Column():
            return _build_alter_table_add_column_sql(info)
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
        f"`{c.full_name.rsplit('.', 1)[-1]}` {c.data_type}" for c in info.columns
    )
    return (
        f"CREATE TABLE IF NOT EXISTS {quote_securable(info.full_name)} ({column_defs})"
        f"{_build_comment_clause(info.comment)}"
        f"{_build_external_location_clause(info.location)}"
    )


def _build_alter_table_add_column_sql(info: Column) -> str:
    """``ALTER TABLE <parent> ADD COLUMN `<name>` <TYPE>`` — adds a single column to
    an existing table. The differ has already validated that ``data_type`` is set
    before a Column reaches this builder."""
    parent_full_name, _, column_name = info.full_name.rpartition(".")
    return (
        f"ALTER TABLE {quote_securable(parent_full_name)} "
        f"ADD COLUMN `{column_name}` {info.data_type}"
    )


def _build_replace_sql(info: Securable) -> str:
    """Build a CREATE OR REPLACE SQL statement for a securable."""
    match info:
        case Function():
            return _build_replace_function_sql(info)
        case _:
            raise NotImplementedError(f"Replace not supported for {type(info).__name__}")


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
    return f"CREATE OR REPLACE FUNCTION {quoted}{params}{comment} RETURN {info.definition}"


def _build_comment_update_sql(securable_type: SecurableType, full_name: str, comment: str) -> str:
    """Build an ALTER/COMMENT ON SQL statement to set the comment of an existing securable.

    Catalog/schema use ``ALTER ... SET COMMENT '...'``; table/volume use
    ``COMMENT ON ... IS '...'``. The differ has already guarded against
    comment changes on views.
    """
    quoted = quote_securable(full_name)
    escaped = _escape_sql_string_literal(comment)
    if securable_type in (SecurableType.COLUMN, SecurableType.FUNCTION):
        raise OrchestratorError(
            f"Comment updates not supported for {securable_type.value}."
        )
    return f'COMMENT ON {securable_type.name} {quoted} IS "{escaped}"'


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
                update.securable_type, update.full_name, update.new_value,
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
    for depth in by_depth:
        by_depth[depth].sort(key=_creation_sort_key)
    return by_depth


def _run_create_batch(
    uc_helper: UnityCatalogHelper,
    creates: list[Securable],
    change_logger: ChangeLogger,
    dry_run: bool,
    max_workers: int,
) -> list[str]:
    """Execute one depth-bucket of creates in parallel; log/error in input order."""
    work_items: list[tuple[Securable, str]] = [
        (info, _build_create_sql(info)) for info in creates
    ]

    def worker(item: tuple[Securable, str]) -> None:
        _info, stmt = item
        if not dry_run:
            uc_helper.execute_sql(stmt)

    results = parallel_for_each(work_items, worker, max_workers=max_workers)
    statements: list[str] = []
    for (info, stmt), _result, error in results:
        if error is not None:
            change_logger.log_error(ExecutionError(context=stmt, exception=error))
            continue
        if not dry_run:
            statements.append(stmt)
        change_logger.log_securable_create(info)
    return statements


def _run_replace_batch(
    uc_helper: UnityCatalogHelper,
    replaces: list[Securable],
    change_logger: ChangeLogger,
    dry_run: bool,
    max_workers: int,
) -> list[str]:
    """Execute the replaces batch in parallel; log/error in input order."""
    work_items: list[tuple[Securable, str]] = [
        (info, _build_replace_sql(info)) for info in replaces
    ]

    def worker(item: tuple[Securable, str]) -> None:
        _info, stmt = item
        if not dry_run:
            uc_helper.execute_sql(stmt)

    results = parallel_for_each(work_items, worker, max_workers=max_workers)
    statements: list[str] = []
    for (info, stmt), _result, error in results:
        if error is not None:
            change_logger.log_error(ExecutionError(context=stmt, exception=error))
            continue
        if not dry_run:
            statements.append(stmt)
        change_logger.log_securable_replace(info)
    return statements


def _attribute_update_stmt(update: AttributeUpdate) -> str | None:
    """Pre-build the SQL stmt for attribute updates that use SQL (just ``comment``)."""
    if update.attribute != "comment":
        return None
    new_comment = next(iter(update.new_value))
    return _build_comment_update_sql(
        update.securable_type, update.full_name, str(new_comment),
    )


def _run_attribute_update_batch(
    uc_helper: UnityCatalogHelper,
    updates: list[AttributeUpdate],
    change_logger: ChangeLogger,
    dry_run: bool,
    max_workers: int,
) -> list[str]:
    """Execute the attribute updates batch in parallel; log/error in input order."""
    work_items: list[tuple[AttributeUpdate, str | None]] = [
        (update, _attribute_update_stmt(update)) for update in updates
    ]

    def worker(item: tuple[AttributeUpdate, str | None]) -> None:
        update, stmt = item
        _run_attribute_update(uc_helper, update, stmt, dry_run)

    results = parallel_for_each(work_items, worker, max_workers=max_workers)
    statements: list[str] = []
    for (update, stmt), _result, error in results:
        if error is not None:
            change_logger.log_error(ExecutionError(
                context=_attribute_update_context(update, stmt),
                exception=error,
            ))
            continue
        if stmt is not None and not dry_run:
            statements.append(stmt)
        change_logger.log_attribute_update(update)
    return statements


def execute_securable_diff(
    uc_helper: UnityCatalogHelper,
    diff: SecurableDiff,
    change_logger: ChangeLogger,
    dry_run: bool = False,
    max_parallel_changes: int = 16,
) -> list[str]:
    """Execute securable creates, replaces, and attribute updates from a SecurableDiff.

    Execution order: creates (SQL, parent-first by depth) → replaces (SQL) →
    attribute updates (SDK call for ``owner``/``rfa_destinations``; SQL ALTER
    for ``comment``).

    Within each depth bucket of creates, and within each of the replaces and
    attribute-updates phases, items run in parallel up to ``max_parallel_changes``.
    Cross-depth ordering is preserved (catalog → schema → tables/volumes/functions
    → columns). Dry-run forces sequential execution so log output is identical to
    non-parallel mode.

    Returns the list of SQL statements that were successfully executed
    (empty in dry-run mode).
    """
    workers = 1 if dry_run else max_parallel_changes
    statements: list[str] = []

    creates_by_depth = _bucket_creates_by_depth(diff)
    for depth in sorted(creates_by_depth):
        statements.extend(_run_create_batch(
            uc_helper, creates_by_depth[depth], change_logger, dry_run, workers,
        ))

    statements.extend(_run_replace_batch(
        uc_helper, list(diff.securables_to_replace), change_logger, dry_run, workers,
    ))

    statements.extend(_run_attribute_update_batch(
        uc_helper, list(diff.attributes_to_update), change_logger, dry_run, workers,
    ))

    return statements
