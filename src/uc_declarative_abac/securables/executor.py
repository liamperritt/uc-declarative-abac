from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_declarative_abac.helpers.unity_catalog import UnityCatalogHelper
    from uc_declarative_abac.logger import ChangeLogger

from uc_declarative_abac.utils import quote_securable as quote_securable
from uc_declarative_abac.securables.state import (
    AttributeUpdate,
    Column,
    Function,
    Securable,
    SecurableDiff,
    Table,
)
from uc_declarative_abac.principals.resolver import ensure_resolved
from uc_declarative_abac.principals.state import Principal
from uc_declarative_abac.types import ExecutionError, GovernorError, SecurableType


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
    return value.replace("'", "\\'")


def _build_comment_clause(comment: str | None) -> str:
    """Return a `` COMMENT '<escaped>''`` suffix, or empty string if no comment."""
    if not comment:
        return ""
    return f" COMMENT '{_escape_sql_string_literal(comment)}'"


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
    match securable_type:
        case SecurableType.CATALOG:
            return f"ALTER CATALOG {quoted} SET COMMENT '{escaped}'"
        case SecurableType.SCHEMA:
            return f"ALTER SCHEMA {quoted} SET COMMENT '{escaped}'"
        case SecurableType.TABLE:
            return f"COMMENT ON TABLE {quoted} IS '{escaped}'"
        case SecurableType.VOLUME:
            return f"COMMENT ON VOLUME {quoted} IS '{escaped}'"
        case _:
            raise GovernorError(
                f"Comment updates not supported for {securable_type.value}."
            )


def _build_location_update_sql(securable_type: SecurableType, full_name: str, location: str) -> str:
    """Build an ALTER SQL statement to set the managed location of a catalog or schema.

    Table/volume external location is immutable — the differ filters those before they
    reach the executor. Reaching this builder for TABLE/VOLUME indicates a differ regression.
    """
    quoted = quote_securable(full_name)
    escaped = _escape_sql_string_literal(location)
    match securable_type:
        case SecurableType.CATALOG:
            return f"ALTER CATALOG {quoted} SET MANAGED LOCATION '{escaped}'"
        case SecurableType.SCHEMA:
            return f"ALTER SCHEMA {quoted} SET MANAGED LOCATION '{escaped}'"
        case _:
            raise GovernorError(
                f"Location alters are not supported for {securable_type.value} — "
                "external location is immutable; this update should have been filtered "
                "by the differ."
            )


def _apply_owner_update(uc_helper: UnityCatalogHelper, update: AttributeUpdate) -> None:
    """Apply an owner change via the SDK ``update_owner`` dispatch."""
    if isinstance(update.new_value, Principal):
        owner_id = ensure_resolved(update.new_value).identifier
    else:
        owner_id = update.new_value
    uc_helper.update_owner(update.securable_type, update.full_name, owner_id)


def _execute_sql_attribute_update(
    uc_helper: UnityCatalogHelper,
    change_logger: ChangeLogger,
    dry_run: bool,
    statements: list[str],
    stmt: str,
) -> bool:
    """Run a SQL-based attribute update (comment/location). Returns True on success or in dry-run.

    On failure: logs an ExecutionError and returns False. Successful executions
    append to ``statements`` so the caller can report the issued SQL.
    """
    if dry_run:
        return True
    try:
        uc_helper.execute_sql(stmt)
    except Exception as exc:
        change_logger.log_error(ExecutionError(context=stmt, exception=exc))
        return False
    statements.append(stmt)
    return True


def _apply_attribute_update(
    uc_helper: UnityCatalogHelper,
    update: AttributeUpdate,
    change_logger: ChangeLogger,
    dry_run: bool,
    statements: list[str],
) -> bool:
    """Dispatch an AttributeUpdate to the right backend (SDK owner update or SQL ALTER)."""
    match update.attribute:
        case "owner":
            if dry_run:
                return True
            try:
                _apply_owner_update(uc_helper, update)
            except Exception as exc:
                change_logger.log_error(ExecutionError(
                    context=f"update_owner({update.securable_type.value}, {update.full_name})",
                    exception=exc,
                ))
                return False
            return True
        case "comment":
            stmt = _build_comment_update_sql(
                update.securable_type, update.full_name, str(update.new_value),
            )
            return _execute_sql_attribute_update(
                uc_helper, change_logger, dry_run, statements, stmt,
            )
        case "location":
            try:
                stmt = _build_location_update_sql(
                    update.securable_type, update.full_name, str(update.new_value),
                )
            except GovernorError as exc:
                change_logger.log_error(ExecutionError(
                    context=f"Update location on {update.securable_type.value} {update.full_name}",
                    exception=exc,
                ))
                return False
            return _execute_sql_attribute_update(
                uc_helper, change_logger, dry_run, statements, stmt,
            )
        case _:
            change_logger.log_error(ExecutionError(
                context=f"Unknown attribute {update.attribute!r} on {update.securable_type.value} {update.full_name}",
                exception=GovernorError(f"No executor branch for attribute {update.attribute!r}"),
            ))
            return False


def execute_securable_diff(
    uc_helper: UnityCatalogHelper,
    diff: SecurableDiff,
    change_logger: ChangeLogger,
    dry_run: bool = False,
) -> list[str]:
    """Execute securable creates, replaces, and attribute updates from a SecurableDiff.

    Execution order: creates (SQL) -> replaces (SQL) -> attribute updates
    (SDK call for ``owner``; SQL ALTER for ``comment``/``location``).
    Returns the list of SQL statements that were successfully executed
    (empty in dry-run mode).
    """
    statements: list[str] = []

    # Creates — sorted parent-first (catalogs before schemas before tables/volumes/functions)
    for info in sorted(diff.securables_to_create, key=_creation_sort_key):
        stmt = _build_create_sql(info)
        if not dry_run:
            try:
                uc_helper.execute_sql(stmt)
            except Exception as exc:
                change_logger.log_error(ExecutionError(context=stmt, exception=exc))
                continue
            statements.append(stmt)
        change_logger.log_securable_create(info)

    # Replaces
    for info in diff.securables_to_replace:
        stmt = _build_replace_sql(info)
        if not dry_run:
            try:
                uc_helper.execute_sql(stmt)
            except Exception as exc:
                change_logger.log_error(ExecutionError(context=stmt, exception=exc))
                continue
            statements.append(stmt)
        change_logger.log_securable_replace(info)

    # Attribute updates (SDK for owner; SQL ALTER for comment/location)
    for update in diff.attributes_to_update:
        applied = _apply_attribute_update(uc_helper, update, change_logger, dry_run, statements)
        if applied:
            change_logger.log_attribute_update(update)

    return statements
