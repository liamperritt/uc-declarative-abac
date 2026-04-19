from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_abac_governor.helpers.unity_catalog import UnityCatalogHelper
    from uc_abac_governor.logger import ChangeLogger

from uc_abac_governor.helpers import quote_securable as quote_securable
from uc_abac_governor.securables.state import (
    Function,
    Securable,
    SecurableDiff,
    Table,
)
from uc_abac_governor.principals.resolver import ensure_resolved
from uc_abac_governor.principals.state import Principal
from uc_abac_governor.types import ExecutionError, SecurableType


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


def _creation_sort_key(info: Securable) -> tuple[int, str]:
    """Sort creates parent-first (by depth), then alphabetically by full_name."""
    depth = _CREATION_DEPTH.get(info.securable_type, 99)
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
    """``CREATE CATALOG IF NOT EXISTS <name>`` — managed only."""
    return f"CREATE CATALOG IF NOT EXISTS {quote_securable(info.full_name)}"


def _build_create_schema_sql(info: Securable) -> str:
    """``CREATE SCHEMA IF NOT EXISTS <catalog>.<schema>`` — managed only."""
    return f"CREATE SCHEMA IF NOT EXISTS {quote_securable(info.full_name)}"


def _build_create_volume_sql(info: Securable) -> str:
    """``CREATE VOLUME IF NOT EXISTS <catalog>.<schema>.<volume>`` — managed only (no LOCATION)."""
    return f"CREATE VOLUME IF NOT EXISTS {quote_securable(info.full_name)}"


def _build_create_table_sql(info: Table) -> str:
    """``CREATE TABLE IF NOT EXISTS <full_name> (col1 TYPE, col2 TYPE, ...)`` — managed only.

    The differ has already validated that every column has a non-None ``type`` before
    a Table reaches this builder, so it's safe to assume types are present.
    """
    column_defs = ", ".join(
        f"`{c.full_name.rsplit('.', 1)[-1]}` {c.type}" for c in info.columns
    )
    return f"CREATE TABLE IF NOT EXISTS {quote_securable(info.full_name)} ({column_defs})"


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
    """Return a ' COMMENT '<escaped>'' suffix, or empty string if no comment."""
    if not comment:
        return ""
    escaped = comment.replace("'", "\\'")
    return f" COMMENT '{escaped}'"


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


def execute_securable_diff(
    uc_helper: UnityCatalogHelper,
    diff: SecurableDiff,
    change_logger: ChangeLogger,
    dry_run: bool = False,
) -> list[str]:
    """Execute securable creates, replaces, and attribute updates from a SecurableDiff.

    Execution order: creates (SQL) -> replaces (SQL) -> attribute updates (API).
    Returns the list of SQL statements that were successfully executed (empty in dry-run mode).
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

    # Attribute updates (API calls, not SQL)
    for update in diff.attributes_to_update:
        if update.attribute == "owner":
            if not dry_run:
                try:
                    if isinstance(update.new_value, Principal):
                        owner_id = ensure_resolved(update.new_value).identifier
                    else:
                        owner_id = update.new_value
                    uc_helper.update_owner(update.securable_type, update.full_name, owner_id)
                except Exception as exc:
                    change_logger.log_error(ExecutionError(
                        context=f"update_owner({update.securable_type.value}, {update.full_name})",
                        exception=exc,
                    ))
                    continue
        change_logger.log_attribute_update(update)

    return statements
