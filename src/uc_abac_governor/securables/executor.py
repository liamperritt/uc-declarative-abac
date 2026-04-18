from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_abac_governor.helpers.unity_catalog import UnityCatalogHelper
    from uc_abac_governor.logger import ChangeLogger

from uc_abac_governor.helpers import quote_securable as quote_securable
from uc_abac_governor.securables.state import (
    FunctionInfo,
    SecurableInfo,
    SecurableDiff,
)
from uc_abac_governor.principals.resolver import ensure_resolved
from uc_abac_governor.principals.state import Principal
from uc_abac_governor.types import ExecutionError


def _build_create_sql(info: SecurableInfo) -> str:
    """Build a CREATE SQL statement for a securable."""
    match info:
        case FunctionInfo():
            return _build_create_function_sql(info)
        case _:
            raise NotImplementedError(f"Create not supported for {type(info).__name__}")


def _build_replace_sql(info: SecurableInfo) -> str:
    """Build a CREATE OR REPLACE SQL statement for a securable."""
    match info:
        case FunctionInfo():
            return _build_replace_function_sql(info)
        case _:
            raise NotImplementedError(f"Replace not supported for {type(info).__name__}")


def _build_function_params(parameters: tuple[tuple[str, str], ...]) -> str:
    """Format function parameters as a parenthesised list."""
    if not parameters:
        return "()"
    entries = ", ".join(f"{name} {data_type}" for name, data_type in parameters)
    return f"({entries})"


def _build_create_function_sql(info: FunctionInfo) -> str:
    """Build CREATE FUNCTION SQL."""
    quoted = quote_securable(info.full_name)
    params = _build_function_params(info.parameters)
    return f"CREATE FUNCTION {quoted}{params} RETURN {info.definition}"


def _build_replace_function_sql(info: FunctionInfo) -> str:
    """Build CREATE OR REPLACE FUNCTION SQL."""
    quoted = quote_securable(info.full_name)
    params = _build_function_params(info.parameters)
    return f"CREATE OR REPLACE FUNCTION {quoted}{params} RETURN {info.definition}"


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

    # Creates
    for info in diff.securables_to_create:
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
