from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_governor.helpers.account import AccountHelper
    from uc_governor.helpers.unity_catalog import UnityCatalogHelper
    from uc_governor.logger import ChangeLogger

from uc_governor.privileges.state import PrivilegeDiff, SecurablePrivilege
from uc_governor.types import ExecutionError, PrincipalValidationError


def _resolve_principal(acct_helper: AccountHelper, principal: str) -> str:
    """Resolve a principal to its application ID if it is a service principal.

    Returns the application ID for service principals, or the original
    display name for all other principal types.
    """
    try:
        return acct_helper.get_sp_application_id(principal)
    except PrincipalValidationError:
        return principal


def _quote_securable(full_name: str) -> str:
    """Backtick-quote each segment of a dot-delimited securable name."""
    return ".".join(f"`{seg}`" for seg in full_name.split("."))


def _build_grant_sql(priv: SecurablePrivilege, resolved_principal: str) -> str:
    """Build a GRANT SQL statement for a single privilege."""
    quoted = _quote_securable(priv.securable_full_name)
    return (
        f"GRANT {priv.privilege_type} "
        f"ON {priv.securable_type.value} {quoted} "
        f"TO `{resolved_principal}`"
    )


def _build_revoke_sql(priv: SecurablePrivilege, resolved_principal: str) -> str:
    """Build a REVOKE SQL statement for a single privilege."""
    quoted = _quote_securable(priv.securable_full_name)
    return (
        f"REVOKE {priv.privilege_type} "
        f"ON {priv.securable_type.value} {quoted} "
        f"FROM `{resolved_principal}`"
    )


def execute_privilege_diff(
    uc_helper: UnityCatalogHelper,
    acct_helper: AccountHelper,
    diff: PrivilegeDiff,
    change_logger: ChangeLogger,
) -> list[str]:
    """Generate and execute GRANT/REVOKE SQL from a PrivilegeDiff.

    Uses acct_helper to resolve SP display names to application IDs.
    Logs each change after successful execution.
    Returns the list of SQL statements executed.
    """
    statements: list[str] = []

    for priv in diff.to_grant:
        resolved = _resolve_principal(acct_helper, priv.principal)
        stmt = _build_grant_sql(priv, resolved)
        try:
            uc_helper.execute_sql(stmt)
        except Exception as exc:
            change_logger.log_error(ExecutionError(statement=stmt, exception=exc))
            continue
        statements.append(stmt)
        change_logger.log_grant(priv)

    for priv in diff.to_revoke:
        resolved = _resolve_principal(acct_helper, priv.principal)
        stmt = _build_revoke_sql(priv, resolved)
        try:
            uc_helper.execute_sql(stmt)
        except Exception as exc:
            change_logger.log_error(ExecutionError(statement=stmt, exception=exc))
            continue
        statements.append(stmt)
        change_logger.log_revoke(priv)

    return statements
