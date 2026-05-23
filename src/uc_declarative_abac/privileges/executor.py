from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_declarative_abac.helpers.unity_catalog import UnityCatalogHelper
    from uc_declarative_abac.logger import ChangeLogger

from uc_declarative_abac.utils import quote_securable as quote_securable
from uc_declarative_abac.principals.resolver import ensure_resolved
from uc_declarative_abac.privileges.state import PrivilegeDiff, SecurablePrivilege
from uc_declarative_abac.types import ExecutionError


def _build_grant_sql(priv: SecurablePrivilege) -> str:
    """Build a GRANT SQL statement for a single privilege."""
    quoted = quote_securable(priv.securable_full_name)
    principal = ensure_resolved(priv.principal)
    return (
        f"GRANT {priv.privilege_type.upper()} "
        f"ON {priv.securable_type.value} {quoted} "
        f"TO `{principal.identifier}`"
    )


def _build_revoke_sql(priv: SecurablePrivilege) -> str:
    """Build a REVOKE SQL statement for a single privilege."""
    quoted = quote_securable(priv.securable_full_name)
    principal = ensure_resolved(priv.principal)
    return (
        f"REVOKE {priv.privilege_type.upper()} "
        f"ON {priv.securable_type.value} {quoted} "
        f"FROM `{principal.identifier}`"
    )


def execute_privilege_diff(
    uc_helper: UnityCatalogHelper,
    diff: PrivilegeDiff,
    change_logger: ChangeLogger,
    dry_run: bool = False,
) -> list[str]:
    """Generate and execute GRANT/REVOKE SQL from a PrivilegeDiff.

    Principal identifiers are read directly from the Principal object
    on each SecurablePrivilege.
    Logs each change after successful execution (or unconditionally in dry-run mode).
    Returns the list of SQL statements executed (empty in dry-run mode).
    """
    statements: list[str] = []

    for priv in sorted(diff.to_grant, key=lambda p: (p.securable_type.value, p.securable_full_name)):
        if not dry_run:
            stmt = _build_grant_sql(priv)
            try:
                uc_helper.execute_sql(stmt)
            except Exception as exc:
                change_logger.log_error(ExecutionError(context=stmt, exception=exc))
                continue
            statements.append(stmt)
        change_logger.log_grant(priv)

    for priv in sorted(diff.to_revoke, key=lambda p: (p.securable_type.value, p.securable_full_name)):
        if not dry_run:
            stmt = _build_revoke_sql(priv)
            try:
                uc_helper.execute_sql(stmt)
            except Exception as exc:
                change_logger.log_error(ExecutionError(context=stmt, exception=exc))
                continue
            statements.append(stmt)
        change_logger.log_revoke(priv)

    return statements
