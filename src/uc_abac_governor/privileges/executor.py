from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_abac_governor.helpers.unity_catalog import UnityCatalogHelper
    from uc_abac_governor.logger import ChangeLogger

from uc_abac_governor.privileges.state import PrivilegeDiff, SecurablePrivilege
from uc_abac_governor.types import ExecutionError


def _quote_securable(full_name: str) -> str:
    """Backtick-quote each segment of a dot-delimited securable name."""
    return ".".join(f"`{seg}`" for seg in full_name.split("."))


def _build_grant_sql(priv: SecurablePrivilege) -> str:
    """Build a GRANT SQL statement for a single privilege."""
    quoted = _quote_securable(priv.securable_full_name)
    return (
        f"GRANT {priv.privilege_type.upper()} "
        f"ON {priv.securable_type.value} {quoted} "
        f"TO `{priv.principal.identifier}`"
    )


def _build_revoke_sql(priv: SecurablePrivilege) -> str:
    """Build a REVOKE SQL statement for a single privilege."""
    quoted = _quote_securable(priv.securable_full_name)
    return (
        f"REVOKE {priv.privilege_type.upper()} "
        f"ON {priv.securable_type.value} {quoted} "
        f"FROM `{priv.principal.identifier}`"
    )


def execute_privilege_diff(
    uc_helper: UnityCatalogHelper,
    diff: PrivilegeDiff,
    change_logger: ChangeLogger,
) -> list[str]:
    """Generate and execute GRANT/REVOKE SQL from a PrivilegeDiff.

    Principal identifiers are read directly from the Principal object
    on each SecurablePrivilege.
    Logs each change after successful execution.
    Returns the list of SQL statements executed.
    """
    statements: list[str] = []

    for priv in sorted(diff.to_grant, key=lambda p: (p.securable_type.value, p.securable_full_name)):
        stmt = _build_grant_sql(priv)
        try:
            uc_helper.execute_sql(stmt)
        except Exception as exc:
            change_logger.log_error(ExecutionError(context=stmt, exception=exc))
            continue
        statements.append(stmt)
        change_logger.log_grant(priv)

    for priv in sorted(diff.to_revoke, key=lambda p: (p.securable_type.value, p.securable_full_name)):
        stmt = _build_revoke_sql(priv)
        try:
            uc_helper.execute_sql(stmt)
        except Exception as exc:
            change_logger.log_error(ExecutionError(context=stmt, exception=exc))
            continue
        statements.append(stmt)
        change_logger.log_revoke(priv)

    return statements
