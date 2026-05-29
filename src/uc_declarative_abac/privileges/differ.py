from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_declarative_abac.logger import ChangeLogger
    from uc_declarative_abac.principals.resolver import PrincipalResolver

from uc_declarative_abac.privileges.state import PrivilegeDiff, SecurablePrivilege
from uc_declarative_abac.utils import ExecutionError, PrincipalValidationError



def compute_privilege_diff(
    desired: set[SecurablePrivilege],
    actual: set[SecurablePrivilege],
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
) -> PrivilegeDiff:
    """Compute the diff between desired and actual privileges.

    Resolves principals on both sides before diffing so that the two sides
    compare correctly (UC stores service principals by application_id, config
    references them by display name). Privileges whose principal fails to
    resolve are logged via change_logger and excluded from the diff.

    - to_grant: desired privileges not in actual
    - to_revoke: actual privileges not in desired
    """
    desired_resolved = _resolve_privileges(desired, resolver, change_logger)
    actual_resolved = _resolve_privileges(actual, resolver, change_logger)
    return PrivilegeDiff(
        to_grant=desired_resolved - actual_resolved,
        to_revoke=actual_resolved - desired_resolved,
    )


def _resolve_privileges(
    unresolved: set[SecurablePrivilege],
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
) -> set[SecurablePrivilege]:
    """Resolve the principal on each SecurablePrivilege.

    Privileges whose principal cannot be resolved are logged once via
    change_logger.log_error and excluded from the result.
    """
    result: set[SecurablePrivilege] = set()
    for priv in unresolved:
        try:
            resolved_principal = resolver.resolve_principal(priv.principal)
        except PrincipalValidationError as exc:
            change_logger.log_error(ExecutionError(
                context=f"Resolve principal for {priv.privilege_type.value.upper()} on {priv.securable_type.value} {priv.securable_full_name}",
                exception=exc,
            ))
            continue
        result.add(SecurablePrivilege(
            securable_type=priv.securable_type,
            securable_full_name=priv.securable_full_name,
            principal=resolved_principal,
            privilege_type=priv.privilege_type,
        ))
    return result
