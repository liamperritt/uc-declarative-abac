from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_abac_governor.helpers.workspace import WorkspaceHelper
    from uc_abac_governor.logger import ChangeLogger

from uc_abac_governor.privileges.state import SecurablePrivilege, UnresolvedPrivilege
from uc_abac_governor.types import ExecutionError, PrincipalValidationError

_logger = logging.getLogger("uc_abac_governor")


def resolve_compiled_privileges(
    compiled: set[UnresolvedPrivilege],
    ws_helper: WorkspaceHelper,
    change_logger: ChangeLogger,
) -> set[SecurablePrivilege]:
    """Resolve compiled privileges to SecurablePrivileges with Principal objects.

    Unknown principals (not in the workspace) are logged as errors and excluded.
    """
    principals = ws_helper.get_principals()
    resolved: set[SecurablePrivilege] = set()
    unknown: set[str] = set()

    for cp in compiled:
        principal = principals.get(cp.principal)
        if principal is None:
            if cp.principal not in unknown:
                unknown.add(cp.principal)
                change_logger.log_error(ExecutionError(
                    context=f"Validate principal '{cp.principal}'",
                    exception=PrincipalValidationError(
                        f"Principal '{cp.principal}' not found in workspace"
                    ),
                ))
            continue
        resolved.add(SecurablePrivilege(
            securable_type=cp.securable_type,
            securable_full_name=cp.securable_full_name,
            principal=principal,
            privilege_type=cp.privilege_type,
        ))

    return resolved


def resolve_actual_privileges(
    actual_privileges: set[UnresolvedPrivilege],
    ws_helper: WorkspaceHelper,
) -> set[SecurablePrivilege]:
    """Resolve unresolved actual privileges (string principals) to Principal objects.

    Actual privileges with unrecognised principals (e.g. deleted users) are
    logged as errors and excluded.
    """
    resolved: set[SecurablePrivilege] = set()
    for p in actual_privileges:
        try:
            principal = ws_helper.resolve_by_identifier(p.principal)
        except PrincipalValidationError:
            _logger.error(f"Skipping actual privilege: unknown principal '{p.principal}'")
            continue
        resolved.add(SecurablePrivilege(
            securable_type=p.securable_type,
            securable_full_name=p.securable_full_name,
            principal=principal,
            privilege_type=p.privilege_type,
        ))
    return resolved
