from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_abac_governor.helpers.workspace import WorkspaceHelper
    from uc_abac_governor.logger import ChangeLogger

from uc_abac_governor.securables.state import SecurableAttributes
from uc_abac_governor.types import ExecutionError, Principal, PrincipalValidationError

_logger = logging.getLogger("uc_abac_governor")


def resolve_desired_owners(
    desired_attrs: set[SecurableAttributes],
    ws_helper: WorkspaceHelper,
    change_logger: ChangeLogger,
) -> dict[str, Principal]:
    """Resolve desired owner display names to Principal objects.

    Returns a mapping of full_name → Principal for each securable with an
    owner. Unknown principals are logged as errors and excluded.
    """
    principals = ws_helper.get_principals()
    result: dict[str, Principal] = {}
    unknown: set[str] = set()

    for attr in desired_attrs:
        if attr.owner is None:
            continue
        principal = principals.get(attr.owner)
        if principal is None:
            if attr.owner not in unknown:
                unknown.add(attr.owner)
                change_logger.log_error(ExecutionError(
                    context=f"Resolve owner '{attr.owner}' for {attr.full_name}",
                    exception=PrincipalValidationError(
                        f"Owner '{attr.owner}' not found in workspace"
                    ),
                ))
            continue
        result[attr.full_name] = principal

    return result


def resolve_actual_owners(
    actual_attrs: set[SecurableAttributes],
    ws_helper: WorkspaceHelper,
) -> dict[str, Principal]:
    """Resolve actual owner identifiers to Principal objects.

    Returns a mapping of full_name → Principal. Unrecognised identifiers
    (e.g. deleted users) are logged and excluded.
    """
    result: dict[str, Principal] = {}

    for attr in actual_attrs:
        if attr.owner is None:
            continue
        try:
            principal = ws_helper.resolve_by_identifier(attr.owner)
        except PrincipalValidationError:
            _logger.warning(f"WARNING: Skipping actual owner: unknown identifier '{attr.owner}' on {attr.full_name}")
            continue
        result[attr.full_name] = principal

    return result
