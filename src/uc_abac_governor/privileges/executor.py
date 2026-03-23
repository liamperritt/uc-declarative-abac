from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_abac_governor.helpers.account import AccountHelper
    from uc_abac_governor.helpers.unity_catalog import UnityCatalogHelper

from uc_abac_governor.privileges.state import PrivilegeDiff


def execute_privilege_diff(
    uc_helper: UnityCatalogHelper,
    acct_helper: AccountHelper,
    diff: PrivilegeDiff,
) -> list[str]:
    """Generate and execute GRANT/REVOKE SQL from a PrivilegeDiff.

    Uses acct_helper to resolve SP display names to application IDs.
    Returns the list of SQL statements executed.
    """
    raise NotImplementedError
