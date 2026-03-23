from __future__ import annotations

from uc_governor.privileges.state import PrivilegeDiff, SecurablePrivilege


def compute_privilege_diff(
    desired: set[SecurablePrivilege],
    actual: set[SecurablePrivilege],
) -> PrivilegeDiff:
    """Compute the diff between desired and actual privileges.

    - to_grant: desired privileges not in actual
    - to_revoke: actual privileges not in desired
    """
    return PrivilegeDiff(
        to_grant=desired - actual,
        to_revoke=actual - desired,
    )
