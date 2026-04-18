from __future__ import annotations

from uc_abac_governor.policies.state import Policy, PolicyDiff


def compute_policy_diff(desired: set[Policy], actual: set[Policy]) -> PolicyDiff:
    """Compute the diff between desired and actual mask/filter policies.

    Key by (securable_type, securable_full_name, name):
    - to_create: policy not present in actual
    - to_replace: policy present in both but fields differ
    Policies present only in actual are ignored (UC policies are never deleted
    by the governor).
    """
    actual_by_key = {_identity(p): p for p in actual}

    to_create: set[Policy] = set()
    to_replace: set[Policy] = set()

    for desired_policy in desired:
        existing = actual_by_key.get(_identity(desired_policy))
        if existing is None:
            to_create.add(desired_policy)
        elif existing != desired_policy:
            to_replace.add(desired_policy)

    return PolicyDiff(to_create=to_create, to_replace=to_replace)


def _identity(policy: Policy) -> tuple:
    return (policy.securable_type, policy.securable_full_name, policy.name)
