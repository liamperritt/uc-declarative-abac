from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_declarative_abac.logger import ChangeLogger
    from uc_declarative_abac.principals import PrincipalResolver

from uc_declarative_abac.policies.state import (
    Policy,
    PolicyDiff,
)
from uc_declarative_abac.utils import (
    PrincipalValidationError,
)
from uc_declarative_abac.principals import (
    log_principal_resolution_failure,
    Principal,
)



def compute_policy_diff(
    desired: set[Policy],
    actual: set[Policy],
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
    ignore_unresolvable: frozenset[str] = frozenset(),
) -> PolicyDiff:
    """Compute the diff between desired and actual mask/filter policies.

    Resolves to_principals and except_principals on both sides before diffing.
    A principal that cannot be resolved is logged and dropped from that policy's
    principal list, but the policy itself is retained. Actual-state (UC-side)
    failures route to a non-fatal warning (suppressed when the identifier is in
    ``ignore_unresolvable``); config-side failures route to a fatal error.

    Key by (securable_type, securable_full_name, name):
    - to_create: policy not present in actual
    - to_replace: policy present in both but fields differ
    Policies present only in actual are ignored (UC policies are never deleted
    by the orchestrator).
    """
    desired_resolved = _resolve_policy_principals(
        desired, resolver, change_logger, ignore_unresolvable
    )
    actual_resolved = _resolve_policy_principals(
        actual, resolver, change_logger, ignore_unresolvable
    )

    actual_by_key = {_identity(p): p for p in actual_resolved}

    to_create: set[Policy] = set()
    to_replace: set[Policy] = set()
    old_policies: dict[tuple, Policy] = {}

    for desired_policy in desired_resolved:
        identity = _identity(desired_policy)
        existing = actual_by_key.get(identity)
        if existing is None:
            to_create.add(desired_policy)
        elif existing != desired_policy:
            to_replace.add(desired_policy)
            old_policies[identity] = existing

    return PolicyDiff(to_create=to_create, to_replace=to_replace, old_policies=old_policies)


def _identity(policy: Policy) -> tuple:
    return (policy.securable_type, policy.securable_full_name, policy.name)


def _resolve_principal_list(
    principals: tuple[Principal, ...],
    policy: Policy,
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
    ignore_unresolvable: frozenset[str],
) -> list[Principal]:
    """Resolve each principal individually, dropping (and logging) any that fail.

    Mirrors the privileges/governed-tags differs: an unresolvable principal is
    routed through log_principal_resolution_failure (actual-state → non-fatal
    warning, suppressed when its identifier is in ``ignore_unresolvable``;
    config-side → fatal error) and dropped, while the remaining principals are
    kept. Dropping just the principal — rather than the whole policy — keeps an
    actual policy that references an unactionable principal (e.g. a Databricks
    system service principal) from aborting the run or vanishing from the diff."""
    context = (
        f"Resolve principal for policy '{policy.name}' on "
        f"{policy.securable_type.value} {policy.securable_full_name}"
    )
    resolved: list[Principal] = []
    for principal in principals:
        try:
            resolved.append(resolver.resolve_principal(principal))
        except PrincipalValidationError as exc:
            log_principal_resolution_failure(
                change_logger, context, principal, exc, ignore_unresolvable,
            )
    return resolved


def _resolve_policy_principals(
    unresolved: set[Policy],
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
    ignore_unresolvable: frozenset[str] = frozenset(),
) -> set[Policy]:
    """Resolve to_principals and except_principals on every Policy in a set.

    Each principal is resolved individually: an unresolvable principal is logged
    and dropped from its list, but the policy is always retained (even if a list
    becomes empty). Both principal tuples are sorted by (identifier, name) so that
    desired and actual policies produced from the same underlying data compare
    equal regardless of the order they arrived in.
    """
    result: set[Policy] = set()
    for policy in unresolved:
        to_resolved = _resolve_principal_list(
            policy.to_principals, policy, resolver, change_logger, ignore_unresolvable,
        )
        except_resolved = _resolve_principal_list(
            policy.except_principals, policy, resolver, change_logger, ignore_unresolvable,
        )
        result.add(Policy(
            securable_type=policy.securable_type,
            securable_full_name=policy.securable_full_name,
            name=policy.name,
            policy_type=policy.policy_type,
            function_name=policy.function_name,
            to_principals=tuple(sorted(to_resolved, key=_principal_sort_key)),
            except_principals=tuple(sorted(except_resolved, key=_principal_sort_key)),
            when_condition=policy.when_condition,
            match_columns=policy.match_columns,
            on_column=policy.on_column,
            using_columns=policy.using_columns,
            comment=policy.comment,
            for_securable_type=policy.for_securable_type,
        ))
    return result


def _principal_sort_key(principal: Principal) -> tuple[str, str]:
    return (principal.identifier, principal.name)
