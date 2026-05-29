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
    ExecutionError,
    PrincipalValidationError,
)
from uc_declarative_abac.principals import Principal



def compute_policy_diff(
    desired: set[Policy],
    actual: set[Policy],
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
) -> PolicyDiff:
    """Compute the diff between desired and actual mask/filter policies.

    Resolves to_principals and except_principals on both sides before diffing.
    Policies whose principals cannot be resolved are logged and dropped.

    Key by (securable_type, securable_full_name, name):
    - to_create: policy not present in actual
    - to_replace: policy present in both but fields differ
    Policies present only in actual are ignored (UC policies are never deleted
    by the orchestrator).
    """
    desired_resolved = _resolve_policy_principals(desired, resolver, change_logger)
    actual_resolved = _resolve_policy_principals(actual, resolver, change_logger)

    actual_by_key = {_identity(p): p for p in actual_resolved}

    to_create: set[Policy] = set()
    to_replace: set[Policy] = set()

    for desired_policy in desired_resolved:
        existing = actual_by_key.get(_identity(desired_policy))
        if existing is None:
            to_create.add(desired_policy)
        elif existing != desired_policy:
            to_replace.add(desired_policy)

    return PolicyDiff(to_create=to_create, to_replace=to_replace)


def _identity(policy: Policy) -> tuple:
    return (policy.securable_type, policy.securable_full_name, policy.name)


def _resolve_policy_principals(
    unresolved: set[Policy],
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
) -> set[Policy]:
    """Resolve to_principals and except_principals on every Policy in a set.

    For each policy, the to + except lists are resolved together in a single
    batch — if any principal fails, the whole policy is dropped and a single
    ExecutionError is logged.

    Post-resolution, both principal tuples are sorted by (identifier, name)
    so that desired and actual policies produced from the same underlying data
    compare equal regardless of the order they arrived in.
    """
    result: set[Policy] = set()
    for policy in unresolved:
        combined = list(policy.to_principals) + list(policy.except_principals)
        try:
            resolved = resolver.resolve_principals(combined)
        except PrincipalValidationError as exc:
            change_logger.log_error(ExecutionError(
                context=f"Resolve principals for policy '{policy.name}' on {policy.securable_type.value} {policy.securable_full_name}",
                exception=exc,
            ))
            continue
        cut = len(policy.to_principals)
        to_resolved = tuple(sorted(resolved[:cut], key=_principal_sort_key))
        except_resolved = tuple(sorted(resolved[cut:], key=_principal_sort_key))
        result.add(Policy(
            securable_type=policy.securable_type,
            securable_full_name=policy.securable_full_name,
            name=policy.name,
            policy_type=policy.policy_type,
            function_name=policy.function_name,
            to_principals=to_resolved,
            except_principals=except_resolved,
            when_condition=policy.when_condition,
            match_columns=policy.match_columns,
            on_column=policy.on_column,
            using_columns=policy.using_columns,
            comment=policy.comment,
        ))
    return result


def _principal_sort_key(principal: Principal) -> tuple[str, str]:
    return (principal.identifier, principal.name)
