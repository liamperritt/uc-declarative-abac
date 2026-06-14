from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_declarative_abac.logger import ChangeLogger
    from uc_declarative_abac.principals.resolver import PrincipalResolver

from uc_declarative_abac.principals.resolver import log_principal_resolution_failure
from uc_declarative_abac.principals.state import Group, GroupDiff, Principal
from uc_declarative_abac.utils import (
    ExecutionError,
    OrchestratorError,
    PrincipalValidationError,
)


def _resolve_group_members(
    group: Group,
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
    ignore_unresolvable: frozenset[str] = frozenset(),
) -> Group:
    """Return a new Group with each principal in ``members`` resolved against
    the workspace.

    Principals that fail to resolve are logged and dropped from the group's
    members — consistent with the governed-tag assigners differ. Dropping
    (rather than aborting) means an unresolvable principal won't trigger a
    phantom add on every run. Actual-state (UC-side) principals route to a
    non-fatal warning (suppressed when the identifier is in
    ``ignore_unresolvable``); config-side principals route to a fatal error (see
    log_principal_resolution_failure).
    """
    resolved: set[Principal] = set()
    for principal in group.members:
        try:
            resolved.add(resolver.resolve_principal(principal))
        except PrincipalValidationError as exc:
            log_principal_resolution_failure(
                change_logger,
                f"Resolve group member for GROUP {group.display_name}",
                principal,
                exc,
                ignore_unresolvable,
            )
            continue
    return Group(
        display_name=group.display_name,
        external_id=group.external_id,
        members=frozenset(resolved),
    )


def compute_group_diff(
    desired: set[Group],
    actual: set[Group],
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
    enable_group_creation: bool = False,
    ignore_unresolvable: frozenset[str] = frozenset(),
) -> GroupDiff:
    """Compute additions-only group-management diff between desired and actual.

    Members on both sides are resolved before comparison so the two sides speak
    the same dialect (config-side has display names; UC-side has identifiers).
    Membership is reconciled additively only — members present in actual but
    absent from desired are left alone (no removals).

    - A desired group whose actual counterpart carries an ``external_id`` is
      externally managed (IdP-provisioned) and cannot be configured here — this
      is a fatal error.
    - A desired group with no actual counterpart is created (with its members)
      when ``enable_group_creation`` is True; otherwise it is a fatal error
      directing the operator to pass ``--enable-group-creation``.

    ``ignore_unresolvable`` silences the resolution-failure warning for the
    listed actual-state member identifiers (the member is still dropped).
    """
    actual_by_name = {g.display_name: g for g in actual}

    diff = GroupDiff()
    for desired_group in desired:
        name = desired_group.display_name
        resolved_desired = _resolve_group_members(
            desired_group, resolver, change_logger, ignore_unresolvable
        )
        actual_group = actual_by_name.get(name)

        if actual_group is not None and actual_group.external_id:
            change_logger.log_error(ExecutionError(
                context=f"Configure GROUP {name}",
                exception=OrchestratorError(
                    f"Group '{name}' is externally managed (IdP-provisioned) "
                    "and cannot be configured by this engine."
                ),
            ))
            continue

        if actual_group is None:
            if enable_group_creation:
                diff.groups_to_create[name] = resolved_desired.members
            else:
                change_logger.log_error(ExecutionError(
                    context=f"Configure GROUP {name}",
                    exception=OrchestratorError(
                        f"Group '{name}' does not exist. Pass "
                        "--enable-group-creation to create it."
                    ),
                ))
            continue

        resolved_actual = _resolve_group_members(
            actual_group, resolver, change_logger, ignore_unresolvable
        )
        to_add = resolved_desired.members - resolved_actual.members
        if to_add:
            diff.members_to_add[name] = frozenset(to_add)

    return diff
