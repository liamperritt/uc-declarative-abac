from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_declarative_abac.logger import ChangeLogger
    from uc_declarative_abac.principals.resolver import PrincipalResolver

from uc_declarative_abac.principals.resolver import log_principal_resolution_failure
from uc_declarative_abac.principals.state import (
    Group,
    GroupDiff,
    GroupRename,
    Principal,
)
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


def _find_actual_group(
    desired_group: Group,
    actual_by_name: dict[str, Group],
    actual_by_id: dict[str, Group],
    change_logger: ChangeLogger,
) -> tuple[Group | None, bool]:
    """Locate the actual group matching ``desired_group``.

    When the desired group declares an ``id``, matching is by id: a desired id with
    no matching account group is a fatal error (returns ``(None, False)``) — no
    fall back to name matching, so a stale or mistyped id fails the run loudly
    rather than silently creating a duplicate group. Without an id, matching falls
    back to display name (returns ``(actual_or_none, True)``)."""
    if desired_group.id:
        actual_group = actual_by_id.get(desired_group.id)
        if actual_group is None:
            change_logger.log_error(ExecutionError(
                context=f"Configure GROUP {desired_group.display_name}",
                exception=OrchestratorError(
                    f"Group id '{desired_group.id}' (declared for "
                    f"'{desired_group.display_name}') does not exist in the account."
                ),
            ))
            return None, False
        return actual_group, True
    return actual_by_name.get(desired_group.display_name), True


def _handle_missing_group(
    desired_group: Group,
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
    ignore_unresolvable: frozenset[str],
    enable_group_creation: bool,
    enable_group_management: bool,
    diff: GroupDiff,
) -> None:
    """Handle a desired group with no actual counterpart (creation gating).

    With creation enabled the group is queued for creation with its resolved
    members; otherwise, under management only, its absence is a fatal error
    directing the operator to ``--enable-group-creation``; with neither flag it is
    silently ignored."""
    name = desired_group.display_name
    if enable_group_creation:
        resolved_desired = _resolve_group_members(
            desired_group, resolver, change_logger, ignore_unresolvable
        )
        diff.groups_to_create[name] = resolved_desired.members
    elif enable_group_management:
        change_logger.log_error(ExecutionError(
            context=f"Configure GROUP {name}",
            exception=OrchestratorError(
                f"Group '{name}' does not exist. Pass "
                "--enable-group-creation to create it."
            ),
        ))


def _emit_rename_if_needed(
    desired_group: Group,
    actual_group: Group,
    actual_by_name: dict[str, Group],
    diff: GroupDiff,
    change_logger: ChangeLogger,
) -> bool:
    """Record a rename when the matched group's display name differs from config.

    A rename is detected only when the group was matched by id and the actual
    display name differs from the desired one. If the desired (new) name already
    belongs to a *different* existing group, the rename is a fatal error (logged)
    and ``False`` is returned so membership reconciliation is skipped. Otherwise
    ``True`` is returned (whether or not a rename was emitted)."""
    name = desired_group.display_name
    if actual_group.display_name == name:
        return True
    collision = actual_by_name.get(name)
    if collision is not None and collision.id != desired_group.id:
        change_logger.log_error(ExecutionError(
            context=f"Configure GROUP {name}",
            exception=OrchestratorError(
                f"Cannot rename group id '{desired_group.id}' to '{name}': another "
                "group already uses that display name."
            ),
        ))
        return False
    diff.groups_to_rename.append(GroupRename(
        id=desired_group.id,
        old_display_name=actual_group.display_name,
        new_display_name=name,
    ))
    return True


def _reconcile_membership(
    desired_group: Group,
    actual_group: Group,
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
    ignore_unresolvable: frozenset[str],
    diff: GroupDiff,
) -> None:
    """Compute member add/remove sets for an existing group, keyed by the desired
    (post-rename) display name so the executor targets the group by its new name."""
    name = desired_group.display_name
    resolved_desired = _resolve_group_members(
        desired_group, resolver, change_logger, ignore_unresolvable
    )
    resolved_actual = _resolve_group_members(
        actual_group, resolver, change_logger, ignore_unresolvable
    )
    to_add = resolved_desired.members - resolved_actual.members
    to_remove = resolved_actual.members - resolved_desired.members
    if to_add:
        diff.members_to_add[name] = frozenset(to_add)
    if to_remove:
        diff.members_to_remove[name] = frozenset(to_remove)


def compute_group_diff(
    desired: set[Group],
    actual: set[Group],
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
    enable_group_creation: bool = False,
    enable_group_management: bool = False,
    ignore_unresolvable: frozenset[str] = frozenset(),
) -> GroupDiff:
    """Compute the group-management diff between desired and actual.

    Members on both sides are resolved before comparison so the two sides speak
    the same dialect (config-side has display names; UC-side has identifiers).
    Groups are matched by ``id`` when a desired group declares one (enabling
    renames), otherwise by display name. The two gates are orthogonal:

    - **Creation** (``enable_group_creation``): a desired group with no actual
      counterpart is created with its configured members (atomically) — it goes
      into ``groups_to_create``. Without the flag, a missing group is a fatal
      error only when management is on (directing the operator to pass
      ``--enable-group-creation``); with neither flag it is ignored.
    - **Management** (``enable_group_management``): an *existing* group's
      membership is reconciled — ``members_to_add = desired − actual`` and
      ``members_to_remove = actual − desired`` (an empty desired set removes all
      members). When the group was matched by id and its actual display name
      differs from config, the rename is recorded in ``groups_to_rename``. An
      existing group with an ``external_id`` (IdP-provisioned) is a fatal error (it
      can be neither renamed nor have its membership managed). Without the flag,
      existing groups are left untouched. A newly-created group is handled by
      creation only — management does not re-process it.

    A desired ``id`` that matches no account group, and a rename whose target name
    is already taken by a different group, are both fatal errors.

    ``ignore_unresolvable`` silences the resolution-failure warning for the
    listed actual-state member identifiers (the member is still dropped, so it is
    never removed).
    """
    actual_by_name = {g.display_name: g for g in actual}
    actual_by_id = {g.id: g for g in actual if g.id}

    diff = GroupDiff()
    for desired_group in desired:
        actual_group, ok = _find_actual_group(
            desired_group, actual_by_name, actual_by_id, change_logger
        )
        if not ok:
            continue  # bad id — fatal error already logged

        if actual_group is None:
            _handle_missing_group(
                desired_group, resolver, change_logger, ignore_unresolvable,
                enable_group_creation, enable_group_management, diff,
            )
            continue

        # Existing group: only reconciled (and renamed) under group management.
        if not enable_group_management:
            continue
        if actual_group.external_id:
            change_logger.log_error(ExecutionError(
                context=f"Configure GROUP {desired_group.display_name}",
                exception=OrchestratorError(
                    f"Group '{actual_group.display_name}' is externally managed "
                    "(IdP-provisioned) and cannot be configured by this engine."
                ),
            ))
            continue

        if not _emit_rename_if_needed(
            desired_group, actual_group, actual_by_name, diff, change_logger
        ):
            continue  # rename target collision — fatal, skip membership
        _reconcile_membership(
            desired_group, actual_group, resolver, change_logger,
            ignore_unresolvable, diff,
        )

    return diff
