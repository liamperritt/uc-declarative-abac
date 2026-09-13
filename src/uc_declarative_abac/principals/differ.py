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
    Scope,
    is_system_account_group,
)


def _in_scope(scope: Scope | None, name: str) -> bool:
    """Whether ``name`` is in ``scope``. ``None`` ⇒ unscoped (matches all) — the
    default that keeps the legacy enable-only behaviour unchanged."""
    return scope is None or scope.matches(name)


def groups_pending_creation(
    desired: set[Group],
    actual: set[Group],
    enable_group_creation: bool,
    creation_scope: Scope | None = None,
) -> set[str]:
    """Display names of configured groups that this run will create.

    A group is pending creation when creation is enabled, its display name is in
    the creation scope, it declares no ``id`` (a declared id means an existing group
    matched for rename — never a creation candidate), and no account group shares its
    name. Mirrors the set the differ places in ``GroupDiff.groups_to_create``, so the
    orchestrator can seed these names into the principal cache **before** the diff —
    letting a group's members that are themselves created this run resolve.
    """
    if not enable_group_creation:
        return set()
    actual_names = {g.display_name for g in actual}
    return {
        group.display_name
        for group in desired
        if not group.id
        and group.display_name not in actual_names
        and _in_scope(creation_scope, group.display_name)
    }


def _resolve_principals(
    principals: frozenset[Principal],
    context: str,
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
    ignore_unresolvable: frozenset[str] = frozenset(),
) -> frozenset[Principal]:
    """Resolve a set of (member or assumer) principals against the workspace.

    Principals that fail to resolve are logged (with ``context``) and dropped —
    consistent with the governed-tag assigners differ. Dropping (rather than aborting)
    means an unresolvable principal won't trigger a phantom add on every run.
    Actual-state (UC-side) principals route to a non-fatal warning (suppressed when the
    identifier is in ``ignore_unresolvable``); config-side principals route to a fatal
    error (see log_principal_resolution_failure). Shared by member and assumer
    reconciliation — the single resolution path for both."""
    resolved: set[Principal] = set()
    for principal in principals:
        try:
            resolved.add(resolver.resolve_principal(principal))
        except PrincipalValidationError as exc:
            log_principal_resolution_failure(
                change_logger,
                context,
                principal,
                exc,
                ignore_unresolvable,
            )
            continue
    return frozenset(resolved)


def _reconcile_membership(
    desired_group: Group,
    actual_group: Group,
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
    ignore_unresolvable: frozenset[str],
    diff: GroupDiff,
) -> None:
    """Compute member add/remove sets for a group, keyed by the desired (post-rename)
    display name so the executor targets the group by its new name.

    No-op when ``desired_group.members is None`` — membership is unmanaged and left
    untouched (nothing is fetched or reconciled). A supplied (possibly empty) member
    set is authoritative: ``to_add = desired − actual`` and
    ``to_remove = actual − desired`` (an empty desired set removes all). ``actual`` may
    carry ``None`` members for a group created this run; it is treated as empty."""
    if desired_group.members is None:
        return
    name = desired_group.display_name
    resolved_desired = _resolve_principals(
        desired_group.members,
        f"Resolve group member for GROUP {name}",
        resolver,
        change_logger,
        ignore_unresolvable,
    )
    resolved_actual = _resolve_principals(
        actual_group.members or frozenset(),
        f"Resolve group member for GROUP {name}",
        resolver,
        change_logger,
        ignore_unresolvable,
    )
    to_add = resolved_desired - resolved_actual
    to_remove = resolved_actual - resolved_desired
    if to_add:
        diff.members_to_add[name] = frozenset(to_add)
    if to_remove:
        diff.members_to_remove[name] = frozenset(to_remove)


def _reconcile_assumers(
    desired_group: Group,
    actual_group: Group,
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
    ignore_unresolvable: frozenset[str],
    diff: GroupDiff,
) -> None:
    """Compute the desired assumer set (the ``roles/group.assumer`` principals on the
    group's account access-control ruleset), keyed by the desired (post-rename) display
    name.

    No-op when ``desired_group.assumers is None`` — assumers are unmanaged and left
    untouched. Otherwise both sides are resolved and compared; when they match, nothing
    is emitted (idempotent). When they differ, the full resolved desired set lands in
    ``assumers_to_set`` (the executor read-modify-writes the ruleset to exactly this
    set, preserving other roles), and the add/remove deltas land in ``assumers_to_add``
    / ``assumers_to_remove`` for logging. Mirrors governed-tag assigner reconciliation.
    ``actual`` may carry ``None`` assumers for a group created this run; it is treated
    as empty."""
    if desired_group.assumers is None:
        return
    name = desired_group.display_name
    resolved_desired = _resolve_principals(
        desired_group.assumers,
        f"Resolve group assumer for GROUP {name}",
        resolver,
        change_logger,
        ignore_unresolvable,
    )
    resolved_actual = _resolve_principals(
        actual_group.assumers or frozenset(),
        f"Resolve group assumer for GROUP {name}",
        resolver,
        change_logger,
        ignore_unresolvable,
    )
    if resolved_desired == resolved_actual:
        return
    diff.assumers_to_set[name] = resolved_desired
    to_add = resolved_desired - resolved_actual
    to_remove = resolved_actual - resolved_desired
    if to_add:
        diff.assumers_to_add[name] = frozenset(to_add)
    if to_remove:
        diff.assumers_to_remove[name] = frozenset(to_remove)


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
            change_logger.log_error(
                ExecutionError(
                    context=f"Configure GROUP {desired_group.display_name}",
                    exception=OrchestratorError(
                        f"Group id '{desired_group.id}' (declared for "
                        f"'{desired_group.display_name}') does not exist in the account."
                    ),
                )
            )
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
    """Handle a desired group with no actual counterpart.

    With creation enabled the group is queued for creation **empty** (its
    members/assumers are applied by the management path, not at creation). Under
    management — for a group being created this run **or** an already-existing one that
    creation won't cover — its members and assumers are reconciled against an empty
    actual group, so a group provisioned this run gets its configured members/assumers.
    Under management without creation, a missing group is a fatal error directing the
    operator to ``--group-creation-scopes``; with neither gate it is silently ignored."""
    name = desired_group.display_name
    if enable_group_creation:
        diff.groups_to_create.add(name)
    elif enable_group_management:
        change_logger.log_error(
            ExecutionError(
                context=f"Configure GROUP {name}",
                exception=OrchestratorError(
                    f"Group '{name}' does not exist. Add it to "
                    "--group-creation-scopes to create it."
                ),
            )
        )
        return
    if enable_group_management:
        empty_actual = Group(
            display_name=name, members=frozenset(), assumers=frozenset()
        )
        _reconcile_membership(
            desired_group,
            empty_actual,
            resolver,
            change_logger,
            ignore_unresolvable,
            diff,
        )
        _reconcile_assumers(
            desired_group,
            empty_actual,
            resolver,
            change_logger,
            ignore_unresolvable,
            diff,
        )


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
        change_logger.log_error(
            ExecutionError(
                context=f"Configure GROUP {name}",
                exception=OrchestratorError(
                    f"Cannot rename group id '{desired_group.id}' to '{name}': another "
                    "group already uses that display name."
                ),
            )
        )
        return False
    diff.groups_to_rename.append(
        GroupRename(
            id=desired_group.id,
            old_display_name=actual_group.display_name,
            new_display_name=name,
        )
    )
    return True


def _diff_group_deletes(
    desired: set[Group],
    all_account_groups: set[Group],
    enable_deletion: bool,
    deletion_scope: Scope | None = None,
) -> set[Group]:
    """Account groups absent from config that should be deleted, when deletion is enabled.

    A group is a deletion candidate only when it is Databricks-managed and undeclared:
    its display name is not among the desired names AND its SCIM id (when present) is not
    among the desired ids — the id check protects a group pending a rename (config holds
    the new name, the account still the old one, matched by id) from being deleted.
    External / IdP-provisioned groups (``external_id`` set) and Databricks account system
    groups (``account users`` / ``account admins``) are never candidates.
    """
    if not enable_deletion:
        return set()
    desired_names = {g.display_name for g in desired}
    desired_ids = {g.id for g in desired if g.id}
    return {
        g
        for g in all_account_groups
        if g.display_name not in desired_names
        and not (g.id and g.id in desired_ids)
        and not g.external_id
        and not is_system_account_group(g.display_name)
        and _in_scope(deletion_scope, g.display_name)
    }


def compute_group_diff(
    desired: set[Group],
    actual: set[Group],
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
    enable_group_creation: bool = False,
    enable_group_management: bool = False,
    enable_group_deletion: bool = False,
    ignore_unresolvable: frozenset[str] = frozenset(),
    all_account_groups: set[Group] = frozenset(),
    creation_scope: Scope | None = None,
    management_scope: Scope | None = None,
    deletion_scope: Scope | None = None,
) -> GroupDiff:
    """Compute the group-management diff between desired and actual.

    Members and assumers on both sides are resolved before comparison so the two sides
    speak the same dialect (config-side has display names; UC-side has identifiers).
    Groups are matched by ``id`` when a desired group declares one (enabling renames),
    otherwise by display name. The gates are orthogonal:

    - **Creation** (``enable_group_creation``): a desired group with no actual
      counterpart is queued for creation **empty** in ``groups_to_create`` (a set of
      display names). Its configured members/assumers are applied by the management
      path, not at creation. Without the flag, a missing group is a fatal error only
      when management is on (directing the operator to pass ``--group-creation-scopes``);
      with neither flag it is ignored.
    - **Management** (``enable_group_management``): a group's members and assumers are
      reconciled — for **existing** groups and for groups created this run (whose actual
      state is treated as empty, so their configured members/assumers are all added).
      Members: ``members_to_add = desired − actual`` and ``members_to_remove = actual −
      desired`` (an empty desired set removes all); membership is a no-op when
      ``members`` is ``None`` (unmanaged). Assumers: the full desired set lands in
      ``assumers_to_set`` when it differs from actual (a no-op when ``assumers`` is
      ``None``). When the group was matched by id and its actual display name differs
      from config, the rename is recorded in ``groups_to_rename``. An existing group
      with an ``external_id`` (IdP-provisioned) may not have ``members`` supplied (fatal)
      and is never renamed, but its assumers are still reconciled. Without the flag,
      existing groups are left untouched.

    - **Deletion** (``enable_group_deletion``): every Databricks-managed account group in
      ``all_account_groups`` that is absent from config (by name and id) is queued for
      deletion in ``groups_to_delete``. External / IdP-provisioned and account system
      groups are excluded. Without the flag (or with an empty ``all_account_groups``), no
      group is deleted.

    A desired ``id`` that matches no account group, and a rename whose target name
    is already taken by a different group, are both fatal errors.

    ``ignore_unresolvable`` silences the resolution-failure warning for the listed
    actual-state member/assumer identifiers (the principal is still dropped, so it is
    never removed).

    ``creation_scope`` / ``management_scope`` / ``deletion_scope`` further restrict
    each gate to groups whose display name they match; ``None`` (the default)
    means unscoped, preserving the legacy enable-only behaviour.
    """
    actual_by_name = {g.display_name: g for g in actual}
    actual_by_id = {g.id: g for g in actual if g.id}

    diff = GroupDiff()
    diff.groups_to_delete = _diff_group_deletes(
        desired, all_account_groups, enable_group_deletion, deletion_scope
    )
    for desired_group in desired:
        # Per-group effective gates: a gate applies only when it is enabled AND
        # the group's display name is in its scope.
        name = desired_group.display_name
        grp_create = enable_group_creation and _in_scope(creation_scope, name)
        grp_manage = enable_group_management and _in_scope(management_scope, name)
        if not grp_create and not grp_manage:
            continue

        actual_group, ok = _find_actual_group(
            desired_group, actual_by_name, actual_by_id, change_logger
        )
        if not ok:
            continue  # bad id — fatal error already logged

        if actual_group is None:
            _handle_missing_group(
                desired_group,
                resolver,
                change_logger,
                ignore_unresolvable,
                grp_create,
                grp_manage,
                diff,
            )
            continue

        # Existing group: only reconciled (and renamed) under group management.
        if not grp_manage:
            continue

        # Externally-managed (IdP-provisioned) groups: their membership is owned by the
        # IdP, so a supplied ``members`` (authoritative) is a fatal error; they can be
        # neither renamed nor have their membership reconciled here. Their assumers may
        # still be managed, so fall through to assumer reconciliation only.
        if actual_group.external_id:
            if desired_group.members is not None:
                change_logger.log_error(
                    ExecutionError(
                        context=f"Configure GROUP {desired_group.display_name}",
                        exception=OrchestratorError(
                            f"Group '{actual_group.display_name}' is externally managed "
                            "(IdP-provisioned); its membership cannot be configured by "
                            "this engine. Remove 'members' (its assumers can still be "
                            "managed)."
                        ),
                    )
                )
                continue
            _reconcile_assumers(
                desired_group,
                actual_group,
                resolver,
                change_logger,
                ignore_unresolvable,
                diff,
            )
            continue

        if not _emit_rename_if_needed(
            desired_group, actual_group, actual_by_name, diff, change_logger
        ):
            continue  # rename target collision — fatal, skip membership
        _reconcile_membership(
            desired_group,
            actual_group,
            resolver,
            change_logger,
            ignore_unresolvable,
            diff,
        )
        _reconcile_assumers(
            desired_group,
            actual_group,
            resolver,
            change_logger,
            ignore_unresolvable,
            diff,
        )

    return diff
