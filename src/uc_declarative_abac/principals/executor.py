from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_declarative_abac.helpers import WorkspaceHelper
    from uc_declarative_abac.logger import ChangeLogger

from databricks.sdk.service.iam import GrantRule

from uc_declarative_abac.principals.resolver import principal_to_ruleset_string
from uc_declarative_abac.principals.state import (
    Group,
    GroupDiff,
    GroupRename,
    Principal,
)
from uc_declarative_abac.utils import (
    ExecutionError,
    OrchestratorError,
    parallel_for_each,
    prompt_delete_confirmation,
)

_logger = logging.getLogger("uc_declarative_abac")

# Account Access Control Proxy assumer role on account groups. Mirrors the constant in
# helpers/workspace.py — kept independently so the executor can build grant rules
# without importing private helpers.
_GROUP_ASSUMER_ROLE = "roles/group.assumer"


def _build_assumer_grant_rules(
    desired_assumers: frozenset[Principal],
    existing_grant_rules: list,
) -> list[GrantRule]:
    """Combine the desired assumers with any non-assumer grant rules already present on
    the rule set so that other roles are preserved. Mirrors the governed-tag assigner
    builder."""
    new_rules: list[GrantRule] = []
    for rule in existing_grant_rules or []:
        if rule.role == _GROUP_ASSUMER_ROLE:
            continue
        new_rules.append(
            GrantRule(role=rule.role, principals=list(rule.principals or []))
        )
    if desired_assumers:
        new_rules.append(
            GrantRule(
                role=_GROUP_ASSUMER_ROLE,
                principals=sorted(
                    principal_to_ruleset_string(p) for p in desired_assumers
                ),
            )
        )
    return new_rules


def _group_membership_error(group_name: str, error: Exception) -> Exception:
    """Augment a member add/remove failure with a clear remediation when it is a
    permission error.

    The account SCIM proxy returns ``PERMISSION_DENIED`` when the engine principal
    lacks the ``MANAGER`` role on the target group, with an opaque message (e.g.
    ``PERMISSION_DENIED: Requesting user '...' does not have securable_type:
    "group"``). Rewrite it into actionable guidance; pass other errors through
    unchanged."""
    if "PERMISSION_DENIED" in str(error):
        return OrchestratorError(
            f"Permission denied updating membership of group '{group_name}'. The "
            f"engine principal must be granted the 'MANAGER' role on this group to "
            f"add or remove its members. Original error: {error}"
        )
    return error


def _execute_creates(
    ws_helper: WorkspaceHelper,
    diff: GroupDiff,
    change_logger: ChangeLogger,
    dry_run: bool,
    max_workers: int,
) -> set[str]:
    """Create each group in groups_to_create (empty) via the account SCIM proxy.

    Groups are always created empty; their configured members and assumers are applied
    by the later management phases (member adds and assumer sets), which run after every
    group created this run exists and its SCIM id is registered — so a group whose
    members/assumers reference another group created this run can be linked. Per-group
    SDK creates run in parallel; logging, id registration and error capture run via
    ``on_complete`` on the main thread so progress streams to the operator. Returns the
    display names whose creation succeeded.
    """
    work_items = sorted(diff.groups_to_create)

    def worker(name: str) -> str | None:
        # Workers must not touch shared caches — id registration happens on the main
        # thread in on_complete.
        return ws_helper.create_group(name) if not dry_run else None

    def on_complete(name: str, result, error) -> None:
        if error is not None:
            change_logger.log_error(
                ExecutionError(
                    context=f"create_group({name})",
                    exception=error,
                )
            )
            return
        if not dry_run:
            ws_helper.register_created_group(name, result)
        change_logger.log_group_create(name)

    results = parallel_for_each(
        work_items,
        worker,
        max_workers=max_workers,
        on_complete=on_complete,
    )
    return {name for name, _result, error in results if error is None}


def _execute_renames(
    ws_helper: WorkspaceHelper,
    diff: GroupDiff,
    change_logger: ChangeLogger,
    dry_run: bool,
    max_workers: int,
) -> None:
    """Rename each group in groups_to_rename via the account SCIM proxy.

    Per-group SDK calls run in parallel; logging and error capture run via
    ``on_complete`` on the main thread. Renames run before member add/remove so
    the group carries its new display name before membership is reconciled.
    """
    work_items = sorted(diff.groups_to_rename, key=lambda r: r.new_display_name)

    def worker(rename: GroupRename) -> None:
        if not dry_run:
            ws_helper.rename_group(rename.id, rename.new_display_name)

    def on_complete(rename: GroupRename, _result, error) -> None:
        if error is not None:
            change_logger.log_error(
                ExecutionError(
                    context=f"rename_group({rename.old_display_name} -> "
                    f"{rename.new_display_name})",
                    exception=error,
                )
            )
            return
        change_logger.log_group_rename(
            rename.old_display_name,
            rename.new_display_name,
        )

    parallel_for_each(
        work_items,
        worker,
        max_workers=max_workers,
        on_complete=on_complete,
    )


def _execute_member_adds(
    ws_helper: WorkspaceHelper,
    diff: GroupDiff,
    change_logger: ChangeLogger,
    dry_run: bool,
    max_workers: int,
    skip_names: set[str],
) -> None:
    """Add members to each group in members_to_add via the account SCIM proxy.

    Covers existing groups and groups created this run (whose actual membership was
    treated as empty). Groups in ``skip_names`` — those whose create failed this run —
    are skipped, since they don't exist to add members to. Per-group SDK calls run in
    parallel; logging and error capture run via ``on_complete`` on the main thread.
    """
    work_items = sorted(
        (item for item in diff.members_to_add.items() if item[0] not in skip_names),
        key=lambda item: item[0],
    )

    def worker(item: tuple[str, frozenset]) -> None:
        name, members = item
        if not dry_run:
            ws_helper.add_group_members(name, members)

    def on_complete(item: tuple[str, frozenset], _result, error) -> None:
        name, members = item
        if error is not None:
            change_logger.log_error(
                ExecutionError(
                    context=f"add_group_members({name})",
                    exception=_group_membership_error(name, error),
                )
            )
            return
        change_logger.log_group_member_add(name, members)

    parallel_for_each(
        work_items,
        worker,
        max_workers=max_workers,
        on_complete=on_complete,
    )


def _execute_member_removes(
    ws_helper: WorkspaceHelper,
    diff: GroupDiff,
    change_logger: ChangeLogger,
    dry_run: bool,
    max_workers: int,
    skip_names: set[str],
) -> None:
    """Remove members from each group in members_to_remove via the account SCIM
    proxy.

    Groups in ``skip_names`` (failed creates this run) are skipped. Per-group SDK calls
    run in parallel; logging and error capture run via ``on_complete`` on the main
    thread.
    """
    work_items = sorted(
        (item for item in diff.members_to_remove.items() if item[0] not in skip_names),
        key=lambda item: item[0],
    )

    def worker(item: tuple[str, frozenset]) -> None:
        name, members = item
        if not dry_run:
            ws_helper.remove_group_members(name, members)

    def on_complete(item: tuple[str, frozenset], _result, error) -> None:
        name, members = item
        if error is not None:
            change_logger.log_error(
                ExecutionError(
                    context=f"remove_group_members({name})",
                    exception=_group_membership_error(name, error),
                )
            )
            return
        change_logger.log_group_member_remove(name, members)

    parallel_for_each(
        work_items,
        worker,
        max_workers=max_workers,
        on_complete=on_complete,
    )


def _execute_deletes(
    ws_helper: WorkspaceHelper,
    diff: GroupDiff,
    change_logger: ChangeLogger,
    dry_run: bool,
    force: bool,
    max_workers: int,
) -> None:
    """Delete each group in groups_to_delete, gated by interactive confirmation.

    Dry-run logs the would-delete list without prompting or executing. Otherwise the
    operator must confirm (unless ``force``); a decline aborts the whole run, matching
    governed-tag deletion. After confirmation, per-group SDK deletes run in parallel.
    """
    if not diff.groups_to_delete:
        return
    groups_sorted = sorted(diff.groups_to_delete, key=lambda g: g.display_name)
    if dry_run:
        for group in groups_sorted:
            change_logger.log_group_delete(group)
        return
    if not force and not prompt_delete_confirmation(
        [g.display_name for g in groups_sorted],
        "group",
        "This is irreversible and will delete these account groups and all their "
        "memberships.",
    ):
        _logger.info("Group deletion cancelled — aborting run.")
        sys.exit(1)

    def worker(group: Group) -> None:
        ws_helper.delete_group(group.id)

    def on_complete(group: Group, _result, error) -> None:
        if error is not None:
            change_logger.log_error(
                ExecutionError(
                    context=f"delete_group({group.display_name})",
                    exception=error,
                )
            )
            return
        change_logger.log_group_delete(group)

    parallel_for_each(
        groups_sorted,
        worker,
        max_workers=max_workers,
        on_complete=on_complete,
    )


def _execute_assumer_sets(
    ws_helper: WorkspaceHelper,
    diff: GroupDiff,
    change_logger: ChangeLogger,
    dry_run: bool,
    max_workers: int,
    skip_names: set[str],
) -> None:
    """Reconcile each group's assumers by read-modify-writing its account access-control
    rule set to exactly ``assumers_to_set[name]``.

    The current rule set is fetched (for its etag and to preserve non-assumer roles),
    then rewritten with the desired assumer principals — mirroring governed-tag assigner
    reconciliation. Covers existing groups and groups created this run (whose id was
    registered in the creates phase). Groups in ``skip_names`` (failed creates) are
    skipped. The add/remove deltas computed by the differ drive the log lines, so dry-run
    and real-run print the same output. Per-group calls run in parallel; logging and
    error capture run via ``on_complete`` on the main thread.
    """
    work_items = sorted(
        (item for item in diff.assumers_to_set.items() if item[0] not in skip_names),
        key=lambda item: item[0],
    )

    def worker(item: tuple[str, frozenset]) -> None:
        name, desired = item
        if dry_run:
            return
        group_id = ws_helper.get_group_id(name)
        if not group_id:
            raise OrchestratorError(f"Group id not cached for {name!r}")
        current = ws_helper.get_group_rule_set(group_id)
        new_rules = _build_assumer_grant_rules(desired, current.grant_rules or [])
        ws_helper.update_group_rule_set(
            group_id=group_id,
            etag=current.etag,
            grant_rules=new_rules,
        )

    def on_complete(item: tuple[str, frozenset], _result, error) -> None:
        name, _desired = item
        if error is not None:
            change_logger.log_error(
                ExecutionError(
                    context=f"update_group_rule_set({name})",
                    exception=error,
                )
            )
            return
        added = diff.assumers_to_add.get(name, frozenset())
        removed = diff.assumers_to_remove.get(name, frozenset())
        if added:
            change_logger.log_group_assumer_add(name, added)
        if removed:
            change_logger.log_group_assumer_remove(name, removed)

    parallel_for_each(
        work_items,
        worker,
        max_workers=max_workers,
        on_complete=on_complete,
    )


def execute_group_diff(
    ws_helper: WorkspaceHelper,
    diff: GroupDiff,
    change_logger: ChangeLogger,
    dry_run: bool = False,
    force: bool = False,
    max_parallel_changes: int = 1,
) -> None:
    """Apply a GroupDiff against the account via the account SCIM proxy.

    Groups are always created **empty** first (``ws_helper.create_group``, whose returned
    SCIM id is registered); their configured members and assumers are then applied by the
    management phases below — never at creation. This lets a group whose members/assumers
    reference other groups created this run be linked once every group exists. Renames of
    existing groups (``ws_helper.rename_group``) run next, then member adds/removes
    (``ws_helper.add_group_members`` / ``remove_group_members``) for existing groups and
    groups created this run, then assumer reconciliation (``ws_helper.update_group_rule_set``),
    then deletion of undeclared groups (``ws_helper.delete_group``, gated by interactive
    confirmation unless ``force``). Renames precede member/assumer ops so a group carries
    its new display name first; member/assumer ops follow creates so a group created this
    run has a registered id (a group whose create failed is skipped); deletes run last so
    no op targets a group being removed. Each phase forms one parallel batch (up to
    ``max_parallel_changes`` workers); dry-run forces sequential execution and skips the
    API calls. Each SDK exception is logged via ``change_logger.log_error`` and the batch
    continues.
    """
    workers = 1 if dry_run else max_parallel_changes
    created_names = _execute_creates(ws_helper, diff, change_logger, dry_run, workers)
    # Groups whose create was attempted this run but failed — skip their member/assumer
    # ops (they don't exist to target); the create failure is already logged.
    skip_names = diff.groups_to_create - created_names
    _execute_renames(ws_helper, diff, change_logger, dry_run, workers)
    _execute_member_adds(ws_helper, diff, change_logger, dry_run, workers, skip_names)
    _execute_member_removes(
        ws_helper, diff, change_logger, dry_run, workers, skip_names
    )
    _execute_assumer_sets(ws_helper, diff, change_logger, dry_run, workers, skip_names)
    _execute_deletes(ws_helper, diff, change_logger, dry_run, force, workers)
