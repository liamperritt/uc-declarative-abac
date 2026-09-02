from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_declarative_abac.helpers import WorkspaceHelper
    from uc_declarative_abac.logger import ChangeLogger

from uc_declarative_abac.principals.state import Group, GroupDiff, GroupRename
from uc_declarative_abac.utils import (
    ExecutionError,
    OrchestratorError,
    parallel_for_each,
    prompt_delete_confirmation,
)

_logger = logging.getLogger("uc_declarative_abac")


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

    Per-group SDK creates run in parallel; logging, id registration and error
    capture run via ``on_complete`` on the main thread so progress streams to the
    operator. Returns the display names whose creation succeeded — only those get
    their members added in the following phase (a failed create leaves no group to
    add members to).
    """
    work_items = sorted(diff.groups_to_create.items(), key=lambda item: item[0])

    def worker(item: tuple[str, frozenset]) -> str | None:
        # Create the group empty and return its new SCIM id; members are added in a
        # later phase (once every group created this run exists) so nested members
        # can be linked. Workers must not touch shared caches — id registration
        # happens on the main thread in on_complete.
        name, _members = item
        return ws_helper.create_group(name) if not dry_run else None

    def on_complete(item: tuple[str, frozenset], result, error) -> None:
        name, members = item
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
        change_logger.log_group_create(name, members)

    results = parallel_for_each(
        work_items,
        worker,
        max_workers=max_workers,
        on_complete=on_complete,
    )
    return {item[0] for item, _result, error in results if error is None}


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
) -> None:
    """Add members to each group in members_to_add via the account SCIM proxy.

    Per-group SDK calls run in parallel; logging and error capture run via
    ``on_complete`` on the main thread.
    """
    work_items = sorted(diff.members_to_add.items(), key=lambda item: item[0])

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
) -> None:
    """Remove members from each group in members_to_remove via the account SCIM
    proxy.

    Per-group SDK calls run in parallel; logging and error capture run via
    ``on_complete`` on the main thread.
    """
    work_items = sorted(diff.members_to_remove.items(), key=lambda item: item[0])

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


def _execute_created_group_member_adds(
    ws_helper: WorkspaceHelper,
    diff: GroupDiff,
    change_logger: ChangeLogger,
    dry_run: bool,
    max_workers: int,
    created_names: set[str],
) -> None:
    """Add members to the groups created this run, after every group exists.

    Newly-created groups are POSTed empty by ``_execute_creates``; their members —
    which may include other groups created this run — are added here, once each new
    group's SCIM id has been registered. Only groups in ``created_names`` (whose create
    succeeded) are processed. No success log line: the create entry already reported the
    intended members. Skipped entirely in dry-run (nothing was created).
    """
    if dry_run:
        return
    work_items = sorted(
        (
            item
            for item in diff.groups_to_create.items()
            if item[1] and item[0] in created_names
        ),
        key=lambda item: item[0],
    )

    def worker(item: tuple[str, frozenset]) -> None:
        name, members = item
        ws_helper.add_group_members(name, members)

    def on_complete(item: tuple[str, frozenset], _result, error) -> None:
        name, _members = item
        if error is not None:
            change_logger.log_error(
                ExecutionError(
                    context=f"add_group_members({name})",
                    exception=_group_membership_error(name, error),
                )
            )

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

    Group creation is two-phase: every group is created **empty** first
    (``ws_helper.create_group``, whose returned SCIM id is registered), then the
    created groups' members are added (``_execute_created_group_member_adds``). This
    ordering lets a configured group whose members include other groups created this
    run be linked once every group exists. Renames of existing groups
    (``ws_helper.rename_group``) run next, then member adds/removes for existing groups
    (``ws_helper.add_group_members`` / ``remove_group_members``), then deletion of
    undeclared groups (``ws_helper.delete_group``, gated by interactive confirmation
    unless ``force``). Renames precede existing-group member ops so a group carries its
    new display name before membership is reconciled; deletes run last so no membership
    op targets a group being removed. Each phase forms one parallel batch (up to
    ``max_parallel_changes`` workers); dry-run forces sequential execution and skips the
    API calls. Each SDK exception is logged via ``change_logger.log_error`` and the
    batch continues.
    """
    workers = 1 if dry_run else max_parallel_changes
    created_names = _execute_creates(ws_helper, diff, change_logger, dry_run, workers)
    _execute_created_group_member_adds(
        ws_helper, diff, change_logger, dry_run, workers, created_names
    )
    _execute_renames(ws_helper, diff, change_logger, dry_run, workers)
    _execute_member_adds(ws_helper, diff, change_logger, dry_run, workers)
    _execute_member_removes(ws_helper, diff, change_logger, dry_run, workers)
    _execute_deletes(ws_helper, diff, change_logger, dry_run, force, workers)
