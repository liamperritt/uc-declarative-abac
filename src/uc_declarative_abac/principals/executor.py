from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_declarative_abac.helpers import WorkspaceHelper
    from uc_declarative_abac.logger import ChangeLogger

from uc_declarative_abac.principals.state import GroupDiff, GroupRename
from uc_declarative_abac.utils import ExecutionError, OrchestratorError, parallel_for_each


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
) -> None:
    """Create each group in groups_to_create via the account SCIM proxy.

    Per-group SDK creates run in parallel; logging and error capture run via
    ``on_complete`` on the main thread so progress streams to the operator.
    """
    work_items = sorted(diff.groups_to_create.items(), key=lambda item: item[0])

    def worker(item: tuple[str, frozenset]) -> None:
        name, members = item
        if not dry_run:
            ws_helper.create_group(name, members)

    def on_complete(item: tuple[str, frozenset], _result, error) -> None:
        name, members = item
        if error is not None:
            change_logger.log_error(ExecutionError(
                context=f"create_group({name})", exception=error,
            ))
            return
        change_logger.log_group_create(name, members)

    parallel_for_each(
        work_items,
        worker,
        max_workers=max_workers,
        on_complete=on_complete,
    )


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
            change_logger.log_error(ExecutionError(
                context=f"rename_group({rename.old_display_name} -> "
                        f"{rename.new_display_name})",
                exception=error,
            ))
            return
        change_logger.log_group_rename(
            rename.old_display_name, rename.new_display_name,
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
            change_logger.log_error(ExecutionError(
                context=f"add_group_members({name})",
                exception=_group_membership_error(name, error),
            ))
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
            change_logger.log_error(ExecutionError(
                context=f"remove_group_members({name})",
                exception=_group_membership_error(name, error),
            ))
            return
        change_logger.log_group_member_remove(name, members)

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
    max_parallel_changes: int = 1,
) -> None:
    """Apply a GroupDiff against the account via the account SCIM proxy.

    Creates groups first (``ws_helper.create_group``, with their members), then
    renames existing groups (``ws_helper.rename_group``), then adds members to and
    removes members from existing groups (``ws_helper.add_group_members`` /
    ``remove_group_members``). Renames precede member ops so a group carries its new
    display name before membership is reconciled. Each phase forms one parallel
    batch (up to ``max_parallel_changes`` workers); dry-run forces sequential
    execution and skips the API calls. Each SDK exception is logged via
    ``change_logger.log_error`` and the batch continues.
    """
    workers = 1 if dry_run else max_parallel_changes
    _execute_creates(ws_helper, diff, change_logger, dry_run, workers)
    _execute_renames(ws_helper, diff, change_logger, dry_run, workers)
    _execute_member_adds(ws_helper, diff, change_logger, dry_run, workers)
    _execute_member_removes(ws_helper, diff, change_logger, dry_run, workers)
