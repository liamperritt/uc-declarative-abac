from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_declarative_abac.helpers import WorkspaceHelper
    from uc_declarative_abac.logger import ChangeLogger

from uc_declarative_abac.principals.state import GroupDiff
from uc_declarative_abac.utils import ExecutionError, parallel_for_each


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
                context=f"add_group_members({name})", exception=error,
            ))
            return
        change_logger.log_group_member_add(name, members)

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

    Creates groups first (``ws_helper.create_group``), then adds members to
    existing groups (``ws_helper.add_group_members``). Each phase forms one
    parallel batch (up to ``max_parallel_changes`` workers); dry-run forces
    sequential execution and skips the API calls. Each SDK exception is logged
    via ``change_logger.log_error`` and the batch continues.
    """
    workers = 1 if dry_run else max_parallel_changes
    _execute_creates(ws_helper, diff, change_logger, dry_run, workers)
    _execute_member_adds(ws_helper, diff, change_logger, dry_run, workers)
