from __future__ import annotations

from typing import TYPE_CHECKING

from databricks.sdk.service.tags import TagPolicy, Value

if TYPE_CHECKING:
    from uc_abac_governor.helpers.workspace import WorkspaceHelper
    from uc_abac_governor.logger import ChangeLogger

from uc_abac_governor.governed_tags.state import GovernedTag, GovernedTagDiff
from uc_abac_governor.types import ExecutionError


def _to_tag_policy(gt: GovernedTag) -> TagPolicy:
    """Convert a desired GovernedTag into the SDK's TagPolicy request body."""
    return TagPolicy(
        tag_key=gt.name,
        description=gt.comment or None,
        values=[Value(name=v) for v in sorted(gt.allowed_values)],
    )


def _compute_update_mask(new: GovernedTag, old: GovernedTag | None) -> str:
    """Return the comma-separated list of TagPolicy fields that differ between old and new."""
    fields: list[str] = []
    if old is None or new.comment != old.comment:
        fields.append("description")
    if old is None or new.allowed_values != old.allowed_values:
        fields.append("values")
    return ",".join(fields)


def _execute_creates(
    ws_helper: WorkspaceHelper,
    diff: GovernedTagDiff,
    change_logger: ChangeLogger,
    dry_run: bool,
) -> None:
    """Create each governed tag in to_create via the SDK. Logs per-tag and collects errors."""
    for gt in sorted(diff.to_create, key=lambda g: g.name):
        if not dry_run:
            try:
                ws_helper.create_tag_policy(_to_tag_policy(gt))
            except Exception as exc:
                change_logger.log_error(ExecutionError(
                    context=f"create_tag_policy({gt.name})", exception=exc,
                ))
                continue
        change_logger.log_governed_tag_create(gt)


def _execute_updates(
    ws_helper: WorkspaceHelper,
    diff: GovernedTagDiff,
    change_logger: ChangeLogger,
    dry_run: bool,
) -> None:
    """Update each governed tag in to_update, computing a precise update_mask per tag."""
    for gt in sorted(diff.to_update, key=lambda g: g.name):
        old = diff.old_values.get(gt.name)
        update_mask = _compute_update_mask(gt, old)
        if not update_mask:
            continue
        if not dry_run:
            try:
                ws_helper.update_tag_policy(
                    tag_key=gt.name,
                    policy=_to_tag_policy(gt),
                    update_mask=update_mask,
                )
            except Exception as exc:
                change_logger.log_error(ExecutionError(
                    context=f"update_tag_policy({gt.name})", exception=exc,
                ))
                continue
        change_logger.log_governed_tag_update(gt, old)


def execute_governed_tag_diff(
    ws_helper: WorkspaceHelper,
    diff: GovernedTagDiff,
    change_logger: ChangeLogger,
    dry_run: bool = False,
) -> None:
    """Apply a GovernedTagDiff against the account via the Databricks SDK.

    Creates are issued first, then updates. Each SDK exception is logged via
    ``change_logger.log_error`` and the batch continues; aggregate failures are
    surfaced by the governor.
    """
    _execute_creates(ws_helper, diff, change_logger, dry_run)
    _execute_updates(ws_helper, diff, change_logger, dry_run)
