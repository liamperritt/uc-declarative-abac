from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING

from databricks.sdk.service.tags import TagPolicy, Value

if TYPE_CHECKING:
    from uc_abac_governor.helpers.workspace import WorkspaceHelper
    from uc_abac_governor.logger import ChangeLogger

from uc_abac_governor.governed_tags.state import GovernedTag, GovernedTagDiff
from uc_abac_governor.types import ExecutionError, InteractiveConfirmationRequiredError

_logger = logging.getLogger("uc_abac_governor")


def _to_tag_policy(gt: GovernedTag) -> TagPolicy:
    """Convert a desired GovernedTag into the SDK's TagPolicy request body."""
    return TagPolicy(
        tag_key=gt.name,
        description=gt.description or None,
        values=[Value(name=v) for v in sorted(gt.allowed_values)],
    )


def _compute_update_mask(new: GovernedTag, old: GovernedTag | None) -> str:
    """Return the comma-separated list of TagPolicy fields that differ between old and new."""
    fields: list[str] = []
    if old is None or new.description != old.description:
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


def _prompt_delete_confirmation(tags: list[GovernedTag]) -> bool:
    """Show the list of tags slated for deletion and require interactive confirmation.

    Accepts ``y`` or ``yes`` (case-insensitive) as affirmative; anything else aborts.
    Re-raises ``EOFError`` (e.g. non-TTY input stream) as
    ``InteractiveConfirmationRequiredError`` so CI contexts get a clear "set --force"
    directive instead of a silent skip.
    """
    print(f"\nAbout to delete {len(tags)} governed tag(s):")
    for gt in tags:
        print(f"  - {gt.name}")
    print()
    try:
        response = input(
            "This is irreversible and will orphan any objects tagged with these keys. "
            "Confirm [y/N]: "
        )
    except EOFError as exc:
        raise InteractiveConfirmationRequiredError(
            "Cannot prompt for confirmation in a non-interactive context. "
            "Set --force to auto-confirm destructive actions."
        ) from exc
    return response.strip().lower() in {"y", "yes"}


def _execute_deletes(
    ws_helper: WorkspaceHelper,
    diff: GovernedTagDiff,
    change_logger: ChangeLogger,
    dry_run: bool,
    force: bool,
) -> None:
    """Delete each governed tag in to_delete, gated by interactive confirmation.

    - Dry-run logs the would-delete list and returns without prompting or calling
      the SDK.
    - Otherwise, if ``force`` is False, prompts the operator; rejection aborts
      the delete phase (creates/updates already ran). A non-TTY input stream in
      a non-forced context raises ``InteractiveConfirmationRequiredError``.
    - After confirmation (or with ``force=True``), each SDK delete failure is
      logged via ``change_logger.log_error`` and the batch continues.
    """
    if not diff.to_delete:
        return
    tags_sorted = sorted(diff.to_delete, key=lambda g: g.name)
    if dry_run:
        for gt in tags_sorted:
            change_logger.log_governed_tag_delete(gt)
        return
    if not force and not _prompt_delete_confirmation(tags_sorted):
        _logger.info("Governed tag deletion cancelled — aborting run.")
        sys.exit(1)
    for gt in tags_sorted:
        try:
            ws_helper.delete_tag_policy(gt.name)
        except Exception as exc:
            change_logger.log_error(ExecutionError(
                context=f"delete_tag_policy({gt.name})", exception=exc,
            ))
            continue
        change_logger.log_governed_tag_delete(gt)


def execute_governed_tag_diff(
    ws_helper: WorkspaceHelper,
    diff: GovernedTagDiff,
    change_logger: ChangeLogger,
    dry_run: bool = False,
    force: bool = False,
) -> None:
    """Apply a GovernedTagDiff against the account via the Databricks SDK.

    Creates run first, then updates, then deletes. Delete is gated by interactive
    confirmation (or ``force=True``); see ``_execute_deletes``. Each SDK exception
    during creates/updates/deletes is logged via ``change_logger.log_error`` and
    the batch continues; aggregate failures are surfaced by the governor.
    """
    _execute_creates(ws_helper, diff, change_logger, dry_run)
    _execute_updates(ws_helper, diff, change_logger, dry_run)
    _execute_deletes(ws_helper, diff, change_logger, dry_run, force)
