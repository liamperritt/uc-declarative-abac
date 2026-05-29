from __future__ import annotations

import logging
import sys
from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_declarative_abac.helpers.unity_catalog import UnityCatalogHelper
    from uc_declarative_abac.logger import ChangeLogger

from uc_declarative_abac.utils import ExecutionError, InteractiveConfirmationRequiredError, quote_securable as quote_securable
from uc_declarative_abac.tags.state import SecurableTag, TagDiff
from uc_declarative_abac.types import SecurableType

_logger = logging.getLogger("uc_declarative_abac")


def _format_tag_entry(tag: SecurableTag) -> str:
    """Format a single tag for use inside a SET TAGS clause."""
    if tag.tag_value is None:
        return f"'{tag.tag_name}'"
    return f"'{tag.tag_name}' = '{tag.tag_value}'"


def _build_set_tags_sql(
    securable_type: SecurableType,
    securable_full_name: str,
    tags: list[SecurableTag],
) -> str:
    """Build an ALTER SET TAGS statement for a batch of tags on one securable."""
    entries = ", ".join(sorted(_format_tag_entry(t) for t in tags))
    if securable_type == SecurableType.COLUMN:
        parts = securable_full_name.split(".")
        table_name = ".".join(parts[:3])
        column_name = parts[3]
        return f"ALTER TABLE {quote_securable(table_name)} ALTER COLUMN `{column_name}` SET TAGS ({entries})"
    quoted = quote_securable(securable_full_name)
    return f"ALTER {securable_type.value} {quoted} SET TAGS ({entries})"


def _build_unset_tags_sql(
    securable_type: SecurableType,
    securable_full_name: str,
    tags: list[SecurableTag],
) -> str:
    """Build an ALTER UNSET TAGS statement for a batch of tags on one securable."""
    entries = ", ".join(sorted(f"'{t.tag_name}'" for t in tags))
    if securable_type == SecurableType.COLUMN:
        parts = securable_full_name.split(".")
        table_name = ".".join(parts[:3])
        column_name = parts[3]
        return f"ALTER TABLE {quote_securable(table_name)} ALTER COLUMN `{column_name}` UNSET TAGS ({entries})"
    quoted = quote_securable(securable_full_name)
    return f"ALTER {securable_type.value} {quoted} UNSET TAGS ({entries})"


def _group_by_securable(
    tags: set[SecurableTag],
) -> dict[tuple[SecurableType, str], list[SecurableTag]]:
    """Group tags by (securable_type, securable_full_name)."""
    groups: dict[tuple[SecurableType, str], list[SecurableTag]] = defaultdict(list)
    for tag in tags:
        groups[(tag.securable_type, tag.securable_full_name)].append(tag)
    return groups


def _partition_governed_removes(
    removes: set[SecurableTag],
    governed_tag_names: set[str],
) -> tuple[set[SecurableTag], set[SecurableTag]]:
    """Split removals into (governed, non-governed) based on tag_name membership."""
    governed: set[SecurableTag] = set()
    nongoverned: set[SecurableTag] = set()
    for tag in removes:
        if tag.tag_name in governed_tag_names:
            governed.add(tag)
        else:
            nongoverned.add(tag)
    return governed, nongoverned


def _prompt_remove_confirmation(removes: list[SecurableTag]) -> bool:
    """Show the list of governed-tag removals and require interactive confirmation.

    Accepts ``y`` or ``yes`` (case-insensitive) as affirmative; anything else skips
    the governed subset. Re-raises ``EOFError`` (e.g. non-TTY input stream) as
    ``InteractiveConfirmationRequiredError`` so CI contexts get a clear "set --force"
    directive instead of a silent skip.
    """
    print(f"\nAbout to remove {len(removes)} governed tag(s) from securables:")
    for tag in removes:
        print(f"  - {tag.securable_type.value} {tag.securable_full_name}  {tag.tag_name}")
    print()
    try:
        response = input(
            "Confirm removing these governed tags from the listed securables [y/N]: "
        )
    except EOFError as exc:
        raise InteractiveConfirmationRequiredError(
            "Cannot prompt for confirmation in a non-interactive context. "
            "Set --force to auto-confirm destructive actions."
        ) from exc
    return response.strip().lower() in {"y", "yes"}


def _apply_set_tags(
    uc_helper: UnityCatalogHelper,
    diff: TagDiff,
    change_logger: ChangeLogger,
    dry_run: bool,
) -> list[str]:
    """Apply adds + updates via ALTER SET TAGS. Returns the executed statements."""
    statements: list[str] = []
    set_tags = diff.to_add | diff.to_update
    for (sec_type, sec_name), tags in sorted(_group_by_securable(set_tags).items()):
        if not dry_run:
            stmt = _build_set_tags_sql(sec_type, sec_name, tags)
            try:
                uc_helper.execute_sql(stmt)
            except Exception as exc:
                change_logger.log_error(ExecutionError(context=stmt, exception=exc))
                continue
            statements.append(stmt)
        for tag in tags:
            if tag in diff.to_add:
                change_logger.log_tag_add(tag)
            else:
                change_logger.log_tag_update(tag, diff.old_values.get(
                    (tag.securable_type, tag.securable_full_name, tag.tag_name)
                ))
    return statements


def _apply_unset_tags(
    uc_helper: UnityCatalogHelper,
    removes: set[SecurableTag],
    change_logger: ChangeLogger,
    dry_run: bool,
) -> list[str]:
    """Apply a set of removals via ALTER UNSET TAGS. Returns the executed statements."""
    statements: list[str] = []
    for (sec_type, sec_name), tags in sorted(_group_by_securable(removes).items()):
        if not dry_run:
            stmt = _build_unset_tags_sql(sec_type, sec_name, tags)
            try:
                uc_helper.execute_sql(stmt)
            except Exception as exc:
                change_logger.log_error(ExecutionError(context=stmt, exception=exc))
                continue
            statements.append(stmt)
        for tag in tags:
            change_logger.log_tag_remove(tag)
    return statements


def _confirm_governed_removes_or_exit(
    governed_removes: set[SecurableTag],
    dry_run: bool,
    force: bool,
) -> None:
    """Gate governed-tag removals on interactive confirmation.

    - Dry-run: always proceeds so the removal is shown in the would-do output.
    - ``force=True``: always proceeds without prompting.
    - Otherwise: prompts the operator; rejection aborts the whole run via
      ``sys.exit(1)``. A non-TTY input stream in a non-forced context raises
      ``InteractiveConfirmationRequiredError``.
    """
    if not governed_removes or dry_run or force:
        return
    sorted_removes = sorted(
        governed_removes,
        key=lambda t: (t.securable_type.value, t.securable_full_name, t.tag_name),
    )
    if _prompt_remove_confirmation(sorted_removes):
        return
    _logger.info("Governed tag removal cancelled — aborting run.")
    sys.exit(1)


def execute_tag_diff(
    uc_helper: UnityCatalogHelper,
    diff: TagDiff,
    change_logger: ChangeLogger,
    governed_tag_names: set[str] | None = None,
    dry_run: bool = False,
    force: bool = False,
) -> list[str]:
    """Generate and execute ALTER SET/UNSET TAGS SQL from a TagDiff.

    Batches tags per securable where possible.
    Logs each change after successful execution (or unconditionally in dry-run mode).
    Returns the list of SQL statements executed (empty in dry-run mode).

    Removals whose ``tag_name`` is in ``governed_tag_names`` are gated by an
    interactive confirmation that lists every governed removal across every
    securable. ``force=True`` bypasses the prompt; ``dry_run=True`` skips it
    (and the SQL). Rejection skips only the governed subset — non-governed
    removals and all adds/updates still apply.
    """
    governed_keys = governed_tag_names or set()
    statements: list[str] = []

    statements.extend(_apply_set_tags(uc_helper, diff, change_logger, dry_run))

    governed_removes, nongoverned_removes = _partition_governed_removes(
        diff.to_remove, governed_keys,
    )
    statements.extend(_apply_unset_tags(uc_helper, nongoverned_removes, change_logger, dry_run))
    _confirm_governed_removes_or_exit(governed_removes, dry_run, force)
    statements.extend(_apply_unset_tags(uc_helper, governed_removes, change_logger, dry_run))

    return statements
