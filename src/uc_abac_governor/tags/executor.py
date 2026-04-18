from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_abac_governor.helpers.unity_catalog import UnityCatalogHelper
    from uc_abac_governor.logger import ChangeLogger

from uc_abac_governor.helpers import quote_securable as quote_securable
from uc_abac_governor.tags.state import SecurableTag, TagDiff
from uc_abac_governor.types import ExecutionError, SecurableType


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


def execute_tag_diff(
    uc_helper: UnityCatalogHelper,
    diff: TagDiff,
    change_logger: ChangeLogger,
    dry_run: bool = False,
) -> list[str]:
    """Generate and execute ALTER SET/UNSET TAGS SQL from a TagDiff.

    Batches tags per securable where possible.
    Logs each change after successful execution (or unconditionally in dry-run mode).
    Returns the list of SQL statements executed (empty in dry-run mode).
    """
    statements: list[str] = []

    # SET TAGS for adds and updates combined
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

    # UNSET TAGS for removes
    for (sec_type, sec_name), tags in sorted(_group_by_securable(diff.to_remove).items()):
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
