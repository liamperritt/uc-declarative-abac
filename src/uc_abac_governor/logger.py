from __future__ import annotations

import logging

from uc_abac_governor.privileges.state import PrivilegeDiff, SecurablePrivilege
from uc_abac_governor.tags.state import SecurableTag, TagDiff
from uc_abac_governor.types import ExecutionError, Principal, SecurableType

_default_logger = logging.getLogger("uc_abac_governor")

# Column widths for aligned output
_TYPE_WIDTH = 7  # len("CATALOG") — longest SecurableType value
_NAME_WIDTH = 36


def _format_tag(tag_name: str, tag_value: str | None) -> str:
    """Format a tag as "'name'='value'" or just 'name' when valueless."""
    return f"{tag_name}='{tag_value or ''}'"


def _format_change_line(symbol: str, securable_type: str, full_name: str, action: str) -> str:
    """Format a single change line with columnar alignment.

    Example:  + CATALOG my_catalog                  ADDED tag env='prod'
    """
    return f"  {symbol} {securable_type:<{_TYPE_WIDTH}} {full_name:<{_NAME_WIDTH}} {action}"


class ChangeLogger:
    """Context manager for logging governance changes.

    Provides domain-specific logging methods for tags and privileges.
    In dry-run mode, prepends [DRY RUN] to all INFO messages.
    Logs a summary of all changes on exit.
    """

    def __init__(
        self,
        dry_run: bool = False,
        logger: logging.Logger | None = None,
    ) -> None:
        self._logger = logger or _default_logger
        self._dry_run = dry_run
        self._tags_added = 0
        self._tags_updated = 0
        self._tags_removed = 0
        self._privileges_granted = 0
        self._privileges_revoked = 0
        self._errors: list[ExecutionError] = []

    @property
    def errors(self) -> list[ExecutionError]:
        """Return all collected execution errors."""
        return list(self._errors)

    @property
    def has_errors(self) -> bool:
        """Return True if any execution errors have been collected."""
        return len(self._errors) > 0

    def log_error(self, error: ExecutionError) -> None:
        """Collect an execution error (displayed later via log_errors_section)."""
        self._errors.append(error)
        self._logger.error(f"  ! Error: {error.context}: {error.exception}")

    def log_summary(self) -> None:
        """Log a summary of all changes recorded so far."""
        self._logger.info("")
        self._logger.info(f"Summary: {self._build_summary()}")

    # ------------------------------------------------------------------
    # Banner and section headers
    # ------------------------------------------------------------------

    def log_banner(self) -> None:
        """Log the opening banner."""
        title = "UC ABAC Governor (dry run)" if self._dry_run else "UC ABAC Governor"
        self._logger.info("")
        self._logger.info(title)
        self._logger.info("=" * len(title))
        self._logger.info("")

    def log_section_header(self, name: str) -> None:
        """Log a section header with underline."""
        suffix = " (dry run)" if self._dry_run else ""
        header = f"{name}{suffix}"
        self._logger.info(header)
        self._logger.info("-" * len(header))

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------

    def _log_info(self, message: str) -> None:
        """Log an INFO message."""
        self._logger.info(message)

    # ------------------------------------------------------------------
    # Tag logging
    # ------------------------------------------------------------------

    def log_tag_add(self, tag: SecurableTag) -> None:
        """Log a tag being added to a securable."""
        self._tags_added += 1
        action_verb = "Add" if self._dry_run else "Added"
        display = _format_tag(tag.tag_name, tag.tag_value)
        self._log_info(_format_change_line(
            "+", tag.securable_type.value, tag.securable_full_name,
            f"{action_verb} tag: {display}",
        ))

    def log_tag_update(self, tag: SecurableTag, old_value: str | None) -> None:
        """Log a tag value being updated on a securable."""
        self._tags_updated += 1
        action_verb = "Update" if self._dry_run else "Updated"
        old_display = _format_tag(tag.tag_name, old_value)
        new_display = _format_tag(tag.tag_name, tag.tag_value)
        self._log_info(_format_change_line(
            "~", tag.securable_type.value, tag.securable_full_name,
            f"{action_verb} tag: {old_display} -> {new_display}",
        ))

    def log_tag_remove(self, tag: SecurableTag) -> None:
        """Log a tag being removed from a securable."""
        self._tags_removed += 1
        action_verb = "Remove" if self._dry_run else "Removed"
        self._log_info(_format_change_line(
            "-", tag.securable_type.value, tag.securable_full_name,
            f"{action_verb} tag: {tag.tag_name}",
        ))

    # ------------------------------------------------------------------
    # Privilege logging
    # ------------------------------------------------------------------

    def _principal_name(self, principal: object) -> str:
        """Return the display name for a principal (str or Principal object)."""
        if isinstance(principal, Principal):
            return principal.name
        return str(principal)

    def log_grant(self, privilege: SecurablePrivilege) -> None:
        """Log a privilege being granted."""
        self._privileges_granted += 1
        action_verb = "Grant" if self._dry_run else "Granted"
        name = self._principal_name(privilege.principal)
        self._log_info(_format_change_line(
            "+", privilege.securable_type.value, privilege.securable_full_name,
            f"{action_verb} {privilege.privilege_type.value.upper()} to '{name}'",
        ))

    def log_revoke(self, privilege: SecurablePrivilege) -> None:
        """Log a privilege being revoked."""
        self._privileges_revoked += 1
        action_verb = "Revoke" if self._dry_run else "Revoked"
        name = self._principal_name(privilege.principal)
        self._log_info(_format_change_line(
            "-", privilege.securable_type.value, privilege.securable_full_name,
            f"{action_verb} {privilege.privilege_type.value.upper()} from '{name}'",
        ))

    # ------------------------------------------------------------------
    # Diff-level convenience methods
    # ------------------------------------------------------------------

    def log_tag_changes(self, diff: TagDiff) -> None:
        """Log all tag changes from a TagDiff under a Tags section header."""
        has_changes = diff.to_add or diff.to_update or diff.to_remove
        if has_changes:
            self.log_section_header("Tags")

        sort_key = lambda t: (t.securable_type.value, t.securable_full_name)
        for tag in sorted(diff.to_add, key=sort_key):
            self.log_tag_add(tag)
        for tag in sorted(diff.to_update, key=sort_key):
            old_value = diff.old_values.get(
                (tag.securable_type, tag.securable_full_name, tag.tag_name)
            )
            self.log_tag_update(tag, old_value)
        for tag in sorted(diff.to_remove, key=sort_key):
            self.log_tag_remove(tag)

        if has_changes:
            self._logger.info("")

    def log_privilege_changes(self, diff: PrivilegeDiff) -> None:
        """Log all privilege changes from a PrivilegeDiff under a Privileges section header."""
        has_changes = diff.to_grant or diff.to_revoke
        if has_changes:
            self.log_section_header("Privileges")

        sort_key = lambda p: (p.securable_type.value, p.securable_full_name)
        for priv in sorted(diff.to_grant, key=sort_key):
            self.log_grant(priv)
        for priv in sorted(diff.to_revoke, key=sort_key):
            self.log_revoke(priv)

        if has_changes:
            self._logger.info("")

    def log_errors_section(self) -> None:
        """Log collected errors as a dedicated section."""
        if not self._errors:
            return
        self.log_section_header("Errors")
        for error in self._errors:
            self._logger.info(f"  ! {error.context}: {error.exception}")
        self._logger.info("")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def _build_summary(self) -> str:
        """Build exit summary string with non-zero counts only."""
        if self._dry_run:
            return self._build_dry_run_summary()
        return self._build_normal_summary()

    def _build_normal_summary(self) -> str:
        tag_parts: list[str] = []
        if self._tags_added:
            tag_parts.append(f"{self._tags_added} added")
        if self._tags_updated:
            tag_parts.append(f"{self._tags_updated} updated")
        if self._tags_removed:
            tag_parts.append(f"{self._tags_removed} removed")

        priv_parts: list[str] = []
        if self._privileges_granted:
            priv_parts.append(f"{self._privileges_granted} granted")
        if self._privileges_revoked:
            priv_parts.append(f"{self._privileges_revoked} revoked")

        sections: list[str] = []
        if tag_parts:
            sections.append("Tags: " + ", ".join(tag_parts))
        if priv_parts:
            sections.append("Privileges: " + ", ".join(priv_parts))
        if self._errors:
            sections.append(f"Errors: {len(self._errors)} failed")

        return " | ".join(sections) if sections else "No changes needed — all in sync"

    def _build_dry_run_summary(self) -> str:
        tag_parts: list[str] = []
        if self._tags_added:
            tag_parts.append(f"{self._tags_added} to add")
        if self._tags_updated:
            tag_parts.append(f"{self._tags_updated} to update")
        if self._tags_removed:
            tag_parts.append(f"{self._tags_removed} to remove")

        priv_parts: list[str] = []
        if self._privileges_granted:
            priv_parts.append(f"{self._privileges_granted} to grant")
        if self._privileges_revoked:
            priv_parts.append(f"{self._privileges_revoked} to revoke")

        sections: list[str] = []
        if tag_parts:
            sections.append("Tags: " + ", ".join(tag_parts))
        if priv_parts:
            sections.append("Privileges: " + ", ".join(priv_parts))

        if sections:
            return " | ".join(sections) + " (dry run — no changes applied)"
        return "No changes needed (dry run — no changes applied)"
