from __future__ import annotations

import logging

from uc_governor.privileges.state import PrivilegeDiff, SecurablePrivilege
from uc_governor.tags.state import SecurableTag, TagDiff
from uc_governor.types import ExecutionError

_default_logger = logging.getLogger("uc_governor")


def _format_tag(tag_name: str, tag_value: str | None) -> str:
    """Format a tag as 'name=value' or just 'name' when valueless."""
    if tag_value is None:
        return tag_name
    return f"{tag_name}={tag_value}"


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
        """Log and collect an execution error."""
        self._errors.append(error)
        self._log_info(f"[ERROR] {error.context}: {error.exception}")

    def log_summary(self) -> None:
        """Log a summary of all changes recorded so far."""
        self._log_info(self._build_summary())

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------

    def _log_info(self, message: str) -> None:
        """Log an INFO message, prepending [DRY RUN] when in dry-run mode."""
        if self._dry_run:
            message = f"[DRY RUN] {message}"
        self._logger.info(message)

    # ------------------------------------------------------------------
    # Tag logging
    # ------------------------------------------------------------------

    def log_tag_add(self, tag: SecurableTag) -> None:
        """Log a tag being added to a securable."""
        self._tags_added += 1
        prefix = "[ADD]" if self._dry_run else "[ADDED]"
        display = _format_tag(tag.tag_name, tag.tag_value)
        self._log_info(
            f"{prefix} {tag.securable_type.value} {tag.securable_full_name} {display}"
        )

    def log_tag_update(self, tag: SecurableTag, old_value: str | None) -> None:
        """Log a tag value being updated on a securable."""
        self._tags_updated += 1
        prefix = "[UPDATE]" if self._dry_run else "[UPDATED]"
        self._log_info(
            f"{prefix} {tag.securable_type.value} {tag.securable_full_name} "
            f"{tag.tag_name} {old_value} -> {tag.tag_value}"
        )

    def log_tag_remove(self, tag: SecurableTag) -> None:
        """Log a tag being removed from a securable."""
        self._tags_removed += 1
        prefix = "[REMOVE]" if self._dry_run else "[REMOVED]"
        self._log_info(
            f"{prefix} {tag.securable_type.value} {tag.securable_full_name} {tag.tag_name}"
        )

    # ------------------------------------------------------------------
    # Privilege logging
    # ------------------------------------------------------------------

    def log_grant(self, privilege: SecurablePrivilege) -> None:
        """Log a privilege being granted."""
        self._privileges_granted += 1
        prefix = "[GRANT]" if self._dry_run else "[GRANTED]"
        self._log_info(
            f"{prefix} {privilege.privilege_type} on "
            f"{privilege.securable_type.value} {privilege.securable_full_name} "
            f"to {privilege.principal}"
        )

    def log_revoke(self, privilege: SecurablePrivilege) -> None:
        """Log a privilege being revoked."""
        self._privileges_revoked += 1
        prefix = "[REVOKE]" if self._dry_run else "[REVOKED]"
        self._log_info(
            f"{prefix} {privilege.privilege_type} on "
            f"{privilege.securable_type.value} {privilege.securable_full_name} "
            f"from {privilege.principal}"
        )

    # ------------------------------------------------------------------
    # Diff-level convenience methods
    # ------------------------------------------------------------------

    def log_tag_changes(self, diff: TagDiff) -> None:
        """Log all tag changes from a TagDiff."""
        for tag in diff.to_add:
            self.log_tag_add(tag)
        for tag in diff.to_update:
            old_value = diff.old_values.get(
                (tag.securable_type, tag.securable_full_name, tag.tag_name)
            )
            self.log_tag_update(tag, old_value)
        for tag in diff.to_remove:
            self.log_tag_remove(tag)

    def log_privilege_changes(self, diff: PrivilegeDiff) -> None:
        """Log all privilege changes from a PrivilegeDiff."""
        for priv in diff.to_grant:
            self.log_grant(priv)
        for priv in diff.to_revoke:
            self.log_revoke(priv)

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

        return " | ".join(sections)

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

        result = " | ".join(sections)
        result += " (dry run — no changes applied)"
        return result
