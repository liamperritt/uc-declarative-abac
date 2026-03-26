from __future__ import annotations

import logging

from uc_abac_governor.privileges.state import PrivilegeDiff, SecurablePrivilege
from uc_abac_governor.tags.state import SecurableTag, TagDiff
from uc_abac_governor.types import ExecutionError, Principal, SecurableType

_default_logger = logging.getLogger("uc_abac_governor")


def _format_tag(tag_name: str, tag_value: str | None) -> str:
    """Format a tag as 'name=value' or just 'name' when valueless."""
    return f"{tag_name}='{tag_value or ''}'"


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

    def _securable_label(self, securable_type: SecurableType, full_name: str) -> str:
        """Format a securable as '(Type 'full_name')'."""
        return f"[{securable_type.value} {full_name}]"

    def log_tag_add(self, tag: SecurableTag) -> None:
        """Log a tag being added to a securable."""
        self._tags_added += 1
        action = "ADD" if self._dry_run else "ADDED"
        label = self._securable_label(tag.securable_type, tag.securable_full_name)
        display = _format_tag(tag.tag_name, tag.tag_value)
        self._log_info(f"[TAGS] {label} {action} tag {display}")

    def log_tag_update(self, tag: SecurableTag, old_value: str | None) -> None:
        """Log a tag value being updated on a securable."""
        self._tags_updated += 1
        action = "UPDATE" if self._dry_run else "UPDATED"
        label = self._securable_label(tag.securable_type, tag.securable_full_name)
        old_display = _format_tag(tag.tag_name, old_value)
        new_display = _format_tag(tag.tag_name, tag.tag_value)
        self._log_info(f"[TAGS] {label} {action} tag {old_display} -> {new_display}")

    def log_tag_remove(self, tag: SecurableTag) -> None:
        """Log a tag being removed from a securable."""
        self._tags_removed += 1
        action = "REMOVE" if self._dry_run else "REMOVED"
        label = self._securable_label(tag.securable_type, tag.securable_full_name)
        self._log_info(f"[TAGS] {label} {action} tag {tag.tag_name}")

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
        action = "GRANT" if self._dry_run else "GRANTED"
        label = self._securable_label(privilege.securable_type, privilege.securable_full_name)
        name = self._principal_name(privilege.principal)
        self._log_info(f"[PRIVILEGES] {label} {action} {privilege.privilege_type.value} to '{name}'")

    def log_revoke(self, privilege: SecurablePrivilege) -> None:
        """Log a privilege being revoked."""
        self._privileges_revoked += 1
        action = "REVOKE" if self._dry_run else "REVOKED"
        label = self._securable_label(privilege.securable_type, privilege.securable_full_name)
        name = self._principal_name(privilege.principal)
        self._log_info(f"[PRIVILEGES] {label} {action} {privilege.privilege_type.value} from '{name}'")

    # ------------------------------------------------------------------
    # Diff-level convenience methods
    # ------------------------------------------------------------------

    def log_tag_changes(self, diff: TagDiff) -> None:
        """Log all tag changes from a TagDiff."""
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

    def log_privilege_changes(self, diff: PrivilegeDiff) -> None:
        """Log all privilege changes from a PrivilegeDiff."""
        sort_key = lambda p: (p.securable_type.value, p.securable_full_name)
        for priv in sorted(diff.to_grant, key=sort_key):
            self.log_grant(priv)
        for priv in sorted(diff.to_revoke, key=sort_key):
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
