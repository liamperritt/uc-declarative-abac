from __future__ import annotations

import logging

from uc_declarative_abac.governed_tags.state import GovernedTag
from uc_declarative_abac.policies.state import Policy
from uc_declarative_abac.privileges.state import SecurablePrivilege
from uc_declarative_abac.securables.state import AttributeUpdate, Securable
from uc_declarative_abac.tags.state import SecurableTag
from uc_declarative_abac.principals.state import Principal
from uc_declarative_abac.types import ExecutionError

_default_logger = logging.getLogger("uc_declarative_abac")

# Column widths for aligned output
_TYPE_WIDTH = 12  # len("GOVERNED_TAG") — longest SecurableType value
_NAME_WIDTH = 36


def _format_tag(tag_name: str, tag_value: str | None) -> str:
    """Format a tag as "'name'='value'" or just 'name' when valueless."""
    return f"{tag_name}='{tag_value or ''}'"


def _format_change_line(symbol: str, securable_type: str, full_name: str, action: str) -> str:
    """Format a single change line with columnar alignment.

    Example:  + CATALOG my_catalog                  ADDED tag env='prod'
    """
    return f"  {symbol} {securable_type:<{_TYPE_WIDTH}} {full_name:<{_NAME_WIDTH}} {action}"


def _format_set_delta(added: frozenset[str], removed: frozenset[str]) -> str:
    """Format an add/remove delta on a string set as `+a, +b, -c, -d` (sorted)."""
    parts: list[str] = []
    parts.extend(f"+{v}" for v in sorted(added))
    parts.extend(f"-{v}" for v in sorted(removed))
    return ", ".join(parts)


def _format_principal_delta(
    added: frozenset[Principal], removed: frozenset[Principal],
) -> str:
    """Format an add/remove delta on a Principal set as `+name, -name` (sorted by name)."""
    parts: list[str] = []
    parts.extend(f"+{p.name}" for p in sorted(added, key=lambda p: p.name))
    parts.extend(f"-{p.name}" for p in sorted(removed, key=lambda p: p.name))
    return ", ".join(parts)


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
        self._attributes_updated = 0
        self._securables_created = 0
        self._securables_replaced = 0
        self._policies_created = 0
        self._policies_replaced = 0
        self._governed_tags_created = 0
        self._governed_tags_updated = 0
        self._governed_tags_deleted = 0
        self._governed_tag_assigners_granted = 0
        self._governed_tag_assigners_revoked = 0
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
        title = "UC Declarative ABAC  (dry run)" if self._dry_run else "UC Declarative ABAC "
        self._logger.info("")
        self._logger.info(title)
        self._logger.info("=" * len(title))
        self._logger.info("")

    def log_section_header(self, name: str) -> None:
        """Log a section header with underline."""
        suffix = " (dry run)" if self._dry_run else ""
        header = f"{name}{suffix}"
        self._logger.info("")
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
    # Securable logging
    # ------------------------------------------------------------------

    def _display_value(self, value: object) -> str:
        """Return a display-friendly string for an AttributeUpdate value.

        ``value`` is a ``frozenset[str] | frozenset[Principal]``:

        - empty → empty string (matches the legacy "no value" rendering)
        - single Principal → its display name
        - single string → the string itself
        - multi-element → sorted, comma-separated list of names / strings
        """
        if isinstance(value, (frozenset, set)):
            if not value:
                return ""
            if len(value) == 1:
                only = next(iter(value))
                return only.name if isinstance(only, Principal) else str(only)
            rendered = sorted(
                v.name if isinstance(v, Principal) else str(v) for v in value
            )
            return ", ".join(rendered)
        if isinstance(value, Principal):
            return value.name
        return str(value)

    def log_attribute_update(self, update: AttributeUpdate) -> None:
        """Log an attribute being updated on a securable."""
        self._attributes_updated += 1
        action_verb = "Update" if self._dry_run else "Updated"
        old = self._display_value(update.old_value)
        new = self._display_value(update.new_value)
        self._log_info(_format_change_line(
            "~", update.securable_type.value, update.full_name,
            f"{action_verb} {update.attribute}: '{old}' -> '{new}'",
        ))

    def log_securable_create(self, info: Securable) -> None:
        """Log a securable being created."""
        self._securables_created += 1
        action_verb = "Create" if self._dry_run else "Created"
        self._log_info(_format_change_line(
            "+", info.securable_type.value, info.full_name,
            f"{action_verb} {info.securable_type.value.lower()}",
        ))

    def log_securable_replace(self, info: Securable) -> None:
        """Log a securable being replaced."""
        self._securables_replaced += 1
        action_verb = "Replace" if self._dry_run else "Replaced"
        self._log_info(_format_change_line(
            "~", info.securable_type.value, info.full_name,
            f"{action_verb} {info.securable_type.value.lower()}",
        ))

    # ------------------------------------------------------------------
    # Policy logging
    # ------------------------------------------------------------------

    def log_policy_create(self, policy: Policy) -> None:
        """Log a mask/filter policy being created."""
        self._policies_created += 1
        action_verb = "Create" if self._dry_run else "Created"
        self._log_info(_format_change_line(
            "+", policy.securable_type.value, policy.securable_full_name,
            f"{action_verb} {policy.policy_type.value} policy '{policy.name}'",
        ))

    def log_policy_replace(self, policy: Policy) -> None:
        """Log a mask/filter policy being replaced."""
        self._policies_replaced += 1
        action_verb = "Replace" if self._dry_run else "Replaced"
        self._log_info(_format_change_line(
            "~", policy.securable_type.value, policy.securable_full_name,
            f"{action_verb} {policy.policy_type.value} policy '{policy.name}'",
        ))

    # ------------------------------------------------------------------
    # Governed tag logging
    # ------------------------------------------------------------------

    def log_governed_tag_create(self, gt: GovernedTag) -> None:
        """Log a governed tag (account-level tag policy) being created — enumerates
        the description, allowed values, and assigners being deployed. Empty
        fields are omitted from the line. Assigners are also counted as grants
        for the summary."""
        self._governed_tags_created += 1
        self._governed_tag_assigners_granted += len(gt.assigners)
        action_verb = "Create" if self._dry_run else "Created"
        parts: list[str] = []
        if gt.description:
            parts.append(f"description='{gt.description}'")
        if gt.allowed_values:
            parts.append(f"allowed_values={','.join(sorted(gt.allowed_values))}")
        if gt.assigners:
            parts.append(
                f"assigners="
                f"{','.join(sorted(p.name for p in gt.assigners))}"
            )
        suffix = f" ({' | '.join(parts)})" if parts else ""
        self._log_info(_format_change_line(
            "+", "GOVERNED_TAG", gt.name,
            f"{action_verb} governed tag{suffix}",
        ))

    def log_governed_tag_update(self, gt: GovernedTag, old: GovernedTag | None) -> None:
        """Log a governed tag being updated — shows the specific deltas per field.

        - description: 'old' -> 'new'
        - allowed_values: +added, -removed
        - assigners: +granted, -revoked

        Unchanged fields are omitted. Assigner deltas also increment the
        assigners_granted/revoked counters for the summary, so dry-run and
        real-run produce identical detail."""
        self._governed_tags_updated += 1
        action_verb = "Update" if self._dry_run else "Updated"

        old_desc = old.description if old else ""
        old_values = old.allowed_values if old else frozenset()
        old_assigners = old.assigners if old else frozenset()

        parts: list[str] = []
        if gt.description != old_desc:
            parts.append(f"description: '{old_desc}' -> '{gt.description}'")

        added_values = gt.allowed_values - old_values
        removed_values = old_values - gt.allowed_values
        if added_values or removed_values:
            parts.append(f"allowed_values: {_format_set_delta(added_values, removed_values)}")

        added_assigners = gt.assigners - old_assigners
        removed_assigners = old_assigners - gt.assigners
        if added_assigners or removed_assigners:
            self._governed_tag_assigners_granted += len(added_assigners)
            self._governed_tag_assigners_revoked += len(removed_assigners)
            parts.append(
                f"assigners: "
                f"{_format_principal_delta(added_assigners, removed_assigners)}"
            )

        summary = " | ".join(parts) if parts else "no fields"
        self._log_info(_format_change_line(
            "~", "GOVERNED_TAG", gt.name,
            f"{action_verb} governed tag ({summary})",
        ))

    def log_governed_tag_delete(self, gt: GovernedTag) -> None:
        """Log a governed tag being deleted — enumerates the description, allowed
        values, and assigners being torn down so operators can see what's being
        lost. Assigners are also counted as revokes for the summary, since the
        rule set is destroyed with the tag."""
        self._governed_tags_deleted += 1
        self._governed_tag_assigners_revoked += len(gt.assigners)
        action_verb = "Delete" if self._dry_run else "Deleted"
        parts: list[str] = []
        if gt.description:
            parts.append(f"description='{gt.description}'")
        if gt.allowed_values:
            parts.append(f"allowed_values={','.join(sorted(gt.allowed_values))}")
        if gt.assigners:
            parts.append(
                f"assigners="
                f"{','.join(sorted(p.name for p in gt.assigners))}"
            )
        suffix = f" ({' | '.join(parts)})" if parts else ""
        self._log_info(_format_change_line(
            "-", "GOVERNED_TAG", gt.name,
            f"{action_verb} governed tag{suffix}",
        ))

    # ------------------------------------------------------------------
    # Error section
    # ------------------------------------------------------------------

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
        sec_parts: list[str] = []
        if self._attributes_updated:
            sec_parts.append(f"{self._attributes_updated} updated")
        if self._securables_created:
            sec_parts.append(f"{self._securables_created} created")
        if self._securables_replaced:
            sec_parts.append(f"{self._securables_replaced} replaced")

        tag_parts: list[str] = []
        if self._tags_added:
            tag_parts.append(f"{self._tags_added} added")
        if self._tags_updated:
            tag_parts.append(f"{self._tags_updated} updated")
        if self._tags_removed:
            tag_parts.append(f"{self._tags_removed} removed")

        policy_parts: list[str] = []
        if self._policies_created:
            policy_parts.append(f"{self._policies_created} created")
        if self._policies_replaced:
            policy_parts.append(f"{self._policies_replaced} replaced")

        priv_parts: list[str] = []
        if self._privileges_granted:
            priv_parts.append(f"{self._privileges_granted} granted")
        if self._privileges_revoked:
            priv_parts.append(f"{self._privileges_revoked} revoked")

        gt_parts: list[str] = []
        if self._governed_tags_created:
            gt_parts.append(f"{self._governed_tags_created} created")
        if self._governed_tags_updated:
            gt_parts.append(f"{self._governed_tags_updated} updated")
        if self._governed_tags_deleted:
            gt_parts.append(f"{self._governed_tags_deleted} deleted")

        gt_assigner_parts: list[str] = []
        if self._governed_tag_assigners_granted:
            gt_assigner_parts.append(f"{self._governed_tag_assigners_granted} granted")
        if self._governed_tag_assigners_revoked:
            gt_assigner_parts.append(f"{self._governed_tag_assigners_revoked} revoked")

        sections: list[str] = []
        if sec_parts:
            sections.append("Securables: " + ", ".join(sec_parts))
        if gt_parts:
            sections.append("Governed tags: " + ", ".join(gt_parts))
        if gt_assigner_parts:
            sections.append("Governed tag assigners: " + ", ".join(gt_assigner_parts))
        if tag_parts:
            sections.append("Tags: " + ", ".join(tag_parts))
        if policy_parts:
            sections.append("Policies: " + ", ".join(policy_parts))
        if priv_parts:
            sections.append("Privileges: " + ", ".join(priv_parts))
        if self._errors:
            sections.append(f"Errors: {len(self._errors)} failed")

        return " | ".join(sections) if sections else "No changes needed — all in sync"

    def _build_dry_run_summary(self) -> str:
        sec_parts: list[str] = []
        if self._attributes_updated:
            sec_parts.append(f"{self._attributes_updated} to update")
        if self._securables_created:
            sec_parts.append(f"{self._securables_created} to create")
        if self._securables_replaced:
            sec_parts.append(f"{self._securables_replaced} to replace")

        tag_parts: list[str] = []
        if self._tags_added:
            tag_parts.append(f"{self._tags_added} to add")
        if self._tags_updated:
            tag_parts.append(f"{self._tags_updated} to update")
        if self._tags_removed:
            tag_parts.append(f"{self._tags_removed} to remove")

        policy_parts: list[str] = []
        if self._policies_created:
            policy_parts.append(f"{self._policies_created} to create")
        if self._policies_replaced:
            policy_parts.append(f"{self._policies_replaced} to replace")

        priv_parts: list[str] = []
        if self._privileges_granted:
            priv_parts.append(f"{self._privileges_granted} to grant")
        if self._privileges_revoked:
            priv_parts.append(f"{self._privileges_revoked} to revoke")

        gt_parts: list[str] = []
        if self._governed_tags_created:
            gt_parts.append(f"{self._governed_tags_created} to create")
        if self._governed_tags_updated:
            gt_parts.append(f"{self._governed_tags_updated} to update")
        if self._governed_tags_deleted:
            gt_parts.append(f"{self._governed_tags_deleted} to delete")

        gt_assigner_parts: list[str] = []
        if self._governed_tag_assigners_granted:
            gt_assigner_parts.append(f"{self._governed_tag_assigners_granted} to grant")
        if self._governed_tag_assigners_revoked:
            gt_assigner_parts.append(f"{self._governed_tag_assigners_revoked} to revoke")

        sections: list[str] = []
        if sec_parts:
            sections.append("Securables: " + ", ".join(sec_parts))
        if gt_parts:
            sections.append("Governed tags: " + ", ".join(gt_parts))
        if gt_assigner_parts:
            sections.append("Governed tag assigners: " + ", ".join(gt_assigner_parts))
        if tag_parts:
            sections.append("Tags: " + ", ".join(tag_parts))
        if policy_parts:
            sections.append("Policies: " + ", ".join(policy_parts))
        if priv_parts:
            sections.append("Privileges: " + ", ".join(priv_parts))

        if sections:
            return " | ".join(sections) + " (dry run — no changes applied)"
        return "No changes needed (dry run — no changes applied)"
