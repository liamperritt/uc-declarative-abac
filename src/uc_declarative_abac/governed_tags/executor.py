from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING

from databricks.sdk.service.iam import GrantRule
from databricks.sdk.service.tags import TagPolicy, Value

if TYPE_CHECKING:
    from uc_declarative_abac.helpers import WorkspaceHelper
    from uc_declarative_abac.logger import ChangeLogger

from uc_declarative_abac.governed_tags.state import (
    GovernedTag,
    GovernedTagDiff,
)
from uc_declarative_abac.utils import (
    ExecutionError,
    InteractiveConfirmationRequiredError,
    OrchestratorError,
)
from uc_declarative_abac.principals import (
    ensure_resolved,
    Principal,
)
from uc_declarative_abac.types import PrincipalType

_logger = logging.getLogger("uc_declarative_abac")

# Account Access Control Proxy ASSIGN role on tag policies.
# Mirrors the constant in helpers/workspace.py — kept independently so the
# executor can build grant rules without importing private helpers.
_TAG_POLICY_ASSIGN_ROLE = "roles/tagPolicy.assigner"


def _to_tag_policy(gt: GovernedTag) -> TagPolicy:
    """Convert a desired GovernedTag into the SDK's TagPolicy request body."""
    return TagPolicy(
        tag_key=gt.name,
        description=gt.description or None,
        values=[Value(name=v) for v in sorted(gt.allowed_values)],
    )


def _compute_tag_policy_update_mask(new: GovernedTag, old: GovernedTag | None) -> str:
    """Return the comma-separated update_mask for the SDK's update_tag_policy.
    Only description and values are managed via that endpoint — assigners
    rides the Account Access Control Proxy rule-set API."""
    fields: list[str] = []
    if old is None or new.description != old.description:
        fields.append("description")
    if old is None or new.allowed_values != old.allowed_values:
        fields.append("values")
    return ",".join(fields)


def _principal_to_ruleset_string(principal: Principal) -> str:
    """Encode a resolved Principal as the SCIM-prefixed string the rule-set API expects."""
    ensure_resolved(principal)
    if principal.principal_type == PrincipalType.USER:
        return f"users/{principal.name}"
    if principal.principal_type == PrincipalType.GROUP:
        return f"groups/{principal.name}"
    if principal.principal_type == PrincipalType.SERVICE_PRINCIPAL:
        return f"servicePrincipals/{principal.identifier}"
    raise OrchestratorError(f"Unsupported principal type for rule set: {principal!r}")


def _build_grant_rules(
    desired_assigners: frozenset[Principal],
    existing_grant_rules: list,
) -> list[GrantRule]:
    """Combine the desired assigners with any non-ASSIGN grant rules
    already present on the rule set so that other roles are preserved."""
    new_rules: list[GrantRule] = []
    for rule in existing_grant_rules or []:
        if rule.role == _TAG_POLICY_ASSIGN_ROLE:
            continue
        new_rules.append(GrantRule(
            role=rule.role,
            principals=list(rule.principals or []),
        ))
    if desired_assigners:
        new_rules.append(GrantRule(
            role=_TAG_POLICY_ASSIGN_ROLE,
            principals=sorted(_principal_to_ruleset_string(p) for p in desired_assigners),
        ))
    return new_rules


def _apply_assigners(
    ws_helper: WorkspaceHelper,
    gt: GovernedTag,
    change_logger: ChangeLogger,
) -> None:
    """Read-modify-write the tag's rule set so its ASSIGN grant rule reflects
    ``gt.assigners``. Non-ASSIGN grant rules are preserved untouched.
    Errors are captured per tag and the run continues. The assigner delta is
    surfaced through the parent ``log_governed_tag_create`` /
    ``log_governed_tag_update`` line — this helper performs no logging itself
    on the success path so dry-run and real-run produce identical output."""
    tag_id = ws_helper.get_tag_policy_id(gt.name)
    if not tag_id:
        change_logger.log_error(ExecutionError(
            context=f"update_rule_set({gt.name})",
            exception=OrchestratorError(f"Tag policy id not cached for {gt.name!r}"),
        ))
        return
    try:
        current = ws_helper.get_tag_policy_rule_set_by_name(gt.name)
        new_rules = _build_grant_rules(gt.assigners, current.grant_rules or [])
        ws_helper.update_tag_policy_rule_set(
            tag_id=tag_id, etag=current.etag, grant_rules=new_rules,
        )
    except Exception as exc:
        change_logger.log_error(ExecutionError(
            context=f"update_rule_set({gt.name})", exception=exc,
        ))


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
                created = ws_helper.create_tag_policy(_to_tag_policy(gt))
            except Exception as exc:
                change_logger.log_error(ExecutionError(
                    context=f"create_tag_policy({gt.name})", exception=exc,
                ))
                continue
            ws_helper.register_created_tag_policy(created)
            if gt.assigners:
                _apply_assigners(ws_helper, gt, change_logger)
        change_logger.log_governed_tag_create(gt)


def _execute_updates(
    ws_helper: WorkspaceHelper,
    diff: GovernedTagDiff,
    change_logger: ChangeLogger,
    dry_run: bool,
) -> None:
    """Update each governed tag in to_update. Description/values changes go via
    update_tag_policy; assigner changes go via the rule-set API."""
    for gt in sorted(diff.to_update, key=lambda g: g.name):
        old = diff.old_values.get(gt.name)
        update_mask = _compute_tag_policy_update_mask(gt, old)
        assigners_changed = gt.assigners != (
            old.assigners if old else frozenset()
        )
        if update_mask and not dry_run:
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
        if assigners_changed and not dry_run:
            _apply_assigners(ws_helper, gt, change_logger)
        if update_mask or assigners_changed:
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
    """Delete each governed tag in to_delete, gated by interactive confirmation."""
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
    """Apply a GovernedTagDiff against the account.

    Creates run first (and immediately set their assigners), then updates
    (description/values via update_tag_policy, assigners via update_rule_set),
    then deletes (interactive confirmation). Each SDK exception is logged via
    ``change_logger.log_error`` and the batch continues.
    """
    _execute_creates(ws_helper, diff, change_logger, dry_run)
    _execute_updates(ws_helper, diff, change_logger, dry_run)
    _execute_deletes(ws_helper, diff, change_logger, dry_run, force)
