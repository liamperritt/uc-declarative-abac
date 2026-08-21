from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from uc_declarative_abac.orchestrator import OrchestratorDiffsResult


Change = dict[str, Any]
ResourceChanges = dict[tuple[str, str], list[Change]]


def _names(principals: Any) -> list[str]:
    return sorted(principal.name for principal in principals)


def _values(values: Any) -> list[str]:
    return sorted(value.name if hasattr(value, "name") else value for value in values)


def _add(
    resources: ResourceChanges,
    type_: str,
    name: str,
    domain: str,
    operation: str,
    payload: dict[str, Any],
    status: str,
) -> None:
    resources[(type_, name)].append(
        {
            "domain": domain,
            "operation": operation,
            "status": status,
            "payload": payload,
        }
    )


def _add_groups(
    resources: ResourceChanges, result: OrchestratorDiffsResult, status: str
) -> None:
    for name, members in result.group_diff.groups_to_create.items():
        _add(
            resources,
            "GROUP",
            name,
            "groups",
            "add",
            {"members": _names(members)},
            status,
        )
    for name, members in result.group_diff.members_to_add.items():
        _add(
            resources,
            "GROUP",
            name,
            "groups",
            "add",
            {"members": _names(members)},
            status,
        )
    for name, members in result.group_diff.members_to_remove.items():
        _add(
            resources,
            "GROUP",
            name,
            "groups",
            "remove",
            {"members": _names(members)},
            status,
        )
    for rename in result.group_diff.groups_to_rename:
        _add(
            resources,
            "GROUP",
            rename.new_display_name,
            "groups",
            "change",
            {
                "id": rename.id,
                "old_display_name": rename.old_display_name,
                "new_display_name": rename.new_display_name,
            },
            status,
        )
    for group in result.group_diff.groups_to_delete:
        _add(
            resources,
            "GROUP",
            group.display_name,
            "groups",
            "remove",
            {"id": group.id},
            status,
        )


def _securable_payload(securable: Any) -> dict[str, Any]:
    payload = {}
    if securable.comment is not None:
        payload["comment"] = securable.comment
    if securable.location is not None:
        payload["location"] = securable.location
    return payload


def _add_securables(
    resources: ResourceChanges, result: OrchestratorDiffsResult, status: str
) -> None:
    for securable in result.securable_diff.securables_to_create:
        _add(
            resources,
            securable.securable_type.value,
            securable.full_name,
            "securables",
            "add",
            _securable_payload(securable),
            status,
        )
    for securable in result.securable_diff.securables_to_replace:
        old = result.securable_diff.old_securables.get(securable.full_name)
        payload = {"new_value": _securable_payload(securable)}
        if old is not None:
            payload["old_value"] = _securable_payload(old)
        _add(
            resources,
            securable.securable_type.value,
            securable.full_name,
            "securables",
            "change",
            payload,
            status,
        )
    for update in result.securable_diff.attributes_to_update:
        payload = {
            "attribute": update.attribute,
            "old_value": _values(update.old_value),
            "new_value": _values(update.new_value),
        }
        _add(
            resources,
            update.securable_type.value,
            update.full_name,
            "securables",
            "change",
            payload,
            status,
        )


def _add_governed_tags(
    resources: ResourceChanges, result: OrchestratorDiffsResult, status: str
) -> None:
    def payload(tag: Any) -> dict[str, Any]:
        return {
            "description": tag.description,
            "allowed_values": sorted(tag.allowed_values),
            "assigners": _names(tag.assigners),
        }

    for tag in result.governed_tag_diff.to_create:
        _add(
            resources,
            "GOVERNED_TAG",
            tag.name,
            "governed_tags",
            "add",
            payload(tag),
            status,
        )
    for tag in result.governed_tag_diff.to_update:
        old = result.governed_tag_diff.old_values.get(tag.name)
        change_payload = {"new_value": payload(tag)}
        if old is not None:
            change_payload["old_value"] = payload(old)
        _add(
            resources,
            "GOVERNED_TAG",
            tag.name,
            "governed_tags",
            "change",
            change_payload,
            status,
        )
    for tag in result.governed_tag_diff.to_delete:
        _add(
            resources,
            "GOVERNED_TAG",
            tag.name,
            "governed_tags",
            "remove",
            payload(tag),
            status,
        )


def _add_tags(
    resources: ResourceChanges, result: OrchestratorDiffsResult, status: str
) -> None:
    operations = (
        ("add", result.tag_diff.to_add),
        ("change", result.tag_diff.to_update),
        ("remove", result.tag_diff.to_remove),
    )
    for operation, tags in operations:
        for tag in tags:
            payload = {"tag_name": tag.tag_name}
            if operation == "change":
                key = (tag.securable_type, tag.securable_full_name, tag.tag_name)
                payload["old_value"] = result.tag_diff.old_values.get(key)
            payload["tag_value"] = tag.tag_value
            _add(
                resources,
                tag.securable_type.value,
                tag.securable_full_name,
                "tags",
                operation,
                payload,
                status,
            )


def _policy_payload(policy: Any) -> dict[str, Any]:
    return {
        "name": policy.name,
        "policy_type": policy.policy_type.value,
        "function_name": policy.function_name,
        "to": _names(policy.to_principals),
        "except": _names(policy.except_principals),
    }


def _add_policies(
    resources: ResourceChanges, result: OrchestratorDiffsResult, status: str
) -> None:
    for policy in result.policy_diff.to_create:
        _add(
            resources,
            policy.securable_type.value,
            policy.securable_full_name,
            "policies",
            "add",
            _policy_payload(policy),
            status,
        )
    for policy in result.policy_diff.to_replace:
        key = (policy.securable_type, policy.securable_full_name, policy.name)
        old = result.policy_diff.old_policies.get(key)
        payload = {"new_value": _policy_payload(policy)}
        if old is not None:
            payload["old_value"] = _policy_payload(old)
        _add(
            resources,
            policy.securable_type.value,
            policy.securable_full_name,
            "policies",
            "change",
            payload,
            status,
        )
    for policy in result.policy_diff.to_delete:
        _add(
            resources,
            policy.securable_type.value,
            policy.securable_full_name,
            "policies",
            "remove",
            _policy_payload(policy),
            status,
        )


def _add_privileges(
    resources: ResourceChanges, result: OrchestratorDiffsResult, status: str
) -> None:
    operations = (
        ("add", result.privilege_diff.to_grant),
        ("remove", result.privilege_diff.to_revoke),
    )
    for operation, privileges in operations:
        for privilege in privileges:
            payload = {
                "principal": privilege.principal.name,
                "privilege": privilege.privilege_type.value,
            }
            _add(
                resources,
                privilege.securable_type.value,
                privilege.securable_full_name,
                "privileges",
                operation,
                payload,
                status,
            )


def _collect(result: OrchestratorDiffsResult, status: str) -> ResourceChanges:
    resources: ResourceChanges = defaultdict(list)
    _add_groups(resources, result, status)
    _add_securables(resources, result, status)
    _add_governed_tags(resources, result, status)
    _add_tags(resources, result, status)
    _add_policies(resources, result, status)
    _add_privileges(resources, result, status)
    return resources


def _render_resources(resources: ResourceChanges) -> list[dict[str, Any]]:
    rendered = []
    for (type_, name), changes in sorted(resources.items()):
        ordered = sorted(
            changes,
            key=lambda change: (
                change["domain"],
                change["operation"],
                json.dumps(change["payload"], sort_keys=True),
            ),
        )
        rendered.append({"type": type_, "full_name": name, "changes": ordered})
    return rendered


def _summary(resources: ResourceChanges) -> dict[str, Any]:
    operations = ("add", "change", "remove")
    counts = {operation: 0 for operation in operations}
    by_domain: dict[str, dict[str, int]] = {}
    for changes in resources.values():
        for change in changes:
            domain_counts = by_domain.setdefault(
                change["domain"], {operation: 0 for operation in operations}
            )
            counts[change["operation"]] += 1
            domain_counts[change["operation"]] += 1
    return {"total": sum(counts.values()), **counts, "by_domain": by_domain}


def render_validate_json(config_dir: Path) -> str:
    """Render a successful local config-validation result as JSON."""
    resources: list[dict[str, Any]] = []
    report = {
        "format_version": "1",
        "mode": "validate",
        "dry_run": False,
        "config_dir": str(config_dir),
        "status": "valid",
        "resources": resources,
        "summary": _summary({}),
        "warnings": [],
        "errors": [],
    }
    return json.dumps(report, indent=2, sort_keys=True)


def render_deploy_json(
    result: OrchestratorDiffsResult, *, config_dir: Path, dry_run: bool
) -> str:
    """Render a completed deployment or dry-run diff as deterministic JSON."""
    changes = _collect(result, "planned" if dry_run else "applied")
    report = {
        "format_version": "1",
        "mode": "deploy",
        "dry_run": dry_run,
        "config_dir": str(config_dir),
        "resources": _render_resources(changes),
        "summary": _summary(changes),
        "warnings": [],
        "errors": [],
    }
    return json.dumps(report, indent=2, sort_keys=True)
