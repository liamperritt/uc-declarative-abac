from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from uc_governor.models import ConfigFile, GrantPolicyConfig
from uc_governor.tags.state import SecurableTag
from uc_governor.types import SecurableType


@dataclass(frozen=True)
class CompiledPrivilege:
    """Intermediate privilege representation emitted by the compiler.

    Contains the raw principal name from the YAML config (a plain string).
    This needs to be resolved to a Principal object with a real identifier
    before diffing.
    """

    securable_type: SecurableType
    securable_full_name: str
    principal: str
    privilege_type: str


def compile_desired_privileges(
    config: ConfigFile,
    desired_tags: set[SecurableTag],
) -> set[CompiledPrivilege]:
    """Compute desired privileges by matching grant policies against desired tags.

    For each grant policy, finds objects whose tags are a superset of the
    policy's tags (AND semantics, exact value match). Emits a CompiledPrivilege
    for each (matching_object, principal, privilege_type).
    """
    tag_index = _build_tag_index(desired_tags)
    policies = _collect_policies(config)
    return _match_policies(policies, tag_index)


def _build_tag_index(
    desired_tags: set[SecurableTag],
) -> dict[str, tuple[SecurableType, set[tuple[str, str | None]]]]:
    """Build a mapping from securable_full_name to (type, set of (tag_name, tag_value))."""
    grouped: dict[str, list[SecurableTag]] = defaultdict(list)
    for tag in desired_tags:
        grouped[tag.securable_full_name].append(tag)

    return {
        full_name: (
            tags[0].securable_type,
            {(t.tag_name, t.tag_value) for t in tags},
        )
        for full_name, tags in grouped.items()
    }


def _collect_policies(config: ConfigFile) -> list[GrantPolicyConfig]:
    """Gather all grant policies across all catalogs, schemas, and tables."""
    policies: list[GrantPolicyConfig] = []
    for catalog in config.catalogs.values():
        if catalog.policies:
            policies.extend(catalog.policies)
        for schema in catalog.schemas or []:
            if schema.policies:
                policies.extend(schema.policies)
            for table in schema.tables or []:
                if table.policies:
                    policies.extend(table.policies)
    return policies


def _match_policies(
    policies: list[GrantPolicyConfig],
    tag_index: dict[str, tuple[SecurableType, set[tuple[str, str | None]]]],
) -> set[CompiledPrivilege]:
    """Match policies against the tag index and emit compiled privileges."""
    result: set[CompiledPrivilege] = set()
    for policy in policies:
        required = {(k, v) for k, v in policy.tags.items()}
        for full_name, (sec_type, actual_tags) in tag_index.items():
            if not required.issubset(actual_tags):
                continue
            for principal_name in policy.to:
                for privilege in policy.privileges:
                    result.add(
                        CompiledPrivilege(
                            securable_type=sec_type,
                            securable_full_name=full_name,
                            principal=principal_name,
                            privilege_type=privilege.upper(),
                        )
                    )
    return result
