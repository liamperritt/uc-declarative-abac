from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import date

from uc_abac_governor.models import ConfigFile, GrantPolicyConfig
from uc_abac_governor.tags.state import SecurableTag
from uc_abac_governor.types import PrivilegeType, SecurableType

# Privileges valid for each securable type. Higher-level securables inherit
# all privileges from lower levels. Unknown privileges are allowed on all types.
_TABLE_PRIVILEGES = {PrivilegeType.SELECT, PrivilegeType.MODIFY}
_VOLUME_PRIVILEGES = {PrivilegeType.READ_VOLUME, PrivilegeType.WRITE_VOLUME}
_SCHEMA_PRIVILEGES = (
    _TABLE_PRIVILEGES
    | _VOLUME_PRIVILEGES
    | {
        PrivilegeType.USE_SCHEMA,
        PrivilegeType.CREATE_TABLE,
        PrivilegeType.CREATE_FUNCTION,
        PrivilegeType.CREATE_VOLUME,
        PrivilegeType.EXECUTE,
        PrivilegeType.EXTERNAL_USE_SCHEMA,
        PrivilegeType.CREATE_MATERIALIZED_VIEW,
        PrivilegeType.REFRESH,
        PrivilegeType.CREATE_MODEL,
        PrivilegeType.CREATE_MODEL_VERSION,
    }
)
_CATALOG_PRIVILEGES = _SCHEMA_PRIVILEGES | {PrivilegeType.USE_CATALOG, PrivilegeType.CREATE_SCHEMA}
_UNIVERSAL_PRIVILEGES = {PrivilegeType.ALL_PRIVILEGES, PrivilegeType.MANAGE}

SECURABLE_TYPE_PRIVILEGE_MAP: dict[SecurableType, set[PrivilegeType]] = {
    SecurableType.CATALOG: _CATALOG_PRIVILEGES | _UNIVERSAL_PRIVILEGES,
    SecurableType.SCHEMA: _SCHEMA_PRIVILEGES | _UNIVERSAL_PRIVILEGES,
    SecurableType.TABLE: _TABLE_PRIVILEGES | _UNIVERSAL_PRIVILEGES,
    SecurableType.VOLUME: _VOLUME_PRIVILEGES | _UNIVERSAL_PRIVILEGES,
}


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
    privilege_type: PrivilegeType


def compile_desired_privileges(
    config: ConfigFile,
    desired_tags: set[SecurableTag],
    run_date: date | None = None,
) -> set[CompiledPrivilege]:
    """Compute desired privileges by matching grant policies against desired tags.

    For each grant policy, finds objects whose tags are a superset of the
    policy's tags (AND semantics, exact value match). Emits a CompiledPrivilege
    for each (matching_object, principal, privilege_type).
    """
    if run_date is None:
        run_date = date.today()
    tag_index = _build_tag_index(desired_tags)
    policies = _collect_policies(config)
    active_policies = [
        p for p in policies
        if p.expiry_date is None or p.expiry_date > run_date
    ]
    return _match_policies(active_policies, tag_index)


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
            allowed = SECURABLE_TYPE_PRIVILEGE_MAP.get(sec_type)
            for principal_name in policy.to:
                for privilege in policy.privileges:
                    if allowed is not None and privilege not in allowed:
                        continue
                    result.add(
                        CompiledPrivilege(
                            securable_type=sec_type,
                            securable_full_name=full_name,
                            principal=principal_name,
                            privilege_type=privilege,
                        )
                    )
    return result
