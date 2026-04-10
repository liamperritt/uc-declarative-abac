from __future__ import annotations

from collections import defaultdict
from datetime import date

from uc_abac_governor.configs.models import ResourcesConfig, GrantPolicyConfig
from uc_abac_governor.tags.state import SecurableTag
from uc_abac_governor.privileges.state import UnresolvedPrivilege
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



def compile_desired_privileges(
    config: ResourcesConfig,
    desired_tags: set[SecurableTag],
    run_date: date | None = None,
) -> set[UnresolvedPrivilege]:
    """Compute desired privileges by matching grant policies against desired tags.

    For each grant policy, finds objects whose tags are a superset of the
    policy's tags (AND semantics, exact value match). Emits a UnresolvedPrivilege
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


def _collect_policies(config: ResourcesConfig) -> list[GrantPolicyConfig]:
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


def _policy_securable_type(policy: GrantPolicyConfig) -> SecurableType:
    """Derive the securable type of the object a policy is attached to."""
    if policy.table_name:
        return SecurableType.TABLE
    if policy.schema_name:
        return SecurableType.SCHEMA
    return SecurableType.CATALOG


def _is_within_scope(full_name: str, policy: GrantPolicyConfig) -> bool:
    """Return True if the securable full_name is within the policy's scope."""
    scope = policy.parent_full_name
    return full_name == scope or full_name.startswith(f"{scope}.")


def _emit_privileges(
    sec_type: SecurableType,
    full_name: str,
    policy: GrantPolicyConfig,
) -> set[UnresolvedPrivilege]:
    """Emit UnresolvedPrivilege entries for each principal × privilege combination."""
    allowed = SECURABLE_TYPE_PRIVILEGE_MAP.get(sec_type)
    result: set[UnresolvedPrivilege] = set()
    for principal_name in policy.to:
        for privilege in policy.privileges:
            if allowed is not None and privilege not in allowed:
                continue
            result.add(
                UnresolvedPrivilege(
                    securable_type=sec_type,
                    securable_full_name=full_name,
                    principal=principal_name,
                    privilege_type=privilege,
                )
            )
    return result


def _match_policies(
    policies: list[GrantPolicyConfig],
    tag_index: dict[str, tuple[SecurableType, set[tuple[str, str | None]]]],
) -> set[UnresolvedPrivilege]:
    """Match policies against the tag index and emit compiled privileges.

    Tagless policies (empty tags) grant directly to their attached securable.
    Policies with tags only match securables within their scope (attached
    securable and its children).
    """
    result: set[UnresolvedPrivilege] = set()
    for policy in policies:
        if not policy.tags:
            # Tagless policy — grant directly to the attached securable
            sec_type = _policy_securable_type(policy)
            result |= _emit_privileges(sec_type, policy.parent_full_name, policy)
            continue

        # Tag-matching policy — scoped to the attached securable and its children
        required = {(k, v) for k, v in policy.tags.items()}
        for full_name, (sec_type, actual_tags) in tag_index.items():
            if not _is_within_scope(full_name, policy):
                continue
            if not required.issubset(actual_tags):
                continue
            result |= _emit_privileges(sec_type, full_name, policy)
    return result
