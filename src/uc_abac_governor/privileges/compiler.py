from __future__ import annotations

from collections import defaultdict
from datetime import date

from uc_abac_governor.configs.models import ResourcesConfig, GrantPolicyConfig
from uc_abac_governor.principals.state import Principal
from uc_abac_governor.tags.state import SecurableTag
from uc_abac_governor.privileges.state import SecurablePrivilege
from uc_abac_governor.types import PrincipalType, PrivilegeType, SecurableType

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
_CATALOG_PRIVILEGES = _SCHEMA_PRIVILEGES | {PrivilegeType.USE_CATALOG, PrivilegeType.CREATE_SCHEMA, PrivilegeType.BROWSE}
_UNIVERSAL_PRIVILEGES = {PrivilegeType.ALL_PRIVILEGES, PrivilegeType.MANAGE}

_TAG_VALUE_WILDCARD = "*"

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
) -> set[SecurablePrivilege]:
    """Compute desired privileges by matching grant policies against desired tags.

    For each grant policy, finds objects whose tags are a superset of the
    policy's tags (AND semantics, exact value match). Emits a SecurablePrivilege
    (with unresolved Principal) for each (matching_object, principal, privilege_type).
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
        policies.extend(_filter_grants(catalog.policies))
        for schema in catalog.schemas or []:
            policies.extend(_filter_grants(schema.policies))
            for table in schema.tables or []:
                policies.extend(_filter_grants(table.policies))
    return policies


def _filter_grants(policies) -> list[GrantPolicyConfig]:
    return [p for p in (policies or []) if isinstance(p, GrantPolicyConfig)]


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


def _catalog_full_name(full_name: str) -> str:
    """Return the catalog portion of a dot-delimited securable full name."""
    return full_name.split(".", 1)[0]


def _schema_full_name(full_name: str) -> str | None:
    """Return the `catalog.schema` portion of a dot-delimited full name,
    or None if the name has no schema segment (catalog-only)."""
    parts = full_name.split(".")
    if len(parts) < 2:
        return None
    return ".".join(parts[:2])


def _target_for_privilege(
    privilege: PrivilegeType,
    sec_type: SecurableType,
    full_name: str,
) -> tuple[SecurableType, str]:
    """Resolve the securable a privilege should be emitted on, given the
    matched object. USE_CATALOG always targets the containing catalog;
    USE_SCHEMA targets the containing schema when there is one (otherwise
    falls back to the matched object, preserving the UC semantic of granting
    USE_SCHEMA on a catalog = across all its schemas)."""
    if privilege == PrivilegeType.USE_CATALOG:
        return SecurableType.CATALOG, _catalog_full_name(full_name)
    if privilege == PrivilegeType.USE_SCHEMA:
        schema_name = _schema_full_name(full_name)
        if schema_name is not None:
            return SecurableType.SCHEMA, schema_name
    return sec_type, full_name


def _emit_privileges(
    sec_type: SecurableType,
    full_name: str,
    policy: GrantPolicyConfig,
) -> set[SecurablePrivilege]:
    """Emit SecurablePrivilege entries (with unresolved Principals) for each
    principal × privilege combination. USE_CATALOG and USE_SCHEMA cascade to
    the appropriate parent ancestor of the matched object, but only when
    that ancestor is within the policy's scope — so a schema- or table-attached
    policy cannot reach up into its parent catalog. The compatibility filter
    is applied against the resolved target type."""
    result: set[SecurablePrivilege] = set()
    for principal_name in policy.to:
        for privilege in policy.privileges:
            target_type, target_full_name = _target_for_privilege(privilege, sec_type, full_name)
            if not _is_within_scope(target_full_name, policy):
                continue
            allowed = SECURABLE_TYPE_PRIVILEGE_MAP.get(target_type)
            if allowed is not None and privilege not in allowed:
                continue
            result.add(
                SecurablePrivilege(
                    securable_type=target_type,
                    securable_full_name=target_full_name,
                    principal=Principal(principal_type=PrincipalType.UNKNOWN, name=principal_name),
                    privilege_type=privilege,
                )
            )
    return result


def _match_policies(
    policies: list[GrantPolicyConfig],
    tag_index: dict[str, tuple[SecurableType, set[tuple[str, str | None]]]],
) -> set[SecurablePrivilege]:
    """Match policies against the tag index and emit compiled privileges.

    Tagless policies (empty tags) grant directly to their attached securable.
    Policies with tags only match securables within their scope (attached
    securable and its children).
    """
    result: set[SecurablePrivilege] = set()
    for policy in policies:
        if not policy.has_tags:
            # Tagless policy — grant directly to the attached securable
            sec_type = _policy_securable_type(policy)
            result |= _emit_privileges(sec_type, policy.parent_full_name, policy)
            continue

        # Tag-matching policy — scoped to the attached securable and its children
        for full_name, (sec_type, actual_tags) in tag_index.items():
            if not _is_within_scope(full_name, policy):
                continue
            if not _tags_match(policy.has_tags, actual_tags):
                continue
            result |= _emit_privileges(sec_type, full_name, policy)
    return result


def _tags_match(
    required: dict[str, str],
    actual_tags: set[tuple[str, str | None]],
) -> bool:
    """Return True iff every required tag is present on the object (AND semantics).

    A required value of '*' matches any value — only the tag's presence is checked.
    Any other required value must equal the actual value exactly.
    """
    actual_by_key = {key: value for key, value in actual_tags}
    for key, required_value in required.items():
        if key not in actual_by_key:
            return False
        if required_value == _TAG_VALUE_WILDCARD:
            continue
        if actual_by_key[key] != required_value:
            return False
    return True
