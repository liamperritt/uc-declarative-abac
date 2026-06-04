from __future__ import annotations

from collections import defaultdict
from datetime import date

from uc_declarative_abac.configs import (
    GrantPolicyConfig,
    ResourcesConfig,
)
from uc_declarative_abac.utils import (
    ExecutionError,
    UngovernedTagError,
)
from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.principals import Principal
from uc_declarative_abac.tags import SecurableTag
from uc_declarative_abac.privileges.state import SecurablePrivilege
from uc_declarative_abac.types import (
    AbstractedPrivilegeType,
    PrincipalType,
    PrivilegeType,
    SecurableType,
)

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
    # Unity Catalog does not support column-level GRANT/REVOKE. Column tags are
    # excluded upstream in _build_tag_index, so a COLUMN securable never reaches
    # matching or this map. This empty set is kept as a defensive guard: were a
    # COLUMN target ever to appear, the compatibility filter in _emit_privileges
    # would drop every privilege targeted at it.
    SecurableType.COLUMN: frozenset(),
}

ABSTRACT_PRIVILEGE_MAP: dict[AbstractedPrivilegeType, frozenset[PrivilegeType]] = {
    AbstractedPrivilegeType.READ: frozenset({
        PrivilegeType.SELECT,
        PrivilegeType.READ_VOLUME,
        PrivilegeType.EXECUTE,
    }),
    AbstractedPrivilegeType.EDIT: frozenset({
        PrivilegeType.MODIFY,
        PrivilegeType.WRITE_VOLUME,
        PrivilegeType.REFRESH,
    }),
    AbstractedPrivilegeType.USE: frozenset({
        PrivilegeType.USE_CATALOG,
        PrivilegeType.USE_SCHEMA,
    }),
    AbstractedPrivilegeType.CREATE: frozenset({
        PrivilegeType.CREATE_TABLE,
        PrivilegeType.CREATE_SCHEMA,
        PrivilegeType.CREATE_FUNCTION,
        PrivilegeType.CREATE_VOLUME,
        PrivilegeType.CREATE_MATERIALIZED_VIEW,
        PrivilegeType.CREATE_MODEL,
        PrivilegeType.CREATE_MODEL_VERSION,
    }),
}


def _expand_privilege(
    item: PrivilegeType | AbstractedPrivilegeType,
) -> frozenset[PrivilegeType]:
    """Return the concrete UC privileges represented by ``item``.

    A ``PrivilegeType`` expands to a singleton; an ``AbstractedPrivilegeType``
    expands to its mapped set."""
    if isinstance(item, AbstractedPrivilegeType):
        return ABSTRACT_PRIVILEGE_MAP[item]
    return frozenset({item})


def compile_desired_privileges(
    config: ResourcesConfig,
    desired_tags: set[SecurableTag],
    governed_tag_names: set[str],
    change_logger: ChangeLogger,
    run_date: date | None = None,
) -> set[SecurablePrivilege]:
    """Compute desired privileges by matching grant policies against desired tags.

    For each grant policy, finds objects matching the policy's tag predicate:
    every ``has_tags`` entry must be present (AND semantics) and at least one
    ``has_any_of_tags`` entry must be present (OR semantics) when that field is
    set. When both are given they combine as AND-of-groups. Values match exactly,
    except ``'*'`` which matches any value. Emits a SecurablePrivilege (with
    unresolved Principal) for each (matching_object, principal, privilege_type).

    Every tag key referenced by a grant policy's ``has_tags`` or
    ``has_any_of_tags`` must appear in ``governed_tag_names`` (the union of
    desired + actual governed tag names).
    Policies that reference an ungoverned key are skipped (no privileges
    emitted) and an ``UngovernedTagError`` is logged on ``change_logger`` for
    every offender.
    """
    if run_date is None:
        run_date = date.today()
    tag_index = _build_tag_index(desired_tags)
    policies = _collect_policies(config)
    active_policies = [
        p for p in policies
        if p.expiry_date is None or p.expiry_date > run_date
    ]
    valid_policies = _drop_policies_with_ungoverned_tags(
        active_policies, governed_tag_names, change_logger,
    )
    return _match_policies(valid_policies, tag_index)


def _drop_policies_with_ungoverned_tags(
    policies: list[GrantPolicyConfig],
    governed_tag_names: set[str],
    change_logger: ChangeLogger,
) -> list[GrantPolicyConfig]:
    """Return only the policies whose ``has_tags`` keys are all governed.
    For each dropped policy, log one error per ungoverned key."""
    kept: list[GrantPolicyConfig] = []
    for policy in policies:
        referenced = set(policy.has_tags or {}) | set(policy.has_any_of_tags or {})
        ungoverned = sorted(referenced - governed_tag_names)
        if not ungoverned:
            kept.append(policy)
            continue
        context = (
            f"Grant policy on {_policy_securable_type(policy).value} "
            f"{policy.parent_full_name}"
        )
        for key in ungoverned:
            change_logger.log_error(
                ExecutionError(
                    context=context,
                    exception=UngovernedTagError(
                        f"{context} references ungoverned tag '{key}'"
                    ),
                )
            )
    return kept


def _build_tag_index(
    desired_tags: set[SecurableTag],
) -> dict[str, tuple[SecurableType, set[tuple[str, str | None]]]]:
    """Build a mapping from securable_full_name to (type, set of (tag_name, tag_value)).

    Column-level tags are ignored entirely by the privileges domain — UC has no
    column-level GRANT, and a column tag must not cause any grant (including
    USE_CATALOG / USE_SCHEMA traverse grants) to be emitted on its ancestors. So
    COLUMN securables are excluded here and never participate in policy matching.
    """
    grouped: dict[str, list[SecurableTag]] = defaultdict(list)
    for tag in desired_tags:
        if tag.securable_type == SecurableType.COLUMN:
            continue
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
        for entry in policy.privileges:
            for privilege in _expand_privilege(entry):
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
        if not policy.has_tags and not policy.has_any_of_tags:
            # Tagless policy — grant directly to the attached securable
            sec_type = _policy_securable_type(policy)
            result |= _emit_privileges(sec_type, policy.parent_full_name, policy)
            continue

        # Tag-matching policy — scoped to the attached securable and its children
        for full_name, (sec_type, actual_tags) in tag_index.items():
            if not _is_within_scope(full_name, policy):
                continue
            if not _policy_tags_match(policy, actual_tags):
                continue
            result |= _emit_privileges(sec_type, full_name, policy)
    return result


def _policy_tags_match(
    policy: GrantPolicyConfig,
    actual_tags: set[tuple[str, str | None]],
) -> bool:
    """Return True iff the object satisfies the policy's tag predicate:
    all ``has_tags`` (AND) and at least one ``has_any_of_tags`` (OR) when set.
    Combining both fields is AND-of-groups."""
    if policy.has_tags and not _tags_match(policy.has_tags, actual_tags):
        return False
    if policy.has_any_of_tags and not _tags_match_any(policy.has_any_of_tags, actual_tags):
        return False
    return True


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


def _tags_match_any(
    required: dict[str, str],
    actual_tags: set[tuple[str, str | None]],
) -> bool:
    """Return True iff at least one required tag is present on the object (OR
    semantics). A required value of '*' matches any value for that key; any other
    value must equal the actual value exactly.
    """
    actual_by_key = {key: value for key, value in actual_tags}
    for key, required_value in required.items():
        if key not in actual_by_key:
            continue
        if required_value == _TAG_VALUE_WILDCARD or actual_by_key[key] == required_value:
            return True
    return False
