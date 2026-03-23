from __future__ import annotations

from collections import defaultdict

from uc_governor.models import ConfigFile, GrantPolicyConfig
from uc_governor.privileges.state import SecurablePrivilege
from uc_governor.tags.state import SecurableTag
from uc_governor.types import SecurableType


def compile_desired_privileges(
    config: ConfigFile,
    desired_tags: set[SecurableTag],
) -> set[SecurablePrivilege]:
    """Compute desired privileges by matching grant policies against desired tags.

    For each catalog's grant policies, finds objects whose tags are a superset
    of the policy's tags (AND semantics, exact value match). Emits a
    SecurablePrivilege for each (matching_object, principal, privilege_type).

    Takes desired_tags as input so it can match policies against the tag state
    without reaching into the tags domain's internals.
    """
    tag_index = _build_tag_index(desired_tags)
    policies = _collect_policies(config)
    return _match_policies(policies, tag_index, desired_tags)


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
    """Gather all grant policies across all catalogs."""
    return [
        policy
        for catalog in config.catalogs.values()
        if catalog.policies
        for policy in catalog.policies
    ]


def _match_policies(
    policies: list[GrantPolicyConfig],
    tag_index: dict[str, tuple[SecurableType, set[tuple[str, str | None]]]],
    desired_tags: set[SecurableTag],
) -> set[SecurablePrivilege]:
    """Match policies against the tag index and emit privileges."""
    result: set[SecurablePrivilege] = set()
    for policy in policies:
        required = {(k, v) for k, v in policy.tags.items()}
        for full_name, (sec_type, actual_tags) in tag_index.items():
            if not required.issubset(actual_tags):
                continue
            for principal in policy.to:
                for privilege in policy.privileges:
                    result.add(
                        SecurablePrivilege(
                            securable_type=sec_type,
                            securable_full_name=full_name,
                            principal=principal,
                            privilege_type=privilege.upper(),
                        )
                    )
    return result
