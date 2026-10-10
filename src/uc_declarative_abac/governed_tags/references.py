from __future__ import annotations

from uc_declarative_abac.configs import (
    ResourcesConfig,
    iter_policy_configs,
    iter_securable_configs,
)


def _securable_tag_keys(config: ResourcesConfig) -> set[str]:
    """Tag keys set on any securable (functions carry no ``tags``)."""
    return {
        key
        for securable in iter_securable_configs(config)
        for key in getattr(securable, "tags", None) or {}
    }


def _policy_tag_keys(config: ResourcesConfig) -> set[str]:
    """Tag keys any policy's match conditions reference, at any attachment level."""
    return {
        key
        for policy in iter_policy_configs(config)
        for key in policy.referenced_tag_keys()
    }


def collect_referenced_tag_keys(config: ResourcesConfig) -> set[str]:
    """Return every tag key referenced anywhere in ``config``.

    Sources: declared governed-tag names, each domain's ``governed_tag``, the
    ``tags`` keys of every taggable securable (catalogs, schemas, tables, columns,
    volumes), and every key a policy references (``BasePolicyConfig.referenced_tag_keys``
    — policy-level and per-column conditions, identity-attribute tag matches, and
    tag-introspection expressions). These are the same config fields the tag,
    policy, domain and governed-tag compilers read; keep them in sync when a new
    tag-bearing field is added.

    Keys only, derived from config alone (no compiled state). Not every key is
    necessarily a governed tag — callers intersect with the account's actual tag
    policies.
    """
    governed_tag_names = {gt.name for gt in (config.governed_tags or {}).values()}
    domain_tags = {d.governed_tag for d in (config.domains or {}).values()}
    return (
        governed_tag_names
        | domain_tags
        | _securable_tag_keys(config)
        | _policy_tag_keys(config)
    )
