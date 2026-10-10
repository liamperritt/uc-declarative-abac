from __future__ import annotations

from uc_declarative_abac.configs import (
    ResourcesConfig,
    iter_policy_configs,
    iter_securable_configs,
)


def _securable_owners(config: ResourcesConfig) -> set[str]:
    """Owners declared on any securable (columns never declare one)."""
    return {
        s.owner for s in iter_securable_configs(config) if getattr(s, "owner", None)
    }


def _policy_principals(config: ResourcesConfig) -> set[str]:
    """Principals in any policy's ``to`` / ``except``, at any attachment level.

    Grant policies have no ``except``; mask/filter ``to`` defaults to
    ``account users`` when omitted, so that default is included.
    """
    return {
        name
        for policy in iter_policy_configs(config)
        for name in [*policy.to, *(getattr(policy, "exceptions", None) or [])]
    }


def _domain_owners(config: ResourcesConfig) -> set[str]:
    return {
        name
        for domain in (config.domains or {}).values()
        for name in [*(domain.business_owners or []), *(domain.technical_owners or [])]
    }


def _governed_tag_assigners(config: ResourcesConfig) -> set[str]:
    return {
        name for tag in (config.governed_tags or {}).values() for name in tag.assigners
    }


def _group_principals(config: ResourcesConfig) -> set[str]:
    return {
        name
        for group in (config.groups or {}).values()
        for name in [*(group.members or []), *(group.assumers or [])]
    }


def collect_referenced_principal_names(config: ResourcesConfig) -> set[str]:
    """Return the display name of every principal referenced anywhere in ``config``.

    Sources: securable ``owner``s (catalogs, schemas, tables, volumes, functions),
    policy ``to`` / ``except``, domain ``business_owners`` / ``technical_owners``,
    governed-tag ``assigners``, and group ``members`` / ``assumers``. These are the
    same config fields the domain compilers read; keep them in sync when a new
    principal-bearing field is added.

    Names only — no resolution — derived from config alone, so it needs no compiled
    or tag-expanded state. The result mixes users, groups and service principals;
    callers intersect it with whatever principal kind they need (e.g. account
    groups).
    """
    return (
        _securable_owners(config)
        | _policy_principals(config)
        | _domain_owners(config)
        | _governed_tag_assigners(config)
        | _group_principals(config)
    )
