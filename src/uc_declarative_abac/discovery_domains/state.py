from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DiscoveryDomain:
    """Desired or actual identity, hierarchy, and managed domain description."""

    tag_key: str
    description: str = ""
    domain_id: str = ""
    resource_name: str = ""
    parent_domain_id: str = ""
    parent_tag_key: str = ""


@dataclass
class DiscoveryDomainDiff:
    """Creations, metadata updates, and scoped deletions for Discovery domains."""

    to_create: set[DiscoveryDomain] = field(default_factory=set)
    to_update: set[DiscoveryDomain] = field(default_factory=set)
    to_delete: set[DiscoveryDomain] = field(default_factory=set)
    old_values: dict[str, DiscoveryDomain] = field(default_factory=dict)
