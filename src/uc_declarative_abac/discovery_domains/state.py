from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DomainIcon:
    """A Discovery domain's display icon: a named glyph plus an optional hex colour."""

    name: str = ""
    color: str = ""


@dataclass(frozen=True)
class DiscoveryDomain:
    """Desired or actual identity, hierarchy, and managed domain metadata.

    ``description`` is always authoritative (an explicit domain value, or the
    referenced governed tag's description as a fallback). ``subtitle``, ``draft``,
    and ``icon`` are managed only when supplied: ``None`` means "leave the server
    value alone" (unmanaged), so omitting them never clobbers values set outside
    this tool and never produces diff churn.
    """

    tag_key: str
    description: str = ""
    subtitle: str | None = None
    draft: bool | None = None
    icon: DomainIcon | None = None
    domain_id: str = ""
    resource_name: str = ""
    parent_domain_id: str = ""
    parent_tag_key: str = ""


@dataclass
class DiscoveryDomainDiff:
    """Creations, metadata updates, and scoped deletions for Discovery domains.

    ``update_masks`` maps a domain's tag key to the field paths that changed, so
    the executor updates only the attributes that differ from actual state.
    """

    to_create: set[DiscoveryDomain] = field(default_factory=set)
    to_update: set[DiscoveryDomain] = field(default_factory=set)
    to_delete: set[DiscoveryDomain] = field(default_factory=set)
    old_values: dict[str, DiscoveryDomain] = field(default_factory=dict)
    update_masks: dict[str, tuple[str, ...]] = field(default_factory=dict)
