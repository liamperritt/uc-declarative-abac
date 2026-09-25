from __future__ import annotations

from uc_declarative_abac.configs import DomainConfig, ResourcesConfig
from uc_declarative_abac.domains.state import (
    Domain,
    DomainIcon,
)
from uc_declarative_abac.governed_tags import GovernedTag
from uc_declarative_abac.utils import OrchestratorError


def _parent_tag_key(tag_key: str) -> str:
    """Validate a domain tag key and return its parent tag key."""
    segments = tag_key.split("/")
    if len(segments) not in (1, 2) or any(not segment for segment in segments):
        raise OrchestratorError(
            "domain governed tags must use domain or domain/subdomain "
            f"form; received {tag_key!r}."
        )
    return segments[0] if len(segments) == 2 else ""


def _compile_domain(
    domain: DomainConfig, governed_tags_by_name: dict[str, GovernedTag]
) -> Domain:
    """Compile a single domain configuration into a Domain.

    Resolves description from the domain's explicit value if set, otherwise falls
    back to the referenced governed tag's description. Includes subtitle, draft, and
    icon metadata when supplied in the domain config.
    """
    description = (
        domain.description or governed_tags_by_name[domain.governed_tag].description
    )
    icon = (
        DomainIcon(
            name=domain.icon.name,
            color=domain.icon.color or "",
        )
        if domain.icon
        else None
    )
    return Domain(
        tag_key=domain.governed_tag,
        description=description,
        subtitle=domain.subtitle,
        draft=domain.draft,
        icon=icon,
        parent_tag_key=_parent_tag_key(domain.governed_tag),
    )


def compile_desired_domains(
    config: ResourcesConfig,
    governed_tags: set[GovernedTag],
) -> set[Domain]:
    """Compile explicitly declared domain resources with tag-derived metadata."""
    if not config.domains:
        return set()

    governed_tags_by_name = {tag.name: tag for tag in governed_tags}
    missing_governed_tags = {
        domain.governed_tag
        for domain in config.domains.values()
        if domain.governed_tag not in governed_tags_by_name
    }
    if missing_governed_tags:
        missing_names = ", ".join(sorted(missing_governed_tags))
        raise OrchestratorError(
            f"domains reference missing governed tags: {missing_names}."
        )

    return {
        _compile_domain(domain, governed_tags_by_name)
        for domain in config.domains.values()
    }
