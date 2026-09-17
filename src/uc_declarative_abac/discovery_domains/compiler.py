from __future__ import annotations

from uc_declarative_abac.discovery_domains.state import DiscoveryDomain
from uc_declarative_abac.governed_tags import GovernedTag
from uc_declarative_abac.utils import OrchestratorError


def _parent_tag_key(tag_key: str) -> str:
    """Validate a Discovery domain tag key and return its parent tag key."""
    segments = tag_key.split("/")
    if len(segments) not in (1, 2) or any(not segment for segment in segments):
        raise OrchestratorError(
            "Discovery domain governed tags must use domain or domain/subdomain "
            f"form; received {tag_key!r}."
        )
    return segments[0] if len(segments) == 2 else ""


def compile_desired_discovery_domains(
    governed_tags: set[GovernedTag],
) -> set[DiscoveryDomain]:
    """Compile every governed tag into a Discovery domain with managed metadata."""
    return {
        DiscoveryDomain(
            tag_key=governed_tag.name,
            description=governed_tag.description,
            parent_tag_key=_parent_tag_key(governed_tag.name),
        )
        for governed_tag in governed_tags
    }
