from __future__ import annotations

from uc_abac_governor.configs.models import ResourcesConfig
from uc_abac_governor.governed_tags.state import GovernedTag


def compile_desired_governed_tags(config: ResourcesConfig) -> set[GovernedTag]:
    """Produce the set of desired governed tags declared under resources.governed_tags."""
    if not config.governed_tags:
        return set()
    return {
        GovernedTag(
            name=gt.name,
            comment=gt.comment or "",
            allowed_values=frozenset(gt.allowed_values or ()),
        )
        for gt in config.governed_tags.values()
    }
