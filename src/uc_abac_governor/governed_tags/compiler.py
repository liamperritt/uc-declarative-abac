from __future__ import annotations

from uc_abac_governor.configs.models import ResourcesConfig
from uc_abac_governor.governed_tags.state import GovernedTag
from uc_abac_governor.principals.state import Principal
from uc_abac_governor.types import PrincipalType


def compile_desired_governed_tags(config: ResourcesConfig) -> set[GovernedTag]:
    """Produce the set of desired governed tags declared under resources.governed_tags.

    Each name in `assigners` becomes an unresolved Principal
    (principal_type=UNKNOWN, name=<display_name>); the differ resolves them
    against the workspace before comparing against actual state.
    """
    if not config.governed_tags:
        return set()
    return {
        GovernedTag(
            name=gt.name,
            description=gt.description or "",
            allowed_values=frozenset(gt.allowed_values or ()),
            assigners=frozenset(
                Principal(PrincipalType.UNKNOWN, name=p)
                for p in (gt.assigners or ())
            ),
        )
        for gt in config.governed_tags.values()
    }
