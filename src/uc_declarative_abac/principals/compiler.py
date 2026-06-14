from __future__ import annotations

from uc_declarative_abac.configs import ResourcesConfig
from uc_declarative_abac.principals.state import Group, Principal
from uc_declarative_abac.types import PrincipalType


def compile_desired_groups(config: ResourcesConfig) -> set[Group]:
    """Produce the set of desired groups declared under resources.groups.

    Each member name becomes an unresolved Principal (principal_type=UNKNOWN,
    name=<display_name>); the differ resolves them against the workspace before
    comparing against actual state. ``external_id`` is never set on the desired
    side — it only appears on actual state for IdP-provisioned groups.
    """
    if not config.groups:
        return set()
    return {
        Group(
            display_name=group.name,
            members=frozenset(
                Principal(PrincipalType.UNKNOWN, name=m)
                for m in (group.members or ())
            ),
        )
        for group in config.groups.values()
    }
