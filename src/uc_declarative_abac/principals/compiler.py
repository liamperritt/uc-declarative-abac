from __future__ import annotations

from datetime import UTC, date, datetime

from uc_declarative_abac.configs import ResourcesConfig
from uc_declarative_abac.principals.state import Group, Principal
from uc_declarative_abac.types import PrincipalType


def compile_desired_groups(
    config: ResourcesConfig,
    run_date: date | None = None,
) -> set[Group]:
    """Produce the set of desired groups declared under resources.groups.

    Each member name becomes an unresolved Principal (principal_type=UNKNOWN,
    name=<display_name>); the differ resolves them against the workspace before
    comparing against actual state. ``id`` is carried through from config (when
    declared) so the differ can match the group across a display-name change.
    ``external_id`` is never set on the desired side — it only appears on actual
    state for IdP-provisioned groups.

    A group whose ``expiry_date`` is on or before ``run_date`` (defaulting to today
    in UTC) is *expired*: it is still emitted with its name and id, but with **empty
    members**, so the differ's membership reconciliation removes every current member
    under ``--enable-group-management`` while leaving the group in place (it is not
    deleted). Mirrors the grant-policy expiry filter in ``compile_desired_privileges``.
    """
    if not config.groups:
        return set()
    if run_date is None:
        run_date = datetime.now(UTC).date()
    desired: set[Group] = set()
    for group in config.groups.values():
        expired = group.expiry_date is not None and group.expiry_date <= run_date
        members = (
            frozenset()
            if expired
            else frozenset(
                Principal(PrincipalType.UNKNOWN, name=m) for m in (group.members or ())
            )
        )
        desired.add(
            Group(
                display_name=group.name,
                id=group.id or "",
                members=members,
            )
        )
    return desired
