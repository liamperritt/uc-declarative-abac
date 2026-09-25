from __future__ import annotations

from datetime import UTC, date, datetime

from uc_declarative_abac.configs import ResourcesConfig
from uc_declarative_abac.principals.state import Group, Principal
from uc_declarative_abac.types import PrincipalType


def compile_principal_names(names: list[str] | None) -> frozenset[Principal] | None:
    """Compile a config principal-name list into unresolved Principals.

    Preserves the authoritative-only-when-supplied contract: ``None`` (the field
    omitted) stays ``None`` (unmanaged), while a supplied list — including the empty
    one — becomes a frozenset (authoritative), so an empty list reconciles to
    "remove all". Each name becomes an unresolved Principal that the differ resolves
    against the workspace before comparison. Shared by the groups compiler
    (members/assumers) and the domains compiler (business/technical owners)."""
    if names is None:
        return None
    return frozenset(Principal(PrincipalType.UNKNOWN, name=n) for n in names)


def compile_desired_groups(
    config: ResourcesConfig,
    run_date: date | None = None,
) -> set[Group]:
    """Produce the set of desired groups declared under resources.groups.

    Each member/assumer name becomes an unresolved Principal (principal_type=UNKNOWN,
    name=<display_name>); the differ resolves them against the workspace before
    comparing against actual state. ``id`` is carried through from config (when
    declared) so the differ can match the group across a display-name change.
    ``external_id`` is never set on the desired side — it only appears on actual
    state for IdP-provisioned groups.

    ``members`` and ``assumers`` follow the authoritative-only-when-supplied contract
    (see ``compile_principal_names``): an omitted field compiles to ``None`` (unmanaged —
    not fetched, not reconciled), while a supplied list (including the empty one) is
    authoritative.

    A group whose ``expiry_date`` is on or before ``run_date`` (defaulting to today in
    UTC) is *expired*: it is still emitted with its name and id, but with **empty
    members and empty assumers** (both authoritative), so the differ removes every
    current member and every assumer under ``--group-management-scopes`` while leaving
    the group in place (it is not deleted). Mirrors the grant-policy expiry filter in
    ``compile_desired_privileges``.
    """
    if not config.groups:
        return set()
    if run_date is None:
        run_date = datetime.now(UTC).date()
    desired: set[Group] = set()
    for group in config.groups.values():
        expired = group.expiry_date is not None and group.expiry_date <= run_date
        members = frozenset() if expired else compile_principal_names(group.members)
        assumers = frozenset() if expired else compile_principal_names(group.assumers)
        desired.add(
            Group(
                display_name=group.name,
                id=group.id or "",
                members=members,
                assumers=assumers,
            )
        )
    return desired
