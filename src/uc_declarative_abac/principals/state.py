from __future__ import annotations

from dataclasses import dataclass, field

from uc_declarative_abac.types import PrincipalType


@dataclass(frozen=True)
class Principal:
    """A Databricks principal.

    A Principal may be unresolved (principal_type=UNKNOWN, with one of
    name or identifier set but not both) or resolved (principal_type set
    to USER/GROUP/SERVICE_PRINCIPAL, with both name and identifier set).

    Resolution is a runtime transformation performed by PrincipalResolver.
    Executors and loggers call ensure_resolved() to assert the runtime
    invariant before reading .name / .identifier.

    Identifier conventions when resolved:
    - USER: identifier = name = username
    - GROUP: identifier = name = display_name
    - SERVICE_PRINCIPAL: identifier = application_id, name = display_name
    """

    principal_type: PrincipalType
    identifier: str = ""
    name: str = ""

    def __post_init__(self) -> None:
        if not self.name and not self.identifier:
            raise ValueError(
                "Principal must have at least one of name or identifier set"
            )
        if self.principal_type != PrincipalType.UNKNOWN:
            if not self.name or not self.identifier:
                raise ValueError(
                    "Resolved principals must have both name and identifier"
                )


@dataclass(frozen=True)
class Group:
    """Desired or actual state of a Databricks-managed group.

    Holds the group's display name plus its members for diffing. ``external_id``
    is populated on actual state for groups SCIM-provisioned from an external IdP;
    such groups are not Databricks-managed and cannot be configured here.
    ``members`` carries (resolved or unresolved) Principals; resolution happens in
    the differ before comparison, mirroring governed-tag assigners.
    """

    display_name: str
    external_id: str = ""
    members: frozenset[Principal] = frozenset()


@dataclass
class GroupDiff:
    """Computed group-management changes — additions only (no member removals).

    ``members_to_add`` maps an existing group's display name to the resolved
    Principals to add to it. ``groups_to_create`` maps a not-yet-existent group's
    display name to its resolved initial members (populated only when group
    creation is enabled). Both values hold fully-resolved Principals — the differ
    resolves them before they land here.
    """

    members_to_add: dict[str, frozenset[Principal]] = field(default_factory=dict)
    groups_to_create: dict[str, frozenset[Principal]] = field(default_factory=dict)
