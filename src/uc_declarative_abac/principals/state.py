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
        if self.principal_type != PrincipalType.UNKNOWN and (
            not self.name or not self.identifier
        ):
            raise ValueError("Resolved principals must have both name and identifier")


@dataclass(frozen=True)
class Group:
    """Desired or actual state of a Databricks account group.

    Holds the group's display name plus its members and assumers for diffing.
    ``external_id`` is populated on actual state for groups SCIM-provisioned from an
    external IdP; such a group may be declared only without ``members`` (its
    membership is owned by the IdP), but its assumers may still be managed. ``id`` is
    the account SCIM / internal group id: set on the desired side from config (when
    declared) and on the actual side from the fetched group; it lets the differ match
    a group across a display-name change (a rename).

    ``members`` and ``assumers`` are **authoritative only when supplied**: ``None``
    means "unmanaged" — the field is not fetched on the actual side and not reconciled
    (leave the group's current members/assumers alone). A supplied frozenset (including
    the empty one) is authoritative: an empty set removes all. Both carry (resolved or
    unresolved) Principals; resolution happens in the differ before comparison,
    mirroring governed-tag assigners. ``assumers`` are the principals granted the
    ``roles/group.assumer`` role on the group's account access-control ruleset.
    """

    display_name: str
    external_id: str = ""
    members: frozenset[Principal] | None = None
    id: str = ""
    assumers: frozenset[Principal] | None = None


@dataclass(frozen=True)
class GroupRename:
    """A pending rename of an existing account group.

    ``id`` is the group's account SCIM id; ``old_display_name`` is its current
    name in the account and ``new_display_name`` is the name declared in config.
    """

    id: str
    old_display_name: str
    new_display_name: str


@dataclass
class GroupDiff:
    """Computed group-management changes.

    ``groups_to_create`` holds the display names of not-yet-existent groups to create
    (populated only when group creation is enabled — groups are created **empty**;
    their configured members/assumers flow through the management fields below and are
    applied after creation). ``members_to_add`` and ``members_to_remove`` map a group's
    display name to the resolved Principals to add to / remove from it (populated only
    when group management is enabled — for existing groups **and** groups created this
    run, whose actual membership is treated as empty). ``assumers_to_set`` maps a
    group's display name to the full resolved set of desired assumers to write to its
    account access-control ruleset (populated only when that group's assumers changed);
    ``assumers_to_add`` / ``assumers_to_remove`` carry the same change as deltas, for
    logging. ``groups_to_rename`` holds the renames detected by matching a desired
    group's ``id`` to an existing group whose display name differs (populated only under
    group management). ``groups_to_delete`` holds the Databricks-managed account groups
    absent from config that should be deleted (populated only when group deletion is
    enabled; each Group carries ``display_name`` + ``id`` and no members — the executor
    deletes by id). All principal values hold fully-resolved Principals — the differ
    resolves them before they land here.
    """

    members_to_add: dict[str, frozenset[Principal]] = field(default_factory=dict)
    members_to_remove: dict[str, frozenset[Principal]] = field(default_factory=dict)
    groups_to_create: set[str] = field(default_factory=set)
    groups_to_rename: list[GroupRename] = field(default_factory=list)
    groups_to_delete: set[Group] = field(default_factory=set)
    assumers_to_set: dict[str, frozenset[Principal]] = field(default_factory=dict)
    assumers_to_add: dict[str, frozenset[Principal]] = field(default_factory=dict)
    assumers_to_remove: dict[str, frozenset[Principal]] = field(default_factory=dict)
