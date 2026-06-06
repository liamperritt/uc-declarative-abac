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
    groups: frozenset[str] = field(default=frozenset(), compare=False)  # Not currently used

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
