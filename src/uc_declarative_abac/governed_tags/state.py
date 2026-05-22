from __future__ import annotations

from dataclasses import dataclass, field

from uc_declarative_abac.principals.state import Principal


@dataclass(frozen=True)
class GovernedTag:
    """Desired or actual state of an account-level governed tag (tag policy)."""
    name: str
    description: str = ""
    allowed_values: frozenset[str] = frozenset()
    assigners: frozenset[Principal] = frozenset()


@dataclass
class GovernedTagDiff:
    to_create: set[GovernedTag] = field(default_factory=set)
    to_update: set[GovernedTag] = field(default_factory=set)
    to_delete: set[GovernedTag] = field(default_factory=set)
    old_values: dict[str, GovernedTag] = field(default_factory=dict)
