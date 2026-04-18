from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class GovernedTag:
    """Desired or actual state of an account-level governed tag (tag policy)."""
    name: str
    comment: str = ""
    allowed_values: frozenset[str] = frozenset()


@dataclass
class GovernedTagDiff:
    to_create: set[GovernedTag] = field(default_factory=set)
    to_update: set[GovernedTag] = field(default_factory=set)
    old_values: dict[str, GovernedTag] = field(default_factory=dict)
