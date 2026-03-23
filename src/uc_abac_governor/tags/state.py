from __future__ import annotations

from dataclasses import dataclass, field

from uc_abac_governor.types import SecurableType


@dataclass(frozen=True)
class SecurableTag:
    securable_type: SecurableType
    securable_full_name: str
    tag_name: str
    tag_value: str | None = None


@dataclass
class TagDiff:
    to_add: set[SecurableTag] = field(default_factory=set)
    to_update: set[SecurableTag] = field(default_factory=set)
    to_remove: set[SecurableTag] = field(default_factory=set)
