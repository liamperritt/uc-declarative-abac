from __future__ import annotations

from dataclasses import dataclass, field

from uc_governor.types import SecurableType


@dataclass(frozen=True)
class SecurablePrivilege:
    securable_type: SecurableType
    securable_full_name: str
    principal: str
    privilege_type: str


@dataclass
class PrivilegeDiff:
    to_grant: set[SecurablePrivilege] = field(default_factory=set)
    to_revoke: set[SecurablePrivilege] = field(default_factory=set)
