from __future__ import annotations

from dataclasses import dataclass, field

from uc_abac_governor.types import Principal, PrivilegeType, SecurableType


@dataclass(frozen=True)
class SecurablePrivilege:
    securable_type: SecurableType
    securable_full_name: str
    principal: Principal
    privilege_type: PrivilegeType


@dataclass
class PrivilegeDiff:
    to_grant: set[SecurablePrivilege] = field(default_factory=set)
    to_revoke: set[SecurablePrivilege] = field(default_factory=set)
