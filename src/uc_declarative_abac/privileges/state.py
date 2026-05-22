from __future__ import annotations

from dataclasses import dataclass, field

from uc_declarative_abac.principals.state import Principal
from uc_declarative_abac.types import PrivilegeType, SecurableType


@dataclass(frozen=True)
class SecurablePrivilege:
    """A privilege on a specific securable object for a principal.

    The principal may be unresolved (principal_type=UNKNOWN) when emitted by
    the compiler or fetch helper, and is resolved before diffing.
    """
    securable_type: SecurableType
    securable_full_name: str
    principal: Principal
    privilege_type: PrivilegeType


@dataclass
class PrivilegeDiff:
    to_grant: set[SecurablePrivilege] = field(default_factory=set)
    to_revoke: set[SecurablePrivilege] = field(default_factory=set)
