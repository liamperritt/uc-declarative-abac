from __future__ import annotations

from dataclasses import dataclass, field

from uc_abac_governor.types import Principal, PrivilegeType, SecurableType


@dataclass(frozen=True)
class SecurablePrivilege:
    """Represents a privilege on a specific securable object with a resolved principal.
    
    This is a fully resolved, normalised privilege representation used for diffing and
    reconciliation against UC state.
    """
    securable_type: SecurableType
    securable_full_name: str
    principal: Principal
    privilege_type: PrivilegeType


@dataclass(frozen=True)
class UnresolvedPrivilege:
    """Intermediate privilege representation with unresolved principal.

    Used by the privilege compiler (principal is a raw YAML string) and by
    UnityCatalogHelper (principal is a raw grantee string from system tables).
    Must be resolved to SecurablePrivilege (with Principal object) before diffing.
    """
    securable_type: SecurableType
    securable_full_name: str
    principal: str
    privilege_type: PrivilegeType


@dataclass
class PrivilegeDiff:
    to_grant: set[SecurablePrivilege] = field(default_factory=set)
    to_revoke: set[SecurablePrivilege] = field(default_factory=set)
