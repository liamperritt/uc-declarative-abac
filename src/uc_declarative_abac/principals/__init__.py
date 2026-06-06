from __future__ import annotations

from uc_declarative_abac.principals.resolver import (
    ensure_all_resolved,
    ensure_resolved,
    log_principal_resolution_failure,
    PrincipalResolver,
)
from uc_declarative_abac.principals.state import Principal

__all__ = [
    "Principal",
    "PrincipalResolver",
    "ensure_all_resolved",
    "ensure_resolved",
    "log_principal_resolution_failure",
]
