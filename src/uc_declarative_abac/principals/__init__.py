from __future__ import annotations

from uc_declarative_abac.principals.resolver import (
    ensure_all_resolved,
    ensure_resolved,
    log_principal_resolution_failure,
    PrincipalResolver,
)
from uc_declarative_abac.principals.state import Group, GroupDiff, GroupRename, Principal
from uc_declarative_abac.principals.compiler import compile_desired_groups
from uc_declarative_abac.principals.differ import compute_group_diff
from uc_declarative_abac.principals.executor import execute_group_diff

__all__ = [
    "Group",
    "GroupDiff",
    "GroupRename",
    "Principal",
    "PrincipalResolver",
    "compile_desired_groups",
    "compute_group_diff",
    "ensure_all_resolved",
    "ensure_resolved",
    "execute_group_diff",
    "log_principal_resolution_failure",
]
