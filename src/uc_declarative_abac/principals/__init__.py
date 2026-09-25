from __future__ import annotations

from uc_declarative_abac.principals.compiler import (
    compile_desired_groups,
    compile_principal_names,
)
from uc_declarative_abac.principals.differ import (
    compute_group_diff,
    groups_pending_creation,
)
from uc_declarative_abac.principals.executor import execute_group_diff
from uc_declarative_abac.principals.resolver import (
    PrincipalResolver,
    ensure_all_resolved,
    ensure_resolved,
    log_principal_resolution_failure,
    principal_to_ruleset_string,
)
from uc_declarative_abac.principals.state import (
    Group,
    GroupDiff,
    GroupRename,
    Principal,
)

__all__ = [
    "Group",
    "GroupDiff",
    "GroupRename",
    "Principal",
    "PrincipalResolver",
    "compile_desired_groups",
    "compile_principal_names",
    "compute_group_diff",
    "ensure_all_resolved",
    "ensure_resolved",
    "execute_group_diff",
    "groups_pending_creation",
    "log_principal_resolution_failure",
    "principal_to_ruleset_string",
]
