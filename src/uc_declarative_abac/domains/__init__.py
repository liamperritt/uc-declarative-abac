"""domain compilation, diffing, and reconciliation."""

from uc_declarative_abac.domains.compiler import (
    compile_desired_domains,
)
from uc_declarative_abac.domains.differ import compute_domain_diff
from uc_declarative_abac.domains.executor import (
    execute_domain_diff,
)
from uc_declarative_abac.domains.state import (
    Domain,
    DomainDiff,
    DomainIcon,
)

__all__ = [
    "Domain",
    "DomainDiff",
    "DomainIcon",
    "compile_desired_domains",
    "compute_domain_diff",
    "execute_domain_diff",
]
