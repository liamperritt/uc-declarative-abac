"""Unity Catalog Discovery domain compilation, diffing, and reconciliation."""

from uc_declarative_abac.discovery_domains.compiler import (
    compile_desired_discovery_domains,
)
from uc_declarative_abac.discovery_domains.differ import compute_discovery_domain_diff
from uc_declarative_abac.discovery_domains.executor import (
    execute_discovery_domain_diff,
)
from uc_declarative_abac.discovery_domains.state import (
    DiscoveryDomain,
    DiscoveryDomainDiff,
    DomainIcon,
)

__all__ = [
    "DiscoveryDomain",
    "DiscoveryDomainDiff",
    "DomainIcon",
    "compile_desired_discovery_domains",
    "compute_discovery_domain_diff",
    "execute_discovery_domain_diff",
]
