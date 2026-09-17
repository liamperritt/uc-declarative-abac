from __future__ import annotations

import pytest

from uc_declarative_abac.discovery_domains import (
    DiscoveryDomain,
    compile_desired_discovery_domains,
)
from uc_declarative_abac.governed_tags import GovernedTag
from uc_declarative_abac.utils import OrchestratorError


def test_discovery_domain_compiler_builds_domains_from_all_governed_tags():
    governed_tags = {
        GovernedTag(name="finance", description="Finance domain"),
        GovernedTag(name="finance/orders", description="Orders subdomain"),
        GovernedTag(name="human-resources", description="People domain"),
    }

    result = compile_desired_discovery_domains(governed_tags)

    assert result == {
        DiscoveryDomain(tag_key="finance", description="Finance domain"),
        DiscoveryDomain(
            tag_key="finance/orders",
            description="Orders subdomain",
            parent_tag_key="finance",
        ),
        DiscoveryDomain(tag_key="human-resources", description="People domain"),
    }


@pytest.mark.parametrize(
    "governed_tag_name",
    ["finance/orders/history", "/orders", "finance/"],
)
def test_discovery_domain_compiler_rejects_invalid_domain_hierarchy(governed_tag_name):
    governed_tags = {GovernedTag(name=governed_tag_name)}

    with pytest.raises(OrchestratorError, match="domain/subdomain"):
        compile_desired_discovery_domains(governed_tags)
