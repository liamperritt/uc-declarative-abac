from __future__ import annotations

import pytest

from uc_declarative_abac.configs import ResourcesConfig
from uc_declarative_abac.discovery_domains import (
    DiscoveryDomain,
    compile_desired_discovery_domains,
)
from uc_declarative_abac.governed_tags import GovernedTag
from uc_declarative_abac.utils import OrchestratorError


def test_discovery_domain_compiler_builds_only_declared_domain_resources():
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {},
            "governed_tags": {
                "finance": {"description": "Finance domain"},
                "finance/orders": {"description": "Orders subdomain"},
                "human-resources": {"description": "People domain"},
            },
            "domains": {
                "finance-domain": {"governed_tag": "finance"},
                "orders-subdomain": {"governed_tag": "finance/orders"},
            },
        }
    )
    governed_tags = {
        GovernedTag(name="finance", description="Finance domain"),
        GovernedTag(name="finance/orders", description="Orders subdomain"),
        GovernedTag(name="human-resources", description="People domain"),
    }

    result = compile_desired_discovery_domains(config, governed_tags)

    assert result == {
        DiscoveryDomain(tag_key="finance", description="Finance domain"),
        DiscoveryDomain(
            tag_key="finance/orders",
            description="Orders subdomain",
            parent_tag_key="finance",
        ),
    }


def test_discovery_domain_compiler_rejects_missing_governed_tag_reference():
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {},
            "domains": {
                "finance-domain": {"governed_tag": "missing-finance-tag"},
            },
        }
    )

    with pytest.raises(OrchestratorError, match="missing-finance-tag"):
        compile_desired_discovery_domains(config, set())


@pytest.mark.parametrize(
    "governed_tag_name",
    ["finance/orders/history", "/orders", "finance/"],
)
def test_discovery_domain_compiler_rejects_invalid_domain_hierarchy(governed_tag_name):
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {},
            "domains": {
                "invalid-domain": {"governed_tag": governed_tag_name},
            },
        }
    )
    governed_tags = {GovernedTag(name=governed_tag_name)}

    with pytest.raises(OrchestratorError, match="domain/subdomain"):
        compile_desired_discovery_domains(config, governed_tags)
