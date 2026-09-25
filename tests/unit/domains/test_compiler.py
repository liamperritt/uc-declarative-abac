from __future__ import annotations

import pytest

from uc_declarative_abac.configs import ResourcesConfig
from uc_declarative_abac.domains import (
    Domain,
    DomainIcon,
    compile_desired_domains,
)
from uc_declarative_abac.governed_tags import GovernedTag
from uc_declarative_abac.utils import OrchestratorError


def test_domain_compiler_builds_only_declared_domain_resources():
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

    result = compile_desired_domains(config, governed_tags)

    assert result == {
        Domain(tag_key="finance", description="Finance domain"),
        Domain(
            tag_key="finance/orders",
            description="Orders subdomain",
            parent_tag_key="finance",
        ),
    }


def test_domain_compiler_rejects_missing_governed_tag_reference():
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {},
            "domains": {
                "finance-domain": {"governed_tag": "missing-finance-tag"},
            },
        }
    )

    with pytest.raises(OrchestratorError, match="missing-finance-tag"):
        compile_desired_domains(config, set())


@pytest.mark.parametrize(
    "governed_tag_name",
    ["finance/orders/history", "/orders", "finance/"],
)
def test_domain_compiler_rejects_invalid_domain_hierarchy(governed_tag_name):
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
        compile_desired_domains(config, governed_tags)


# ---


def test_domain_compiler_uses_explicit_description_over_governed_tag():
    """Domain declares description; its governed tag also has description.
    Assert the compiled Domain uses the explicit description."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {},
            "governed_tags": {
                "finance": {"description": "Governed tag description"},
            },
            "domains": {
                "finance-domain": {
                    "governed_tag": "finance",
                    "description": "Explicit domain description",
                },
            },
        }
    )
    governed_tags = {
        GovernedTag(name="finance", description="Governed tag description"),
    }

    result = compile_desired_domains(config, governed_tags)
    domain = next(d for d in result if d.tag_key == "finance")

    assert domain.description == "Explicit domain description"


def test_domain_compiler_compiles_subtitle_draft_and_icon():
    """Domain declares subtitle/draft/icon with governed_tag.
    Assert the compiled Domain has these fields set correctly."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {},
            "governed_tags": {
                "finance": {"description": "Governed tag description"},
            },
            "domains": {
                "finance-domain": {
                    "governed_tag": "finance",
                    "description": "Explicit domain description",
                    "subtitle": "Financial data assets",
                    "draft": True,
                    "icon": {"name": "BANK", "color": "#1B5E20"},
                },
            },
        }
    )
    governed_tags = {
        GovernedTag(name="finance", description="Governed tag description"),
    }

    result = compile_desired_domains(config, governed_tags)
    domain = next(d for d in result if d.tag_key == "finance")

    assert domain.subtitle == "Financial data assets"
    assert domain.draft is True
    assert domain.icon == DomainIcon(name="BANK", color="#1B5E20")


def test_domain_compiler_leaves_metadata_none_when_omitted():
    """Domain declares only governed_tag (no subtitle/draft/icon/description).
    Assert the compiled Domain has subtitle/draft/icon as None
    and description falls back to the governed tag's description."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {},
            "governed_tags": {
                "finance": {"description": "Governed tag description"},
            },
            "domains": {
                "finance-domain": {
                    "governed_tag": "finance",
                },
            },
        }
    )
    governed_tags = {
        GovernedTag(name="finance", description="Governed tag description"),
    }

    result = compile_desired_domains(config, governed_tags)
    domain = next(d for d in result if d.tag_key == "finance")

    assert domain.subtitle is None
    assert domain.draft is None
    assert domain.icon is None
    assert domain.description == "Governed tag description"
