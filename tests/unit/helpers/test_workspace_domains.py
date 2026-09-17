from __future__ import annotations

from unittest.mock import MagicMock

from databricks.sdk import WorkspaceClient
from databricks.sdk.service.domains import Domain, FieldMask

from uc_declarative_abac.discovery_domains import DiscoveryDomain
from uc_declarative_abac.helpers import WorkspaceHelper


def test_workspace_helper_fetch_actual_discovery_domains_normalizes_parent_tag_key() -> (
    None
):
    client = MagicMock(spec=WorkspaceClient)
    client.domains.list_domains.return_value = [
        Domain(
            tag_key="finance",
            description="Financial data",
            domain_id="parent-id",
            name="domains/parent-id",
        ),
        Domain(
            tag_key="finance/orders",
            description="Order data",
            domain_id="child-id",
            name="domains/child-id",
            parent_domain_id="parent-id",
        ),
    ]
    helper = WorkspaceHelper(client)

    result = helper.fetch_actual_discovery_domains()

    assert result == {
        DiscoveryDomain(
            tag_key="finance",
            description="Financial data",
            domain_id="parent-id",
            resource_name="domains/parent-id",
        ),
        DiscoveryDomain(
            tag_key="finance/orders",
            description="Order data",
            domain_id="child-id",
            resource_name="domains/child-id",
            parent_domain_id="parent-id",
            parent_tag_key="finance",
        ),
    }
    assert helper.get_discovery_domain_id("finance") == "parent-id"


def test_workspace_helper_create_discovery_domain_uses_sdk_and_caches_result() -> None:
    client = MagicMock(spec=WorkspaceClient)
    client.domains.create_domain.return_value = Domain(
        tag_key="finance/orders",
        domain_id="child-id",
        parent_domain_id="parent-id",
    )
    helper = WorkspaceHelper(client)

    helper.create_discovery_domain(
        "finance/orders",
        description="Financial data",
        parent_domain_id="parent-id",
    )

    client.domains.create_domain.assert_called_once_with(
        Domain(
            tag_key="finance/orders",
            description="Financial data",
            parent_domain_id="parent-id",
        )
    )
    assert helper.get_discovery_domain_id("finance/orders") == "child-id"


def test_workspace_helper_update_discovery_domain_uses_sdk_resource_name_and_update_mask() -> (
    None
):
    client = MagicMock(spec=WorkspaceClient)
    helper = WorkspaceHelper(client)
    domain = DiscoveryDomain(
        tag_key="finance",
        description="Financial data",
        domain_id="domain-id",
        resource_name="domains/domain-id",
    )

    helper.update_discovery_domain(domain, "description")

    client.domains.update_domain.assert_called_once_with(
        name="domains/domain-id",
        domain=Domain(tag_key="finance", description="Financial data"),
        update_mask=FieldMask("description"),
    )
