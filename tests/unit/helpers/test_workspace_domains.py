from __future__ import annotations

from unittest.mock import MagicMock

from databricks.sdk import WorkspaceClient
from databricks.sdk.service.domains import (
    Domain as SdkDomain,
)
from databricks.sdk.service.domains import (
    DomainIcon as SdkDomainIcon,
)
from databricks.sdk.service.domains import (
    DomainIconName,
    FieldMask,
)

from uc_declarative_abac.domains import Domain, DomainIcon
from uc_declarative_abac.helpers import WorkspaceHelper


def test_workspace_helper_fetch_actual_domains_normalizes_parent_tag_key() -> None:
    client = MagicMock(spec=WorkspaceClient)
    client.domains.list_domains.return_value = [
        SdkDomain(
            tag_key="finance",
            description="Financial data",
            domain_id="parent-id",
            name="domains/parent-id",
        ),
        SdkDomain(
            tag_key="finance/orders",
            description="Order data",
            domain_id="child-id",
            name="domains/child-id",
            parent_domain_id="parent-id",
        ),
    ]
    helper = WorkspaceHelper(client)

    result = helper.fetch_actual_domains()

    assert result == {
        Domain(
            tag_key="finance",
            description="Financial data",
            domain_id="parent-id",
            resource_name="domains/parent-id",
        ),
        Domain(
            tag_key="finance/orders",
            description="Order data",
            domain_id="child-id",
            resource_name="domains/child-id",
            parent_domain_id="parent-id",
            parent_tag_key="finance",
        ),
    }
    assert helper.get_domain_id("finance") == "parent-id"


def test_workspace_helper_create_domain_uses_sdk_and_caches_result() -> None:
    client = MagicMock(spec=WorkspaceClient)
    client.domains.create_domain.return_value = SdkDomain(
        tag_key="finance/orders",
        domain_id="child-id",
        parent_domain_id="parent-id",
    )
    helper = WorkspaceHelper(client)

    helper.create_domain(
        "finance/orders",
        description="Financial data",
        parent_domain_id="parent-id",
    )

    client.domains.create_domain.assert_called_once_with(
        SdkDomain(
            tag_key="finance/orders",
            description="Financial data",
            parent_domain_id="parent-id",
        )
    )
    assert helper.get_domain_id("finance/orders") == "child-id"


def test_workspace_helper_update_domain_uses_sdk_resource_name_and_update_mask() -> (
    None
):
    client = MagicMock(spec=WorkspaceClient)
    helper = WorkspaceHelper(client)
    domain = Domain(
        tag_key="finance",
        description="Financial data",
        domain_id="domain-id",
        resource_name="domains/domain-id",
    )

    helper.update_domain(domain, ("description",))

    client.domains.update_domain.assert_called_once_with(
        name="domains/domain-id",
        domain=SdkDomain(tag_key="finance", description="Financial data"),
        update_mask=FieldMask(["description"]),
    )


def test_workspace_helper_update_domain_builds_multi_field_mask_and_body() -> None:
    client = MagicMock(spec=WorkspaceClient)
    helper = WorkspaceHelper(client)
    domain = Domain(
        tag_key="finance",
        description="Fin",
        subtitle="Sub",
        draft=True,
        icon=DomainIcon(name="BANK", color="#1B5E20"),
        domain_id="d",
        resource_name="domains/d",
    )

    helper.update_domain(domain, ("description", "subtitle", "draft", "icon"))

    client.domains.update_domain.assert_called_once_with(
        name="domains/d",
        domain=SdkDomain(
            tag_key="finance",
            description="Fin",
            subtitle="Sub",
            draft=True,
            icon=SdkDomainIcon(name=DomainIconName.BANK, color="#1B5E20"),
        ),
        update_mask=FieldMask(["description", "subtitle", "draft", "icon"]),
    )


def test_workspace_helper_create_domain_includes_metadata_attributes() -> None:
    client = MagicMock(spec=WorkspaceClient)
    client.domains.create_domain.return_value = SdkDomain(
        tag_key="finance",
        domain_id="id",
    )
    helper = WorkspaceHelper(client)

    helper.create_domain(
        "finance",
        description="Fin",
        parent_domain_id="",
        subtitle="Sub",
        draft=True,
        icon=DomainIcon(name="ROCKET", color="#FF5733"),
    )

    client.domains.create_domain.assert_called_once_with(
        SdkDomain(
            tag_key="finance",
            description="Fin",
            parent_domain_id=None,
            subtitle="Sub",
            draft=True,
            icon=SdkDomainIcon(name=DomainIconName.ROCKET, color="#FF5733"),
        )
    )


def test_workspace_helper_fetch_actual_domains_includes_metadata_attributes() -> None:
    client = MagicMock(spec=WorkspaceClient)
    client.domains.list_domains.return_value = [
        SdkDomain(
            tag_key="finance",
            description="Fin",
            subtitle="Sub",
            draft=True,
            effective_draft=True,
            icon=SdkDomainIcon(name=DomainIconName.BANK, color="#1B5E20"),
            domain_id="id",
            name="domains/id",
        )
    ]
    helper = WorkspaceHelper(client)

    result = helper.fetch_actual_domains()

    assert result == {
        Domain(
            tag_key="finance",
            description="Fin",
            subtitle="Sub",
            draft=True,
            icon=DomainIcon(name="BANK", color="#1B5E20"),
            domain_id="id",
            resource_name="domains/id",
        )
    }


def test_workspace_helper_fetch_actual_domains_falls_back_to_effective_draft() -> None:
    client = MagicMock(spec=WorkspaceClient)
    client.domains.list_domains.return_value = [
        SdkDomain(
            tag_key="finance",
            draft=None,
            effective_draft=True,
            domain_id="id",
            name="domains/id",
        )
    ]
    helper = WorkspaceHelper(client)

    result = helper.fetch_actual_domains()

    assert len(result) == 1
    domain = next(iter(result))
    assert domain.draft is True


def test_workspace_helper_delete_domain_uses_sdk_resource_name() -> None:
    client = MagicMock(spec=WorkspaceClient)
    helper = WorkspaceHelper(client)
    domain = Domain(
        tag_key="finance",
        resource_name="domains/domain-id",
    )

    helper.delete_domain(domain)

    client.domains.delete_domain.assert_called_once_with(name="domains/domain-id")
