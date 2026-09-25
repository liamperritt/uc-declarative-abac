from __future__ import annotations

from types import SimpleNamespace
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
from uc_declarative_abac.principals import Principal
from uc_declarative_abac.types import PrincipalType


def _make_user(user_name: str, user_id: str) -> SimpleNamespace:
    return SimpleNamespace(username=user_name, user_id=user_id)


def _make_group(display_name: str, group_id: str) -> SimpleNamespace:
    return SimpleNamespace(group_name=display_name, group_id=group_id, external_id="")


def _client_with_principals(
    users: list[SimpleNamespace] | None = None,
    groups: list[SimpleNamespace] | None = None,
) -> MagicMock:
    """A WorkspaceClient mock whose V2 list proxies serve the given principals, so
    fetch_principals can build the numeric-id maps owner conversion depends on."""
    client = MagicMock()
    iam = client.workspace_iam_v2
    iam.list_users_proxy.side_effect = lambda **kwargs: iter(users or [])
    iam.list_groups_proxy.side_effect = lambda **kwargs: iter(groups or [])
    iam.list_service_principals_proxy.side_effect = lambda **kwargs: iter([])
    return client


def _resolved_user(name: str, identifier: str) -> Principal:
    return Principal(PrincipalType.USER, name=name, identifier=identifier)


def _resolved_group(name: str) -> Principal:
    return Principal(PrincipalType.GROUP, name=name, identifier=name)


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


# ---
# Owner reconciliation (business_owner_ids / technical_owner_ids)


def test_workspace_helper_create_domain_sets_owner_ids_from_resolved_principals() -> (
    None
):
    client = _client_with_principals(
        users=[_make_user("alice@co", "1")],
        groups=[_make_group("finance-stewards", "10")],
    )
    client.domains.create_domain.return_value = SdkDomain(
        tag_key="finance", domain_id="id"
    )
    helper = WorkspaceHelper(client, manage_domain_owners=True)
    helper.fetch_principals()

    helper.create_domain(
        "finance",
        description="Fin",
        business_owners=frozenset({_resolved_group("finance-stewards")}),
        technical_owners=frozenset({_resolved_user("alice", "alice@co")}),
    )

    client.domains.create_domain.assert_called_once_with(
        SdkDomain(
            tag_key="finance",
            description="Fin",
            parent_domain_id=None,
            business_owner_ids=[10],
            technical_owner_ids=[1],
        )
    )


def test_workspace_helper_update_domain_builds_owner_mask_and_id_body() -> None:
    client = _client_with_principals(users=[_make_user("alice@co", "1")])
    helper = WorkspaceHelper(client, manage_domain_owners=True)
    helper.fetch_principals()
    domain = Domain(
        tag_key="finance",
        domain_id="d",
        resource_name="domains/d",
        business_owners=frozenset({_resolved_user("alice", "alice@co")}),
    )

    helper.update_domain(domain, ("business_owner_ids",))

    client.domains.update_domain.assert_called_once_with(
        name="domains/d",
        domain=SdkDomain(tag_key="finance", business_owner_ids=[1]),
        update_mask=FieldMask(["business_owner_ids"]),
    )


def test_workspace_helper_fetch_actual_domains_maps_owner_ids_to_principals() -> None:
    client = _client_with_principals(
        users=[_make_user("alice@co", "1")],
        groups=[_make_group("finance-stewards", "10")],
    )
    client.domains.list_domains.return_value = [
        SdkDomain(
            tag_key="finance",
            domain_id="id",
            name="domains/id",
            business_owner_ids=[10],
            technical_owner_ids=[1],
        )
    ]
    helper = WorkspaceHelper(client, manage_domain_owners=True)
    helper.fetch_principals()

    result = helper.fetch_actual_domains()

    domain = next(iter(result))
    assert domain.business_owners == frozenset(
        {Principal(PrincipalType.UNKNOWN, identifier="finance-stewards")}
    )
    assert domain.technical_owners == frozenset(
        {Principal(PrincipalType.UNKNOWN, identifier="alice@co")}
    )


def test_workspace_helper_delete_domain_uses_sdk_resource_name() -> None:
    client = MagicMock(spec=WorkspaceClient)
    helper = WorkspaceHelper(client)
    domain = Domain(
        tag_key="finance",
        resource_name="domains/domain-id",
    )

    helper.delete_domain(domain)

    client.domains.delete_domain.assert_called_once_with(name="domains/domain-id")
