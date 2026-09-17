from __future__ import annotations

from unittest.mock import MagicMock, call, patch

from databricks.sdk.errors.base import DatabricksError

from uc_declarative_abac.discovery_domains import (
    DiscoveryDomain,
    DiscoveryDomainDiff,
    execute_discovery_domain_diff,
)
from uc_declarative_abac.helpers import WorkspaceHelper
from uc_declarative_abac.logger import ChangeLogger


def test_discovery_domain_executor_creates_parent_before_child() -> None:
    parent = DiscoveryDomain(
        tag_key="finance",
        description="Finance data",
    )
    child = DiscoveryDomain(
        tag_key="finance/orders",
        parent_tag_key="finance",
        description="Finance orders data",
    )
    diff = DiscoveryDomainDiff(to_create={child, parent})
    ws_helper = MagicMock(spec=WorkspaceHelper)
    change_logger = MagicMock(spec=ChangeLogger)
    created_domain_ids: dict[str, str] = {}

    def create_discovery_domain(
        tag_key: str,
        *,
        description: str,
        parent_domain_id: str,
    ) -> None:
        if tag_key == "finance":
            created_domain_ids[tag_key] = "parent-id"

    ws_helper.create_discovery_domain.side_effect = create_discovery_domain
    ws_helper.get_discovery_domain_id.side_effect = created_domain_ids.get

    execute_discovery_domain_diff(ws_helper, diff, change_logger, dry_run=False)

    assert ws_helper.create_discovery_domain.call_args_list == [
        call(
            "finance",
            description="Finance data",
            parent_domain_id="",
        ),
        call(
            "finance/orders",
            description="Finance orders data",
            parent_domain_id="parent-id",
        ),
    ]
    assert change_logger.log_discovery_domain_create.call_args_list == [
        call(parent),
        call(child),
    ]


def test_discovery_domain_executor_logs_error_and_skips_child_when_parent_creation_fails() -> (
    None
):
    parent = DiscoveryDomain(tag_key="finance")
    child = DiscoveryDomain(
        tag_key="finance/orders",
        parent_tag_key="finance",
    )
    diff = DiscoveryDomainDiff(to_create={child, parent})
    ws_helper = MagicMock(spec=WorkspaceHelper)
    ws_helper.create_discovery_domain.side_effect = DatabricksError("boom")
    ws_helper.get_discovery_domain_id.return_value = None
    change_logger = ChangeLogger(dry_run=False)

    execute_discovery_domain_diff(ws_helper, diff, change_logger, dry_run=False)

    ws_helper.create_discovery_domain.assert_called_once_with(
        "finance",
        description="",
        parent_domain_id="",
    )
    assert change_logger.has_errors


def test_discovery_domain_executor_updates_description_and_logs_old_value() -> None:
    old_domain = DiscoveryDomain(
        tag_key="finance",
        description="Legacy description",
        domain_id="domain-id",
        resource_name="domains/domain-id",
    )
    updated_domain = DiscoveryDomain(
        tag_key="finance",
        description="Finance data",
        domain_id="domain-id",
        resource_name="domains/domain-id",
    )
    diff = DiscoveryDomainDiff(
        to_update={updated_domain},
        old_values={"finance": old_domain},
    )
    ws_helper = MagicMock(spec=WorkspaceHelper)
    change_logger = MagicMock(spec=ChangeLogger)

    execute_discovery_domain_diff(ws_helper, diff, change_logger, dry_run=False)

    ws_helper.update_discovery_domain.assert_called_once_with(
        updated_domain,
        update_mask="description",
    )
    change_logger.log_discovery_domain_update.assert_called_once_with(
        updated_domain,
        old_domain,
    )


def test_discovery_domain_executor_logs_fatal_error_without_success_when_description_update_fails() -> (
    None
):
    old_domain = DiscoveryDomain(
        tag_key="finance",
        description="Legacy description",
        domain_id="domain-id",
        resource_name="domains/domain-id",
    )
    updated_domain = DiscoveryDomain(
        tag_key="finance",
        description="Finance data",
        domain_id="domain-id",
        resource_name="domains/domain-id",
    )
    diff = DiscoveryDomainDiff(
        to_update={updated_domain},
        old_values={"finance": old_domain},
    )
    ws_helper = MagicMock(spec=WorkspaceHelper)
    ws_helper.update_discovery_domain.side_effect = DatabricksError("boom")
    change_logger = ChangeLogger(dry_run=False)

    with patch.object(
        change_logger,
        "log_discovery_domain_update",
        wraps=change_logger.log_discovery_domain_update,
    ) as log_update:
        execute_discovery_domain_diff(ws_helper, diff, change_logger, dry_run=False)

    assert change_logger.has_errors
    assert change_logger.errors[0].context == "Update Discovery domain 'finance'"
    log_update.assert_not_called()
