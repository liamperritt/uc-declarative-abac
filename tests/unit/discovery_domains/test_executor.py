from __future__ import annotations

from unittest.mock import MagicMock, call, patch

from databricks.sdk.errors.base import DatabricksError

from uc_declarative_abac.discovery_domains import (
    DiscoveryDomain,
    DiscoveryDomainDiff,
    DomainIcon,
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
        subtitle: str | None,
        draft: bool | None,
        icon: DomainIcon | None,
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
            subtitle=None,
            draft=None,
            icon=None,
        ),
        call(
            "finance/orders",
            description="Finance orders data",
            parent_domain_id="parent-id",
            subtitle=None,
            draft=None,
            icon=None,
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
        subtitle=None,
        draft=None,
        icon=None,
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
        update_masks={"finance": ("description",)},
    )
    ws_helper = MagicMock(spec=WorkspaceHelper)
    change_logger = MagicMock(spec=ChangeLogger)

    execute_discovery_domain_diff(ws_helper, diff, change_logger, dry_run=False)

    ws_helper.update_discovery_domain.assert_called_once_with(
        updated_domain,
        update_mask=("description",),
    )
    change_logger.log_discovery_domain_update.assert_called_once_with(
        updated_domain,
        old_domain,
    )


def test_discovery_domain_executor_forwards_metadata_attributes_on_create() -> None:
    domain = DiscoveryDomain(
        tag_key="finance",
        description="Fin",
        subtitle="Sub",
        draft=True,
        icon=DomainIcon(name="ROCKET", color="#FF5733"),
    )
    diff = DiscoveryDomainDiff(to_create={domain})
    ws_helper = MagicMock(spec=WorkspaceHelper)
    ws_helper.get_discovery_domain_id.return_value = None
    change_logger = MagicMock(spec=ChangeLogger)

    execute_discovery_domain_diff(ws_helper, diff, change_logger, dry_run=False)

    ws_helper.create_discovery_domain.assert_called_once_with(
        "finance",
        description="Fin",
        parent_domain_id="",
        subtitle="Sub",
        draft=True,
        icon=DomainIcon(name="ROCKET", color="#FF5733"),
    )


def test_discovery_domain_executor_forwards_computed_update_mask() -> None:
    domain = DiscoveryDomain(
        tag_key="finance",
        description="Fin",
        subtitle="Sub",
        draft=True,
        icon=DomainIcon(name="BANK", color="#1B5E20"),
        domain_id="d",
        resource_name="domains/d",
    )
    old_domain = DiscoveryDomain(
        tag_key="finance",
        description="Old",
        domain_id="d",
        resource_name="domains/d",
    )
    diff = DiscoveryDomainDiff(
        to_update={domain},
        old_values={"finance": old_domain},
        update_masks={"finance": ("description", "subtitle", "draft", "icon")},
    )
    ws_helper = MagicMock(spec=WorkspaceHelper)
    change_logger = MagicMock(spec=ChangeLogger)

    execute_discovery_domain_diff(ws_helper, diff, change_logger, dry_run=False)

    ws_helper.update_discovery_domain.assert_called_once_with(
        domain,
        update_mask=("description", "subtitle", "draft", "icon"),
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
        update_masks={"finance": ("description",)},
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


def test_discovery_domain_executor_prompts_before_delete_when_not_forced(
    monkeypatch,
    capsys,
) -> None:
    domain = DiscoveryDomain(
        tag_key="finance/legacy",
        domain_id="domain-id",
        resource_name="domains/domain-id",
    )
    diff = DiscoveryDomainDiff(to_delete={domain})
    ws_helper = MagicMock(spec=WorkspaceHelper)
    change_logger = MagicMock(spec=ChangeLogger)
    prompts: list[str] = []

    def _confirm(prompt: str) -> str:
        prompts.append(prompt)
        return "yes"

    monkeypatch.setattr("builtins.input", _confirm)

    execute_discovery_domain_diff(ws_helper, diff, change_logger, dry_run=False)

    output = capsys.readouterr().out
    assert domain.tag_key in output
    assert len(prompts) == 1
    prompt = prompts[0].lower()
    assert "irreversible" in prompt
    assert "delete" in prompt
    ws_helper.delete_discovery_domain.assert_called_once_with(domain)


def test_discovery_domain_executor_force_deletes_children_before_parents_without_prompt(
    monkeypatch,
) -> None:
    parent = DiscoveryDomain(
        tag_key="finance",
        domain_id="parent-id",
        resource_name="domains/parent-id",
    )
    child = DiscoveryDomain(
        tag_key="finance/orders",
        domain_id="child-id",
        resource_name="domains/child-id",
        parent_domain_id="parent-id",
        parent_tag_key="finance",
    )
    diff = DiscoveryDomainDiff(to_delete={parent, child})
    ws_helper = MagicMock(spec=WorkspaceHelper)
    change_logger = MagicMock(spec=ChangeLogger)

    def _should_not_be_called(*_):
        raise AssertionError("input() was called even though force=True")

    monkeypatch.setattr("builtins.input", _should_not_be_called)

    execute_discovery_domain_diff(
        ws_helper,
        diff,
        change_logger,
        dry_run=False,
        force=True,
    )

    assert ws_helper.delete_discovery_domain.call_args_list == [
        call(child),
        call(parent),
    ]
    assert change_logger.log_discovery_domain_delete.call_args_list == [
        call(child),
        call(parent),
    ]


def test_discovery_domain_executor_dry_run_logs_delete_without_prompt_or_sdk_call(
    monkeypatch,
) -> None:
    domain = DiscoveryDomain(
        tag_key="finance",
        domain_id="domain-id",
        resource_name="domains/domain-id",
    )
    diff = DiscoveryDomainDiff(to_delete={domain})
    ws_helper = MagicMock(spec=WorkspaceHelper)
    change_logger = MagicMock(spec=ChangeLogger)

    def _should_not_be_called(*_):
        raise AssertionError("input() was called during a dry run")

    monkeypatch.setattr("builtins.input", _should_not_be_called)

    execute_discovery_domain_diff(ws_helper, diff, change_logger, dry_run=True)

    ws_helper.delete_discovery_domain.assert_not_called()
    change_logger.log_discovery_domain_delete.assert_called_once_with(domain)
