from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from uc_abac_governor.governed_tags.executor import execute_governed_tag_diff
from uc_abac_governor.governed_tags.state import GovernedTag, GovernedTagDiff
from uc_abac_governor.logger import ChangeLogger


def _gt(name: str, description: str = "", values: set[str] | None = None) -> GovernedTag:
    return GovernedTag(
        name=name,
        description=description,
        allowed_values=frozenset(values or set()),
    )


@pytest.fixture
def ws_helper() -> MagicMock:
    helper = MagicMock()
    return helper


@pytest.fixture
def change_logger() -> ChangeLogger:
    return ChangeLogger(dry_run=False)


def test_governed_tag_executor_creates_new_tag_policy(ws_helper, change_logger):
    """A to_create entry triggers a single create_tag_policy call with the mapped TagPolicy."""
    diff = GovernedTagDiff(to_create={_gt("pii", "PII", {"name", "email"})})

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    assert ws_helper.create_tag_policy.call_count == 1
    sent_policy = ws_helper.create_tag_policy.call_args[0][0]
    assert sent_policy.tag_key == "pii"
    assert sent_policy.description == "PII"
    assert {v.name for v in sent_policy.values} == {"name", "email"}


def test_governed_tag_executor_updates_description_only_when_description_changes(ws_helper, change_logger):
    """When only description differs, update_mask is 'description'."""
    new = _gt("pii", "New description", {"name"})
    old = _gt("pii", "Old description", {"name"})
    diff = GovernedTagDiff(to_update={new}, old_values={"pii": old})

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    ws_helper.update_tag_policy.assert_called_once()
    call = ws_helper.update_tag_policy.call_args
    assert call.kwargs.get("update_mask", call.args[2] if len(call.args) > 2 else None) == "description"


def test_governed_tag_executor_updates_values_only_when_values_change(ws_helper, change_logger):
    """When only allowed_values differ, update_mask is 'values'."""
    new = _gt("pii", "Same", {"name", "email"})
    old = _gt("pii", "Same", {"name"})
    diff = GovernedTagDiff(to_update={new}, old_values={"pii": old})

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    ws_helper.update_tag_policy.assert_called_once()
    call = ws_helper.update_tag_policy.call_args
    assert call.kwargs.get("update_mask", call.args[2] if len(call.args) > 2 else None) == "values"


def test_governed_tag_executor_combines_update_mask_when_both_change(ws_helper, change_logger):
    """When both description and allowed_values differ, update_mask includes both fields."""
    new = _gt("pii", "New", {"name", "email"})
    old = _gt("pii", "Old", {"name"})
    diff = GovernedTagDiff(to_update={new}, old_values={"pii": old})

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    call = ws_helper.update_tag_policy.call_args
    mask = call.kwargs.get("update_mask", call.args[2] if len(call.args) > 2 else None)
    assert mask == "description,values"


def test_governed_tag_executor_sorts_allowed_values_before_sending_to_sdk(ws_helper, change_logger):
    """Allowed values are sent to the SDK in deterministic (sorted) order."""
    diff = GovernedTagDiff(to_create={_gt("pii", "PII", {"phone", "email", "name"})})

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    sent_policy = ws_helper.create_tag_policy.call_args[0][0]
    value_names = [v.name for v in sent_policy.values]
    assert value_names == sorted(value_names)


def test_governed_tag_executor_skips_execution_in_dry_run(ws_helper, change_logger):
    """In dry-run mode, neither create nor update is invoked on the SDK."""
    diff = GovernedTagDiff(
        to_create={_gt("new_tag", "New", {"a"})},
        to_update={_gt("pii", "New", {"b"})},
        old_values={"pii": _gt("pii", "Old", {"b"})},
    )

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=True)

    ws_helper.create_tag_policy.assert_not_called()
    ws_helper.update_tag_policy.assert_not_called()


def test_governed_tag_executor_logs_error_and_continues_on_sdk_exception(ws_helper, change_logger):
    """An SDK exception during one create does not abort the rest of the batch."""
    ws_helper.create_tag_policy.side_effect = [
        Exception("boom"),   # first call fails
        MagicMock(),         # second call succeeds
    ]
    diff = GovernedTagDiff(to_create={_gt("fail", "", {"x"}), _gt("succeed", "", {"y"})})

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    assert ws_helper.create_tag_policy.call_count == 2
    assert change_logger.has_errors
