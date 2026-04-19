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


# ---------------------------------------------------------------------------
# Deletion path + interactive confirmation
# ---------------------------------------------------------------------------


def _diff_with_deletes(*names: str) -> GovernedTagDiff:
    return GovernedTagDiff(to_delete={_gt(n, "", set()) for n in names})


def test_governed_tag_executor_deletes_tag_after_yes_confirmation(ws_helper, change_logger, monkeypatch):
    """When `input` returns 'yes', the SDK delete is invoked for each tag."""
    monkeypatch.setattr("builtins.input", lambda *_: "yes")
    diff = _diff_with_deletes("legacy")

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    ws_helper.delete_tag_policy.assert_called_once_with("legacy")


def test_governed_tag_executor_deletes_tag_after_y_confirmation(ws_helper, change_logger, monkeypatch):
    """Short form 'y' is also accepted as confirmation."""
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    diff = _diff_with_deletes("legacy")

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    ws_helper.delete_tag_policy.assert_called_once_with("legacy")


def test_governed_tag_executor_is_case_insensitive_for_confirmation(ws_helper, change_logger, monkeypatch):
    """'YES' confirms — confirmation is case-insensitive."""
    monkeypatch.setattr("builtins.input", lambda *_: "YES")
    diff = _diff_with_deletes("legacy")

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    ws_helper.delete_tag_policy.assert_called_once_with("legacy")


def test_governed_tag_executor_skips_delete_when_confirmation_not_given(ws_helper, change_logger, monkeypatch):
    """Any response other than 'y'/'yes' (here: 'no') aborts the delete phase;
    SDK delete is not invoked."""
    monkeypatch.setattr("builtins.input", lambda *_: "no")
    diff = _diff_with_deletes("legacy")

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    ws_helper.delete_tag_policy.assert_not_called()


def test_governed_tag_executor_deletes_without_prompt_when_force_enabled(ws_helper, change_logger, monkeypatch):
    """`force=True` bypasses the prompt — `input()` is never called."""
    def _should_not_be_called(*_):
        raise AssertionError("input() was called even though force=True")
    monkeypatch.setattr("builtins.input", _should_not_be_called)
    diff = _diff_with_deletes("legacy")

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False, force=True)

    ws_helper.delete_tag_policy.assert_called_once_with("legacy")


def test_governed_tag_executor_does_not_prompt_or_delete_in_dry_run(ws_helper, change_logger, monkeypatch):
    """Dry-run logs the would-delete list but never prompts or calls the SDK."""
    def _should_not_be_called(*_):
        raise AssertionError("input() was called during dry-run")
    monkeypatch.setattr("builtins.input", _should_not_be_called)
    diff = _diff_with_deletes("legacy")

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=True)

    ws_helper.delete_tag_policy.assert_not_called()


def test_governed_tag_executor_logs_deletion_per_tag(ws_helper, change_logger, monkeypatch):
    """Each successful delete produces a log entry via log_governed_tag_delete."""
    monkeypatch.setattr("builtins.input", lambda *_: "yes")
    diff = _diff_with_deletes("a", "b", "c")

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    # Summary reflects the three deletes.
    assert change_logger._governed_tags_deleted == 3


def test_governed_tag_executor_raises_interactive_confirmation_error_on_eof_when_not_forced(
    ws_helper, change_logger, monkeypatch,
):
    """EOFError from `input()` in a non-forced context raises InteractiveConfirmationRequiredError."""
    from uc_abac_governor.types import InteractiveConfirmationRequiredError

    def _raise_eof(*_):
        raise EOFError()
    monkeypatch.setattr("builtins.input", _raise_eof)
    diff = _diff_with_deletes("legacy")

    with pytest.raises(InteractiveConfirmationRequiredError):
        execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    ws_helper.delete_tag_policy.assert_not_called()


def test_governed_tag_executor_logs_error_and_continues_on_sdk_delete_failure(
    ws_helper, change_logger, monkeypatch,
):
    """An SDK exception during one delete does not abort the rest of the batch."""
    monkeypatch.setattr("builtins.input", lambda *_: "yes")
    ws_helper.delete_tag_policy.side_effect = [Exception("boom"), None]
    diff = _diff_with_deletes("fail", "succeed")

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    assert ws_helper.delete_tag_policy.call_count == 2
    assert change_logger.has_errors
