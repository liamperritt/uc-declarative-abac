from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from uc_abac_governor.governed_tags.executor import execute_governed_tag_diff
from uc_abac_governor.governed_tags.state import GovernedTag, GovernedTagDiff
from uc_abac_governor.logger import ChangeLogger
from uc_abac_governor.principals.state import Principal
from uc_abac_governor.types import PrincipalType


def _gt(
    name: str,
    description: str = "",
    values: set[str] | None = None,
    assigners: set[Principal] | None = None,
) -> GovernedTag:
    return GovernedTag(
        name=name,
        description=description,
        allowed_values=frozenset(values or set()),
        assigners=frozenset(assigners or set()),
    )


def _resolved_user(name: str) -> Principal:
    return Principal(PrincipalType.USER, identifier=name, name=name)


def _resolved_group(name: str) -> Principal:
    return Principal(PrincipalType.GROUP, identifier=name, name=name)


def _resolved_sp(display_name: str, app_id: str) -> Principal:
    return Principal(PrincipalType.SERVICE_PRINCIPAL, identifier=app_id, name=display_name)


def _make_rule_set_response(etag: str = "etag-1", grant_rules: list | None = None) -> MagicMock:
    resp = MagicMock()
    resp.etag = etag
    resp.grant_rules = grant_rules or []
    return resp


def _make_grant_rule(role: str, principals: list[str]) -> MagicMock:
    rule = MagicMock()
    rule.role = role
    rule.principals = principals
    return rule


def _setup_ws_helper_for_assigners(ws_helper: MagicMock, tag_to_id: dict[str, str], existing_assigners_by_tag: dict[str, list[str]] | None = None) -> None:
    """Wire ws_helper to return tag IDs and rule sets for the given tags."""
    existing = existing_assigners_by_tag or {}
    ws_helper.get_tag_policy_id.side_effect = lambda name: tag_to_id.get(name)

    def _get_rule_set_by_name(name: str) -> MagicMock:
        principals = existing.get(name, [])
        rules = [_make_grant_rule("roles/tagPolicy.assigner", principals)] if principals else []
        return _make_rule_set_response(etag=f"etag-{name}", grant_rules=rules)

    ws_helper.get_tag_policy_rule_set_by_name.side_effect = _get_rule_set_by_name

    def _create_tag_policy(policy):
        # Mimic SDK: return a TagPolicy with a fresh id matching the tag_to_id map.
        new_id = tag_to_id.get(policy.tag_key, "tp-new")
        result = MagicMock()
        result.tag_key = policy.tag_key
        result.id = new_id
        return result

    ws_helper.create_tag_policy.side_effect = _create_tag_policy


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


def test_governed_tag_executor_exits_when_confirmation_not_given(ws_helper, change_logger, monkeypatch):
    """Any response other than 'y'/'yes' (here: 'no') aborts the whole program
    via SystemExit; SDK delete is not invoked."""
    monkeypatch.setattr("builtins.input", lambda *_: "no")
    diff = _diff_with_deletes("legacy")

    with pytest.raises(SystemExit):
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


# ---------------------------------------------------------------------------
# assigners enforcement
# ---------------------------------------------------------------------------


def test_governed_tag_executor_sets_assigners_for_newly_created_tag(ws_helper, change_logger):
    """A new tag with assigners triggers update_rule_set after create."""
    _setup_ws_helper_for_assigners(ws_helper, tag_to_id={"pii": "tp-pii"})
    diff = GovernedTagDiff(to_create={
        _gt("pii", "PII", {"name"}, assigners={_resolved_user("alice@co.com")}),
    })

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    assert ws_helper.create_tag_policy.call_count == 1
    assert ws_helper.update_tag_policy_rule_set.call_count == 1
    call = ws_helper.update_tag_policy_rule_set.call_args
    tag_id = call.kwargs.get("tag_id", call.args[0] if call.args else None)
    grant_rules = call.kwargs.get("grant_rules")
    assert tag_id == "tp-pii"
    assert any("users/alice@co.com" in (rule.principals or []) for rule in grant_rules)


def test_governed_tag_executor_registers_created_tag_id(ws_helper, change_logger):
    """After a successful create, the executor registers the new tag's id on ws_helper."""
    _setup_ws_helper_for_assigners(ws_helper, tag_to_id={"pii": "tp-pii"})
    diff = GovernedTagDiff(to_create={_gt("pii", "PII", {"name"})})

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    ws_helper.register_created_tag_policy.assert_called_once()


def test_governed_tag_executor_skips_rule_set_call_when_new_tag_has_no_principals(ws_helper, change_logger):
    """A new tag with empty assigners doesn't trigger update_rule_set."""
    _setup_ws_helper_for_assigners(ws_helper, tag_to_id={"pii": "tp-pii"})
    diff = GovernedTagDiff(to_create={_gt("pii", "PII", {"name"})})

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    ws_helper.update_tag_policy_rule_set.assert_not_called()


def test_governed_tag_executor_updates_rule_set_when_principals_change(ws_helper, change_logger):
    """An update where only assigners change triggers update_rule_set, not update_tag_policy."""
    _setup_ws_helper_for_assigners(
        ws_helper,
        tag_to_id={"pii": "tp-pii"},
        existing_assigners_by_tag={"pii": ["users/alice@co.com"]},
    )
    new = _gt("pii", "PII", {"name"}, assigners={
        _resolved_user("alice@co.com"),
        _resolved_user("bob@co.com"),
    })
    old = _gt("pii", "PII", {"name"}, assigners={_resolved_user("alice@co.com")})
    diff = GovernedTagDiff(to_update={new}, old_values={"pii": old})

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    ws_helper.update_tag_policy.assert_not_called()
    ws_helper.update_tag_policy_rule_set.assert_called_once()


def test_governed_tag_executor_does_not_update_rule_set_when_only_description_changes(ws_helper, change_logger):
    """An update where only description changes leaves the rule set alone."""
    _setup_ws_helper_for_assigners(ws_helper, tag_to_id={"pii": "tp-pii"})
    new = _gt("pii", "New", {"name"}, assigners={_resolved_user("alice@co.com")})
    old = _gt("pii", "Old", {"name"}, assigners={_resolved_user("alice@co.com")})
    diff = GovernedTagDiff(to_update={new}, old_values={"pii": old})

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    ws_helper.update_tag_policy.assert_called_once()
    ws_helper.update_tag_policy_rule_set.assert_not_called()


def test_governed_tag_executor_updates_both_when_description_and_principals_change(ws_helper, change_logger):
    """An update touching description AND assigners issues both calls."""
    _setup_ws_helper_for_assigners(
        ws_helper,
        tag_to_id={"pii": "tp-pii"},
        existing_assigners_by_tag={"pii": ["users/alice@co.com"]},
    )
    new = _gt("pii", "New", {"name"}, assigners={_resolved_user("bob@co.com")})
    old = _gt("pii", "Old", {"name"}, assigners={_resolved_user("alice@co.com")})
    diff = GovernedTagDiff(to_update={new}, old_values={"pii": old})

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    ws_helper.update_tag_policy.assert_called_once()
    ws_helper.update_tag_policy_rule_set.assert_called_once()


def test_governed_tag_executor_uses_etag_from_get_for_update_rule_set(ws_helper, change_logger):
    """The etag returned by the GET ruleset is passed to update_rule_set (read-modify-write)."""
    _setup_ws_helper_for_assigners(
        ws_helper,
        tag_to_id={"pii": "tp-pii"},
        existing_assigners_by_tag={"pii": []},
    )
    new = _gt("pii", "PII", {"name"}, assigners={_resolved_user("alice@co.com")})
    old = _gt("pii", "PII", {"name"}, assigners=set())
    diff = GovernedTagDiff(to_update={new}, old_values={"pii": old})

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    call = ws_helper.update_tag_policy_rule_set.call_args
    etag = call.kwargs.get("etag")
    assert etag == "etag-pii"


def test_governed_tag_executor_preserves_non_assign_grant_rules(ws_helper, change_logger):
    """Grant rules with roles other than ASSIGN are preserved across update_rule_set."""
    other_rule = _make_grant_rule("roles/tagPolicy.someOtherRole", ["users/admin@co.com"])
    ws_helper.get_tag_policy_id.return_value = "tp-pii"
    ws_helper.get_tag_policy_rule_set_by_name.return_value = _make_rule_set_response(
        etag="etag-pii", grant_rules=[other_rule],
    )

    def _create_tag_policy(policy):
        result = MagicMock()
        result.tag_key = policy.tag_key
        result.id = "tp-pii"
        return result
    ws_helper.create_tag_policy.side_effect = _create_tag_policy

    new = _gt("pii", "PII", {"name"}, assigners={_resolved_user("alice@co.com")})
    old = _gt("pii", "PII", {"name"}, assigners=set())
    diff = GovernedTagDiff(to_update={new}, old_values={"pii": old})

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    call = ws_helper.update_tag_policy_rule_set.call_args
    grant_rules = call.kwargs.get("grant_rules")
    roles = [r.role for r in grant_rules]
    assert "roles/tagPolicy.someOtherRole" in roles
    assert "roles/tagPolicy.assigner" in roles


def test_governed_tag_executor_encodes_user_principal_with_users_prefix(ws_helper, change_logger):
    """Resolved USER principals are encoded as `users/<username>` in grant_rules."""
    _setup_ws_helper_for_assigners(ws_helper, tag_to_id={"pii": "tp-pii"})
    diff = GovernedTagDiff(to_create={
        _gt("pii", "PII", {"name"}, assigners={_resolved_user("alice@co.com")}),
    })

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    call = ws_helper.update_tag_policy_rule_set.call_args
    grant_rules = call.kwargs.get("grant_rules")
    assign_rule = next(r for r in grant_rules if r.role == "roles/tagPolicy.assigner")
    assert "users/alice@co.com" in assign_rule.principals


def test_governed_tag_executor_encodes_group_principal_with_groups_prefix(ws_helper, change_logger):
    """Resolved GROUP principals are encoded as `groups/<name>`."""
    _setup_ws_helper_for_assigners(ws_helper, tag_to_id={"pii": "tp-pii"})
    diff = GovernedTagDiff(to_create={
        _gt("pii", "PII", {"name"}, assigners={_resolved_group("data_engineers")}),
    })

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    call = ws_helper.update_tag_policy_rule_set.call_args
    grant_rules = call.kwargs.get("grant_rules")
    assign_rule = next(r for r in grant_rules if r.role == "roles/tagPolicy.assigner")
    assert "groups/data_engineers" in assign_rule.principals


def test_governed_tag_executor_encodes_sp_principal_with_service_principals_prefix(ws_helper, change_logger):
    """Resolved SP principals are encoded as `servicePrincipals/<application_id>`."""
    _setup_ws_helper_for_assigners(ws_helper, tag_to_id={"pii": "tp-pii"})
    diff = GovernedTagDiff(to_create={
        _gt("pii", "PII", {"name"}, assigners={_resolved_sp("my-sp", "app-uuid-123")}),
    })

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    call = ws_helper.update_tag_policy_rule_set.call_args
    grant_rules = call.kwargs.get("grant_rules")
    assign_rule = next(r for r in grant_rules if r.role == "roles/tagPolicy.assigner")
    assert "servicePrincipals/app-uuid-123" in assign_rule.principals


def test_governed_tag_executor_skips_rule_set_calls_in_dry_run(ws_helper, change_logger):
    """Dry-run never calls update_rule_set."""
    _setup_ws_helper_for_assigners(ws_helper, tag_to_id={"pii": "tp-pii"})
    diff = GovernedTagDiff(to_create={
        _gt("pii", "PII", {"name"}, assigners={_resolved_user("alice@co.com")}),
    })

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=True)

    ws_helper.update_tag_policy_rule_set.assert_not_called()
    ws_helper.create_tag_policy.assert_not_called()


def test_governed_tag_executor_logs_error_and_continues_on_rule_set_failure(ws_helper, change_logger):
    """An SDK failure during one rule-set update is captured and the run continues."""
    ws_helper.get_tag_policy_id.return_value = "tp-pii"
    ws_helper.get_tag_policy_rule_set_by_name.return_value = _make_rule_set_response(etag="etag-pii")
    ws_helper.update_tag_policy_rule_set.side_effect = Exception("boom")

    new = _gt("pii", "PII", {"name"}, assigners={_resolved_user("alice@co.com")})
    old = _gt("pii", "PII", {"name"}, assigners=set())
    diff = GovernedTagDiff(to_update={new}, old_values={"pii": old})

    execute_governed_tag_diff(ws_helper, diff, change_logger, dry_run=False)

    assert change_logger.has_errors
