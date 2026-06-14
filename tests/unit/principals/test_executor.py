from __future__ import annotations

from unittest.mock import call, MagicMock

import pytest

from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.principals import execute_group_diff, GroupDiff, Principal
from uc_declarative_abac.types import PrincipalType


def _resolved_user(name: str) -> Principal:
    return Principal(PrincipalType.USER, identifier=name, name=name)


@pytest.fixture
def ws_helper() -> MagicMock:
    return MagicMock()


@pytest.fixture
def change_logger() -> ChangeLogger:
    return ChangeLogger(dry_run=False)


# ---------------------------------------------------------------------------
# Group creation + member addition
# ---------------------------------------------------------------------------


def test_group_executor_creates_each_group_to_create(ws_helper, change_logger):
    """Each entry in groups_to_create triggers one create_group call with its name and members."""
    members = frozenset({_resolved_user("alice@co.com")})
    diff = GroupDiff(groups_to_create={"new_group": members})

    execute_group_diff(ws_helper, diff, change_logger, dry_run=False)

    assert ws_helper.create_group.call_count == 1
    sent_name = ws_helper.create_group.call_args.args[0]
    sent_members = ws_helper.create_group.call_args.args[1]
    assert sent_name == "new_group"
    assert set(sent_members) == set(members)


def test_group_executor_adds_members_for_each_group_to_add(ws_helper, change_logger):
    """Each entry in members_to_add triggers one add_group_members call with its name and members."""
    members = frozenset({_resolved_user("bob@co.com")})
    diff = GroupDiff(members_to_add={"existing_group": members})

    execute_group_diff(ws_helper, diff, change_logger, dry_run=False)

    assert ws_helper.add_group_members.call_count == 1
    sent_name = ws_helper.add_group_members.call_args.args[0]
    sent_members = ws_helper.add_group_members.call_args.args[1]
    assert sent_name == "existing_group"
    assert set(sent_members) == set(members)


def test_group_executor_creates_groups_before_adding_members(ws_helper, change_logger):
    """Groups are created before members are added to existing groups."""
    diff = GroupDiff(
        groups_to_create={"new_group": frozenset({_resolved_user("alice@co.com")})},
        members_to_add={"existing_group": frozenset({_resolved_user("bob@co.com")})},
    )

    execute_group_diff(ws_helper, diff, change_logger, dry_run=False)

    method_names = [c[0] for c in ws_helper.method_calls]
    assert "create_group" in method_names
    assert "add_group_members" in method_names
    assert method_names.index("create_group") < method_names.index("add_group_members")


# ---------------------------------------------------------------------------
# Empty diff + dry run
# ---------------------------------------------------------------------------


def test_group_executor_does_nothing_for_empty_diff(ws_helper, change_logger):
    """An empty diff produces no create_group/add_group_members calls and no errors."""
    diff = GroupDiff()

    execute_group_diff(ws_helper, diff, change_logger, dry_run=False)

    ws_helper.create_group.assert_not_called()
    ws_helper.add_group_members.assert_not_called()
    assert not change_logger.has_errors


def test_group_executor_skips_mutations_in_dry_run(ws_helper, change_logger):
    """In dry-run mode, neither create_group nor add_group_members is invoked; the run succeeds."""
    diff = GroupDiff(
        groups_to_create={"new_group": frozenset({_resolved_user("alice@co.com")})},
        members_to_add={"existing_group": frozenset({_resolved_user("bob@co.com")})},
    )

    execute_group_diff(ws_helper, diff, change_logger, dry_run=True)

    ws_helper.create_group.assert_not_called()
    ws_helper.add_group_members.assert_not_called()
    assert not change_logger.has_errors


# ---------------------------------------------------------------------------
# Per-item error isolation
# ---------------------------------------------------------------------------


def test_group_executor_logs_error_and_continues_on_add_members_failure(ws_helper, change_logger):
    """A failing add_group_members for one group is logged; other groups still proceed."""
    def _fail_for_one(name, members):
        if name == "fail_group":
            raise RuntimeError("boom")
        return None

    ws_helper.add_group_members.side_effect = _fail_for_one
    diff = GroupDiff(members_to_add={
        "fail_group": frozenset({_resolved_user("alice@co.com")}),
        "ok_group": frozenset({_resolved_user("bob@co.com")}),
    })

    execute_group_diff(ws_helper, diff, change_logger, dry_run=False)

    assert change_logger.has_errors
    called_names = {c.args[0] for c in ws_helper.add_group_members.call_args_list}
    assert "ok_group" in called_names


def test_group_executor_logs_error_and_continues_on_create_group_failure(ws_helper, change_logger):
    """A failing create_group is recorded; member-addition work still proceeds."""
    ws_helper.create_group.side_effect = RuntimeError("boom")
    diff = GroupDiff(
        groups_to_create={"fail_group": frozenset({_resolved_user("alice@co.com")})},
        members_to_add={"ok_group": frozenset({_resolved_user("bob@co.com")})},
    )

    execute_group_diff(ws_helper, diff, change_logger, dry_run=False)

    assert change_logger.has_errors
    ws_helper.add_group_members.assert_called_once()
    assert ws_helper.add_group_members.call_args.args[0] == "ok_group"
