from __future__ import annotations

from unittest.mock import call, MagicMock

import pytest

from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.principals import execute_group_diff, GroupDiff, GroupRename, Principal
from uc_declarative_abac.types import PrincipalType


def _resolved_user(name: str) -> Principal:
    return Principal(PrincipalType.USER, identifier=name, name=name)


def _summary_of(logger_mock: MagicMock) -> str:
    """Return the logged summary line emitted by ChangeLogger.log_summary()."""
    return next(
        c.args[0]
        for c in reversed(logger_mock.info.call_args_list)
        if c.args and "Summary:" in c.args[0]
    )


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
    """In dry-run mode, no create/add/remove is invoked; the run succeeds."""
    diff = GroupDiff(
        groups_to_create={"new_group": frozenset({_resolved_user("alice@co.com")})},
        members_to_add={"existing_group": frozenset({_resolved_user("bob@co.com")})},
        members_to_remove={"existing_group": frozenset({_resolved_user("carol@co.com")})},
    )

    execute_group_diff(ws_helper, diff, change_logger, dry_run=True)

    ws_helper.create_group.assert_not_called()
    ws_helper.add_group_members.assert_not_called()
    ws_helper.remove_group_members.assert_not_called()
    assert not change_logger.has_errors


# ---------------------------------------------------------------------------
# Member removal
# ---------------------------------------------------------------------------


def test_group_executor_removes_members_for_each_group_to_remove(ws_helper, change_logger):
    """Each entry in members_to_remove triggers one remove_group_members call."""
    members = frozenset({_resolved_user("carol@co.com")})
    diff = GroupDiff(members_to_remove={"existing_group": members})

    execute_group_diff(ws_helper, diff, change_logger, dry_run=False)

    assert ws_helper.remove_group_members.call_count == 1
    assert ws_helper.remove_group_members.call_args.args[0] == "existing_group"
    assert set(ws_helper.remove_group_members.call_args.args[1]) == set(members)


def test_group_executor_adds_before_removes_after_creates(ws_helper, change_logger):
    """Ordering is create -> add -> remove on the shared ws_helper."""
    diff = GroupDiff(
        groups_to_create={"new_group": frozenset({_resolved_user("alice@co.com")})},
        members_to_add={"existing_group": frozenset({_resolved_user("bob@co.com")})},
        members_to_remove={"existing_group": frozenset({_resolved_user("carol@co.com")})},
    )

    execute_group_diff(ws_helper, diff, change_logger, dry_run=False)

    method_names = [c[0] for c in ws_helper.method_calls]
    assert (
        method_names.index("create_group")
        < method_names.index("add_group_members")
        < method_names.index("remove_group_members")
    )


def test_group_executor_logs_error_and_continues_on_remove_members_failure(ws_helper, change_logger):
    """A failing remove_group_members for one group is logged; other groups still proceed."""
    def _fail_for_one(name, members):
        if name == "fail_group":
            raise RuntimeError("boom")
        return None

    ws_helper.remove_group_members.side_effect = _fail_for_one
    diff = GroupDiff(members_to_remove={
        "fail_group": frozenset({_resolved_user("alice@co.com")}),
        "ok_group": frozenset({_resolved_user("bob@co.com")}),
    })

    execute_group_diff(ws_helper, diff, change_logger, dry_run=False)

    assert change_logger.has_errors
    called_names = {c.args[0] for c in ws_helper.remove_group_members.call_args_list}
    assert "ok_group" in called_names


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


def test_group_executor_rewrites_permission_denied_on_add_with_manager_hint(ws_helper, change_logger):
    """A PERMISSION_DENIED failure adding members is rewritten to point at the
    missing MANAGER role on the specific group."""
    ws_helper.add_group_members.side_effect = RuntimeError(
        'PERMISSION_DENIED: Requesting user does not have securable_type: "group"'
    )
    diff = GroupDiff(members_to_add={"data_engineers": frozenset({_resolved_user("alice@co.com")})})

    execute_group_diff(ws_helper, diff, change_logger, dry_run=False)

    assert change_logger.has_errors
    message = str(change_logger.errors[0].exception)
    assert "MANAGER" in message
    assert "data_engineers" in message


def test_group_executor_rewrites_permission_denied_on_remove_with_manager_hint(ws_helper, change_logger):
    """A PERMISSION_DENIED failure removing members is rewritten with the MANAGER hint."""
    ws_helper.remove_group_members.side_effect = RuntimeError(
        'PERMISSION_DENIED: Requesting user does not have securable_type: "group"'
    )
    diff = GroupDiff(members_to_remove={"data_engineers": frozenset({_resolved_user("bob@co.com")})})

    execute_group_diff(ws_helper, diff, change_logger, dry_run=False)

    assert change_logger.has_errors
    message = str(change_logger.errors[0].exception)
    assert "MANAGER" in message
    assert "data_engineers" in message


def test_group_executor_passes_through_non_permission_errors(ws_helper, change_logger):
    """A non-permission failure is logged unchanged (no MANAGER hint)."""
    ws_helper.add_group_members.side_effect = RuntimeError("boom: something else")
    diff = GroupDiff(members_to_add={"data_engineers": frozenset({_resolved_user("alice@co.com")})})

    execute_group_diff(ws_helper, diff, change_logger, dry_run=False)

    assert change_logger.has_errors
    message = str(change_logger.errors[0].exception)
    assert "boom: something else" in message
    assert "MANAGER" not in message


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


# ---------------------------------------------------------------------------
# Group rename
# ---------------------------------------------------------------------------


def test_group_executor_renames_each_group_to_rename(ws_helper, change_logger):
    """Each entry in groups_to_rename triggers one rename_group call with (id, new_name)."""
    diff = GroupDiff(groups_to_rename=[
        GroupRename(id="g1", old_display_name="old_one", new_display_name="new_one"),
        GroupRename(id="g2", old_display_name="old_two", new_display_name="new_two"),
    ])

    execute_group_diff(ws_helper, diff, change_logger, dry_run=False)

    assert ws_helper.rename_group.call_count == 2
    sent = {(c.args[0], c.args[1]) for c in ws_helper.rename_group.call_args_list}
    assert sent == {("g1", "new_one"), ("g2", "new_two")}


def test_group_executor_renames_before_adding_members(ws_helper, change_logger):
    """Renames are applied before members are added to existing groups."""
    diff = GroupDiff(
        groups_to_rename=[
            GroupRename(id="g1", old_display_name="old_one", new_display_name="new_one"),
        ],
        members_to_add={"existing_group": frozenset({_resolved_user("bob@co.com")})},
    )

    execute_group_diff(ws_helper, diff, change_logger, dry_run=False)

    method_names = [c[0] for c in ws_helper.method_calls]
    assert "rename_group" in method_names
    assert "add_group_members" in method_names
    assert method_names.index("rename_group") < method_names.index("add_group_members")


def test_group_executor_skips_rename_patch_in_dry_run(ws_helper):
    """In dry-run mode rename_group is not invoked, but the rename is still recorded."""
    logger_mock = MagicMock()
    change_logger = ChangeLogger(dry_run=True, logger=logger_mock)
    diff = GroupDiff(groups_to_rename=[
        GroupRename(id="g1", old_display_name="old_one", new_display_name="new_one"),
    ])

    execute_group_diff(ws_helper, diff, change_logger, dry_run=True)

    ws_helper.rename_group.assert_not_called()
    change_logger.log_summary()
    assert "to rename" in _summary_of(logger_mock)
    assert not change_logger.has_errors


def test_group_executor_logs_rename_on_success(ws_helper):
    """A successful rename is recorded in the change logger's summary."""
    logger_mock = MagicMock()
    change_logger = ChangeLogger(dry_run=False, logger=logger_mock)
    diff = GroupDiff(groups_to_rename=[
        GroupRename(id="g1", old_display_name="old_one", new_display_name="new_one"),
    ])

    execute_group_diff(ws_helper, diff, change_logger, dry_run=False)

    change_logger.log_summary()
    assert "renamed" in _summary_of(logger_mock)
    assert not change_logger.has_errors


def test_group_executor_collects_error_when_rename_fails(ws_helper, change_logger):
    """A failing rename_group is logged as an error without crashing execution."""
    ws_helper.rename_group.side_effect = RuntimeError("boom")
    diff = GroupDiff(groups_to_rename=[
        GroupRename(id="g1", old_display_name="old_one", new_display_name="new_one"),
    ])

    execute_group_diff(ws_helper, diff, change_logger, dry_run=False)

    assert change_logger.has_errors
