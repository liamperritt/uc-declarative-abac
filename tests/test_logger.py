from __future__ import annotations

import logging
from unittest.mock import MagicMock

from uc_abac_governor.privileges.state import SecurablePrivilege
from uc_abac_governor.logger import ChangeLogger
from uc_abac_governor.tags.state import SecurableTag
from uc_abac_governor.types import SecurableType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_logger() -> MagicMock:
    """Create a mock logger with info and debug methods."""
    return MagicMock(spec=logging.Logger)


def _make_change_logger(dry_run: bool = False) -> tuple[ChangeLogger, MagicMock]:
    """Create a ChangeLogger with a mock logger. Returns (session, mock_logger)."""
    mock_logger = _make_logger()
    session = ChangeLogger(dry_run=dry_run, logger=mock_logger)
    return session, mock_logger


def _info_messages(mock_logger: MagicMock) -> list[str]:
    """Extract all messages passed to mock_logger.info()."""
    return [c.args[0] for c in mock_logger.info.call_args_list]



def _make_tag(
    securable_type: SecurableType = SecurableType.CATALOG,
    securable_full_name: str = "my_catalog",
    tag_name: str = "env",
    tag_value: str | None = "prod",
) -> SecurableTag:
    return SecurableTag(
        securable_type=securable_type,
        securable_full_name=securable_full_name,
        tag_name=tag_name,
        tag_value=tag_value,
    )


def _make_privilege(
    securable_type: SecurableType = SecurableType.SCHEMA,
    securable_full_name: str = "my_catalog.sales",
    principal: str = "data_engineers",
    privilege_type: str = "SELECT",
) -> SecurablePrivilege:
    return SecurablePrivilege(
        securable_type=securable_type,
        securable_full_name=securable_full_name,
        principal=principal,
        privilege_type=privilege_type,
    )


# ---------------------------------------------------------------------------
# Tag logging
# ---------------------------------------------------------------------------


def test_change_logger_logs_tag_add() -> None:
    """log_tag_add in live mode produces INFO with [ADDED] (past tense)."""
    cl, mock_logger = _make_change_logger()
    tag = _make_tag(
        securable_type=SecurableType.CATALOG,
        securable_full_name="my_catalog",
        tag_name="env",
        tag_value="prod",
    )
    cl.log_tag_add(tag)

    messages = _info_messages(mock_logger)
    assert len(messages) == 1
    msg = messages[0]
    assert "[ADDED]" in msg
    assert "CATALOG" in msg
    assert "my_catalog" in msg
    assert "env" in msg
    assert "prod" in msg


def test_change_logger_logs_tag_add_with_valueless_tag() -> None:
    """tag_value=None logs just the tag name without =value."""
    cl, mock_logger = _make_change_logger()
    tag = _make_tag(tag_name="deprecated", tag_value=None)
    cl.log_tag_add(tag)

    messages = _info_messages(mock_logger)
    assert len(messages) == 1
    msg = messages[0]
    assert "[ADDED]" in msg
    assert "deprecated" in msg
    assert "=" not in msg


def test_change_logger_logs_tag_update_with_old_value() -> None:
    """log_tag_update in live mode produces INFO with [UPDATED] (past tense)."""
    cl, mock_logger = _make_change_logger()
    tag = _make_tag(
        securable_type=SecurableType.TABLE,
        securable_full_name="my_catalog.sales.orders",
        tag_name="classification",
        tag_value="confidential",
    )
    cl.log_tag_update(tag, old_value="internal")

    messages = _info_messages(mock_logger)
    assert len(messages) == 1
    msg = messages[0]
    assert "[UPDATED]" in msg
    assert "TABLE" in msg
    assert "my_catalog.sales.orders" in msg
    assert "internal" in msg
    assert "confidential" in msg


def test_change_logger_logs_tag_remove() -> None:
    """log_tag_remove in live mode produces INFO with [REMOVED] (past tense)."""
    cl, mock_logger = _make_change_logger()
    tag = _make_tag(
        securable_type=SecurableType.SCHEMA,
        securable_full_name="my_catalog.sales",
        tag_name="deprecated",
        tag_value=None,
    )
    cl.log_tag_remove(tag)

    messages = _info_messages(mock_logger)
    assert len(messages) == 1
    msg = messages[0]
    assert "[REMOVED]" in msg
    assert "SCHEMA" in msg
    assert "my_catalog.sales" in msg
    assert "deprecated" in msg


# ---------------------------------------------------------------------------
# Privilege logging
# ---------------------------------------------------------------------------


def test_change_logger_logs_grant() -> None:
    """log_grant in live mode produces INFO with [GRANTED] (past tense)."""
    cl, mock_logger = _make_change_logger()
    priv = _make_privilege(
        securable_type=SecurableType.SCHEMA,
        securable_full_name="my_catalog.sales",
        principal="data_engineers",
        privilege_type="SELECT",
    )
    cl.log_grant(priv)

    messages = _info_messages(mock_logger)
    assert len(messages) == 1
    msg = messages[0]
    assert "[GRANTED]" in msg
    assert "SELECT" in msg
    assert "SCHEMA" in msg
    assert "my_catalog.sales" in msg
    assert "data_engineers" in msg


def test_change_logger_logs_revoke() -> None:
    """log_revoke in live mode produces INFO with [REVOKED] (past tense)."""
    cl, mock_logger = _make_change_logger()
    priv = _make_privilege(
        securable_type=SecurableType.TABLE,
        securable_full_name="my_catalog.sales.orders",
        principal="temp_users",
        privilege_type="MODIFY",
    )
    cl.log_revoke(priv)

    messages = _info_messages(mock_logger)
    assert len(messages) == 1
    msg = messages[0]
    assert "[REVOKED]" in msg
    assert "MODIFY" in msg
    assert "TABLE" in msg
    assert "my_catalog.sales.orders" in msg
    assert "temp_users" in msg


# ---------------------------------------------------------------------------
# Dry-run mode
# ---------------------------------------------------------------------------


def test_change_logger_prepends_dry_run_prefix() -> None:
    """In dry_run mode, INFO messages have [DRY RUN] prefix and use present tense."""
    cl, mock_logger = _make_change_logger(dry_run=True)

    cl.log_tag_add(_make_tag())
    cl.log_grant(_make_privilege())

    messages = _info_messages(mock_logger)
    assert len(messages) == 2
    for msg in messages:
        assert "[DRY RUN]" in msg
    # Present tense in dry-run mode
    assert "[ADD]" in messages[0]
    assert "[GRANT]" in messages[1]


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def test_change_logger_logs_summary() -> None:
    """log_summary logs a summary with correct counts."""
    cl, mock_logger = _make_change_logger()

    cl.log_tag_add(_make_tag(tag_name="a"))
    cl.log_tag_add(_make_tag(tag_name="b"))
    cl.log_tag_update(_make_tag(tag_name="c", tag_value="new"), old_value="old")
    cl.log_tag_remove(_make_tag(tag_name="d"))
    cl.log_grant(_make_privilege(privilege_type="SELECT"))
    cl.log_revoke(_make_privilege(privilege_type="MODIFY"))
    cl.log_summary()

    messages = _info_messages(mock_logger)
    summary = messages[-1]

    assert "2 added" in summary
    assert "1 updated" in summary
    assert "1 removed" in summary
    assert "1 granted" in summary
    assert "1 revoked" in summary


def test_change_logger_logs_dry_run_summary() -> None:
    """In dry_run mode, summary uses future tense and notes dry run."""
    cl, mock_logger = _make_change_logger(dry_run=True)

    cl.log_tag_add(_make_tag(tag_name="a"))
    cl.log_tag_add(_make_tag(tag_name="b"))
    cl.log_tag_update(_make_tag(tag_name="c", tag_value="new"), old_value="old")
    cl.log_grant(_make_privilege(privilege_type="SELECT"))
    cl.log_summary()

    messages = _info_messages(mock_logger)
    summary = messages[-1]

    assert "2 to add" in summary
    assert "1 to update" in summary
    assert "1 to grant" in summary
    assert "dry run" in summary.lower()


# ---------------------------------------------------------------------------
# Diff-level convenience methods
# ---------------------------------------------------------------------------


def test_change_logger_logs_tag_changes() -> None:
    """log_tag_changes logs all adds, updates, and removes from a TagDiff."""
    from uc_abac_governor.tags.state import TagDiff

    cl, mock_logger = _make_change_logger()

    tag_add = _make_tag(tag_name="new_tag", tag_value="val")
    tag_update = _make_tag(tag_name="changed", tag_value="new_val")
    tag_remove = _make_tag(tag_name="old_tag", tag_value="stale")

    diff = TagDiff(
        to_add={tag_add},
        to_update={tag_update},
        to_remove={tag_remove},
        old_values={
            (tag_update.securable_type, tag_update.securable_full_name, tag_update.tag_name): "old_val",
        },
    )

    cl.log_tag_changes(diff)

    messages = _info_messages(mock_logger)
    assert len(messages) == 3

    combined = "\n".join(messages)
    assert "[ADDED]" in combined
    assert "[UPDATED]" in combined
    assert "[REMOVED]" in combined
    assert "new_tag" in combined
    assert "changed" in combined
    assert "old_tag" in combined
    assert "old_val" in combined
    assert "new_val" in combined


def test_change_logger_logs_privilege_changes() -> None:
    """log_privilege_changes logs all grants and revokes from a PrivilegeDiff."""
    from uc_abac_governor.privileges.state import PrivilegeDiff

    cl, mock_logger = _make_change_logger()

    grant_priv = _make_privilege(principal="team_a", privilege_type="SELECT")
    revoke_priv = _make_privilege(principal="team_b", privilege_type="MODIFY")

    diff = PrivilegeDiff(
        to_grant={grant_priv},
        to_revoke={revoke_priv},
    )

    cl.log_privilege_changes(diff)

    messages = _info_messages(mock_logger)
    assert len(messages) == 2

    combined = "\n".join(messages)
    assert "[GRANTED]" in combined
    assert "[REVOKED]" in combined
    assert "team_a" in combined
    assert "team_b" in combined
    assert "SELECT" in combined
    assert "MODIFY" in combined

