from __future__ import annotations

import logging
from unittest.mock import MagicMock

from uc_declarative_abac.policies.state import Policy
from uc_declarative_abac.privileges.state import SecurablePrivilege
from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.securables.state import AttributeUpdate, Function, Securable
from uc_declarative_abac.tags.state import SecurableTag
from uc_declarative_abac.principals.state import Principal
from uc_declarative_abac.types import PrincipalType, PolicyType, PrivilegeType, SecurableType, ExecutionError


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


def _all_messages(mock_logger: MagicMock) -> list[str]:
    """Extract all messages from info() and error() calls, in call order."""
    return [
        args[0]
        for name, args, _ in mock_logger.method_calls
        if name in ("info", "error")
    ]


def _change_lines(mock_logger: MagicMock) -> list[str]:
    """Extract only change lines (indented action symbols like '  + ...') from info messages."""
    return [m for m in _info_messages(mock_logger) if m.startswith("  ") and m[2:3] in ("+", "~", "-", "!")]



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
    principal: Principal = Principal(PrincipalType.GROUP, "data_engineers", "data_engineers"),
    privilege_type: str | PrivilegeType = PrivilegeType.SELECT,
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
    msg = messages[0].lower()
    assert "added" in msg
    assert "catalog" in msg and "my_catalog" in msg
    assert "env" in msg and "prod" in msg


def test_change_logger_logs_tag_add_with_valueless_tag() -> None:
    """tag_value="" logs the tag with an empty value."""
    cl, mock_logger = _make_change_logger()
    tag = _make_tag(tag_name="deprecated", tag_value="")
    cl.log_tag_add(tag)

    messages = _info_messages(mock_logger)
    assert len(messages) == 1
    msg = messages[0].lower()
    assert "added" in msg
    assert "deprecated" in msg


def test_change_logger_logs_tag_update_with_old_value() -> None:
    """log_tag_update in live mode shows old and new tag values."""
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
    msg = messages[0].lower()
    assert "updated" in msg
    assert "table" in msg and "my_catalog.sales.orders" in msg
    assert "classification" in msg and "internal" in msg
    assert "confidential" in msg
    assert "->" in msg


def test_change_logger_logs_tag_remove() -> None:
    """log_tag_remove in live mode logs the removed tag."""
    cl, mock_logger = _make_change_logger()
    tag = _make_tag(
        securable_type=SecurableType.SCHEMA,
        securable_full_name="my_catalog.sales",
        tag_name="deprecated",
        tag_value="",
    )
    cl.log_tag_remove(tag)

    messages = _info_messages(mock_logger)
    assert len(messages) == 1
    msg = messages[0].lower()
    assert "removed" in msg
    assert "schema" in msg and "my_catalog.sales" in msg
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
        principal=Principal(PrincipalType.GROUP, "data_engineers", "data_engineers"),
        privilege_type=PrivilegeType.SELECT,
    )
    cl.log_grant(priv)

    messages = _info_messages(mock_logger)
    assert len(messages) == 1
    msg = messages[0].lower()
    assert "granted" in msg
    assert "schema" in msg and "my_catalog.sales" in msg
    assert "select" in msg
    assert "data_engineers" in msg


def test_change_logger_logs_revoke() -> None:
    """log_revoke in live mode logs the revoked privilege."""
    cl, mock_logger = _make_change_logger()
    priv = _make_privilege(
        securable_type=SecurableType.TABLE,
        securable_full_name="my_catalog.sales.orders",
        principal=Principal(PrincipalType.GROUP, "temp_users", "temp_users"),
        privilege_type=PrivilegeType.MODIFY,
    )
    cl.log_revoke(priv)

    messages = _info_messages(mock_logger)
    assert len(messages) == 1
    msg = messages[0].lower()
    assert "revoked" in msg
    assert "table" in msg and "my_catalog.sales.orders" in msg
    assert "modify" in msg
    assert "temp_users" in msg


# ---------------------------------------------------------------------------
# Dry-run mode
# ---------------------------------------------------------------------------


def test_change_logger_prepends_dry_run_prefix() -> None:
    """In dry_run mode, change lines use present tense (Add/Grant not Added/Granted)."""
    cl, mock_logger = _make_change_logger(dry_run=True)

    cl.log_tag_add(_make_tag())
    cl.log_grant(_make_privilege())

    messages = _change_lines(mock_logger)
    assert len(messages) == 2
    # Present tense in dry-run mode
    assert "add" in messages[0].lower() and "tag" in messages[0].lower()
    assert "grant" in messages[1].lower()
    # Must NOT contain past tense
    assert "added" not in messages[0].lower()
    assert "granted" not in messages[1].lower()


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
    cl.log_grant(_make_privilege(privilege_type=PrivilegeType.SELECT))
    cl.log_revoke(_make_privilege(privilege_type=PrivilegeType.MODIFY))
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
    cl.log_grant(_make_privilege(privilege_type=PrivilegeType.SELECT))
    cl.log_summary()

    messages = _info_messages(mock_logger)
    summary = messages[-1]

    assert "2 to add" in summary
    assert "1 to update" in summary
    assert "1 to grant" in summary
    assert "dry run" in summary.lower()


# ---------------------------------------------------------------------------
# Error tracking
# ---------------------------------------------------------------------------


def _make_execution_error(
    statement: str = "GRANT SELECT ON TABLE `cat`.`s`.`t` TO `user`",
    exception: Exception | None = None,
) -> "ExecutionError":
    return ExecutionError(
        context=statement,
        exception=exception or RuntimeError("SQL execution failed"),
    )


def test_change_logger_collects_errors() -> None:
    """log_error() collects ExecutionError instances accessible via .errors."""
    cl, _ = _make_change_logger()
    err1 = _make_execution_error(statement="ALTER CATALOG `c` SET TAGS ('a')")
    err2 = _make_execution_error(statement="GRANT SELECT ON TABLE `c`.`s`.`t` TO `u`")

    cl.log_error(err1)
    cl.log_error(err2)

    assert cl.errors == [err1, err2]


def test_change_logger_has_errors_returns_false_when_no_errors() -> None:
    """has_errors is False on a fresh ChangeLogger."""
    cl, _ = _make_change_logger()
    assert cl.has_errors is False


def test_change_logger_has_errors_returns_true_after_error_logged() -> None:
    """has_errors is True after at least one error is logged."""
    cl, _ = _make_change_logger()
    cl.log_error(_make_execution_error())
    assert cl.has_errors is True


def test_change_logger_logs_error_message() -> None:
    """log_error() logs an [ERROR] prefixed message via the logger."""
    cl, mock_logger = _make_change_logger()
    cl.log_error(_make_execution_error())

    messages = _all_messages(mock_logger)
    assert any("error" in msg.lower() for msg in messages), (
        f"Expected an error message in: {messages}"
    )


def test_change_logger_summary_includes_error_count() -> None:
    """Summary includes the error count when errors have been logged."""
    cl, mock_logger = _make_change_logger()

    # 1 success
    cl.log_tag_add(_make_tag(tag_name="a"))
    # 2 errors
    cl.log_error(_make_execution_error(statement="stmt1"))
    cl.log_error(_make_execution_error(statement="stmt2"))

    cl.log_summary()

    messages = _info_messages(mock_logger)
    summary = messages[-1]
    assert "2 failed" in summary.lower() or "2 error" in summary.lower(), (
        f"Expected error count in summary: {summary}"
    )


def test_change_logger_summary_excludes_errors_when_none() -> None:
    """Summary does not mention failures when no errors were logged."""
    cl, mock_logger = _make_change_logger()

    cl.log_tag_add(_make_tag(tag_name="a"))
    cl.log_summary()

    messages = _info_messages(mock_logger)
    summary = messages[-1]
    assert "failed" not in summary.lower()
    assert "error" not in summary.lower()


# ---------------------------------------------------------------------------
# Principal display name in logs
# ---------------------------------------------------------------------------


def test_change_logger_uses_principal_display_name_in_grant_log() -> None:
    """log_grant uses the Principal's display_name (not identifier) in the log message."""
    cl, mock_logger = _make_change_logger()
    priv = SecurablePrivilege(
        securable_type=SecurableType.TABLE,
        securable_full_name="catalog.schema.orders",
        principal=Principal(PrincipalType.SERVICE_PRINCIPAL, "app-id-123", "my-etl-sp"),
        privilege_type=PrivilegeType.SELECT,
    )
    cl.log_grant(priv)

    messages = _info_messages(mock_logger)
    assert len(messages) == 1
    msg = messages[0].lower()

    # The display name must appear in the log
    assert "my-etl-sp" in msg
    # The system identifier must NOT appear in the log
    assert "app-id-123" not in msg


# ---------------------------------------------------------------------------
# Securable logging
# ---------------------------------------------------------------------------


def test_logger_logs_attribute_update() -> None:
    """log_attribute_update increments _attributes_updated counter."""
    cl, _ = _make_change_logger()
    update = AttributeUpdate(
        securable_type=SecurableType.CATALOG,
        full_name="my_catalog",
        attribute="owner",
        old_value="old_owner",
        new_value="new_owner",
    )
    cl.log_attribute_update(update)

    assert cl._attributes_updated == 1


def test_logger_logs_securable_create() -> None:
    """log_securable_create increments _securables_created counter."""
    cl, _ = _make_change_logger()
    info = Function(
        securable_type=SecurableType.FUNCTION,
        full_name="cat.schema.func",
        parameters=(("col", "STRING"),),
        definition="col",
    )
    cl.log_securable_create(info)

    assert cl._securables_created == 1


def test_logger_logs_securable_replace() -> None:
    """log_securable_replace increments _securables_replaced counter."""
    cl, _ = _make_change_logger()
    info = Function(
        securable_type=SecurableType.FUNCTION,
        full_name="cat.schema.func",
        parameters=(("col", "STRING"),),
        definition="col",
    )
    cl.log_securable_replace(info)

    assert cl._securables_replaced == 1


def test_logger_includes_securables_in_summary() -> None:
    """_build_summary includes a Securables section with attribute, create, and replace counts."""
    cl, _ = _make_change_logger()

    cl.log_attribute_update(AttributeUpdate(
        securable_type=SecurableType.CATALOG,
        full_name="my_catalog",
        attribute="owner",
        old_value="old_owner",
        new_value="new_owner",
    ))
    cl.log_securable_create(Function(
        securable_type=SecurableType.FUNCTION,
        full_name="cat.schema.func",
        parameters=(("col", "STRING"),),
        definition="col",
    ))
    cl.log_securable_replace(Function(
        securable_type=SecurableType.FUNCTION,
        full_name="cat.schema.func2",
        parameters=(("col", "STRING"),),
        definition="col",
    ))

    summary = cl._build_summary()

    assert "1 updated" in summary
    assert "1 created" in summary
    assert "1 replaced" in summary
    assert "Securables:" in summary


# ---------------------------------------------------------------------------
# Policy logging
# ---------------------------------------------------------------------------


def _make_policy(name: str = "p1") -> Policy:
    return Policy(
        securable_type=SecurableType.TABLE,
        securable_full_name="cat.s.t",
        name=name,
        policy_type=PolicyType.MASK,
        function_name="cat.default.fn",
        to_principals=("analysts",),
        except_principals=(),
        when_condition=None,
        match_columns=(),
        on_column="c",
        using_columns=(),
    )


def test_logger_logs_policy_create_increments_counter() -> None:
    cl, mock_logger = _make_change_logger()
    cl.log_policy_create(_make_policy(name="mask_pii"))

    assert cl._policies_created == 1
    msg = _info_messages(mock_logger)[0].lower()
    assert "created" in msg
    assert "mask policy 'mask_pii'" in msg
    assert "cat.s.t" in msg


def test_logger_logs_policy_replace_increments_counter() -> None:
    cl, mock_logger = _make_change_logger()
    cl.log_policy_replace(_make_policy(name="mask_pii"))

    assert cl._policies_replaced == 1
    msg = _info_messages(mock_logger)[0].lower()
    assert "replaced" in msg


def test_logger_includes_policies_in_summary() -> None:
    cl, _ = _make_change_logger()
    cl.log_policy_create(_make_policy(name="p1"))
    cl.log_policy_replace(_make_policy(name="p2"))

    summary = cl._build_summary()
    assert "Policies:" in summary
    assert "1 created" in summary
    assert "1 replaced" in summary


# ---------------------------------------------------------------------------
# Governed tag logging
# ---------------------------------------------------------------------------


def _resolved_user(name: str) -> Principal:
    return Principal(PrincipalType.USER, identifier=name, name=name)


def _gt(
    name: str = "pii",
    description: str = "",
    values: set[str] | None = None,
    assigners: set[Principal] | None = None,
):
    from uc_declarative_abac.governed_tags.state import GovernedTag
    return GovernedTag(
        name=name,
        description=description,
        allowed_values=frozenset(values or set()),
        assigners=frozenset(assigners or set()),
    )


# log_governed_tag_create — show actual values being deployed


def test_logger_governed_tag_create_shows_description_values_and_assigners() -> None:
    cl, mock_logger = _make_change_logger()
    cl.log_governed_tag_create(_gt(
        description="PII data",
        values={"name", "email"},
        assigners={_resolved_user("alice@co.com")},
    ))
    msg = _info_messages(mock_logger)[0]
    assert "PII data" in msg
    assert "name" in msg and "email" in msg
    assert "alice@co.com" in msg


def test_logger_governed_tag_create_omits_empty_fields() -> None:
    cl, mock_logger = _make_change_logger()
    cl.log_governed_tag_create(_gt(values={"x"}))
    msg = _info_messages(mock_logger)[0]
    assert "description" not in msg
    assert "assigners" not in msg
    assert "allowed_values" in msg


def test_logger_governed_tag_create_increments_created_counter() -> None:
    cl, _ = _make_change_logger()
    cl.log_governed_tag_create(_gt())
    assert cl._governed_tags_created == 1


def test_logger_governed_tag_create_counts_assigners_as_grants() -> None:
    """Creating a tag with assigners counts each one as a grant for the summary."""
    cl, _ = _make_change_logger()
    cl.log_governed_tag_create(_gt(assigners={
        _resolved_user("alice@co.com"), _resolved_user("bob@co.com"),
    }))
    assert cl._governed_tag_assigners_granted == 2


# log_governed_tag_update — show specific deltas


def test_logger_governed_tag_update_shows_description_old_to_new() -> None:
    cl, mock_logger = _make_change_logger()
    cl.log_governed_tag_update(
        _gt(description="new desc", values={"x"}),
        _gt(description="old desc", values={"x"}),
    )
    msg = _info_messages(mock_logger)[0]
    assert "old desc" in msg
    assert "new desc" in msg
    assert "->" in msg


def test_logger_governed_tag_update_shows_added_and_removed_values() -> None:
    cl, mock_logger = _make_change_logger()
    cl.log_governed_tag_update(
        _gt(values={"name", "phone"}),
        _gt(values={"name", "email"}),
    )
    msg = _info_messages(mock_logger)[0]
    assert "+phone" in msg
    assert "-email" in msg
    # unchanged values aren't repeated
    assert "+name" not in msg
    assert "-name" not in msg


def test_logger_governed_tag_update_shows_added_and_removed_assigners() -> None:
    cl, mock_logger = _make_change_logger()
    cl.log_governed_tag_update(
        _gt(assigners={_resolved_user("alice@co.com")}),
        _gt(assigners={_resolved_user("bob@co.com")}),
    )
    msg = _info_messages(mock_logger)[0]
    assert "+alice@co.com" in msg
    assert "-bob@co.com" in msg


def test_logger_governed_tag_update_increments_updated_counter() -> None:
    cl, _ = _make_change_logger()
    cl.log_governed_tag_update(
        _gt(description="new"), _gt(description="old"),
    )
    assert cl._governed_tags_updated == 1


def test_logger_governed_tag_update_increments_assigner_counters_from_delta() -> None:
    """Adding 2 assigners and removing 1 yields 2 granted / 1 revoked in the summary."""
    cl, _ = _make_change_logger()
    cl.log_governed_tag_update(
        _gt(assigners={_resolved_user("a@co.com"), _resolved_user("b@co.com")}),
        _gt(assigners={_resolved_user("c@co.com")}),
    )
    assert cl._governed_tag_assigners_granted == 2
    assert cl._governed_tag_assigners_revoked == 1


def test_logger_governed_tag_update_omits_unchanged_fields() -> None:
    cl, mock_logger = _make_change_logger()
    cl.log_governed_tag_update(
        _gt(description="d", values={"x"}, assigners={_resolved_user("a@co.com")}),
        _gt(description="d", values={"x"}, assigners=set()),
    )
    msg = _info_messages(mock_logger)[0]
    # description and allowed_values unchanged → not shown
    assert "description" not in msg
    assert "allowed_values" not in msg
    assert "assigners" in msg


# log_governed_tag_delete — show what's being torn down


def test_logger_governed_tag_delete_shows_values_and_assigners_being_lost() -> None:
    cl, mock_logger = _make_change_logger()
    cl.log_governed_tag_delete(_gt(
        description="legacy",
        values={"a", "b"},
        assigners={_resolved_user("admin@co.com")},
    ))
    msg = _info_messages(mock_logger)[0]
    assert "legacy" in msg
    assert "a" in msg and "b" in msg
    assert "admin@co.com" in msg


def test_logger_governed_tag_delete_increments_deleted_counter() -> None:
    cl, _ = _make_change_logger()
    cl.log_governed_tag_delete(_gt())
    assert cl._governed_tags_deleted == 1


def test_logger_governed_tag_delete_counts_assigners_as_revokes() -> None:
    """Deleting a tag with N assigners counts each as a revoke for the summary."""
    cl, _ = _make_change_logger()
    cl.log_governed_tag_delete(_gt(assigners={
        _resolved_user("alice@co.com"), _resolved_user("bob@co.com"),
    }))
    assert cl._governed_tag_assigners_revoked == 2


# Summary integration


def test_logger_includes_governed_tags_in_summary() -> None:
    cl, _ = _make_change_logger()
    cl.log_governed_tag_create(_gt(name="a"))
    cl.log_governed_tag_update(_gt(name="b", description="new"), _gt(name="b", description="old"))
    summary = cl._build_summary()
    assert "Governed tags:" in summary
    assert "1 created" in summary
    assert "1 updated" in summary


def test_logger_includes_governed_tag_assigners_in_summary_via_create_and_update() -> None:
    cl, _ = _make_change_logger()
    cl.log_governed_tag_create(_gt(name="new", assigners={_resolved_user("alice@co.com")}))
    cl.log_governed_tag_update(
        _gt(assigners={_resolved_user("c@co.com")}),
        _gt(assigners={_resolved_user("d@co.com")}),
    )
    summary = cl._build_summary()
    assert "Governed tag assigners:" in summary
    assert "2 granted" in summary
    assert "1 revoked" in summary


def test_logger_includes_governed_tag_assigners_in_dry_run_summary() -> None:
    cl, _ = _make_change_logger(dry_run=True)
    cl.log_governed_tag_create(_gt(assigners={_resolved_user("alice@co.com")}))
    summary = cl._build_summary()
    assert "Governed tag assigners:" in summary
    assert "1 to grant" in summary
