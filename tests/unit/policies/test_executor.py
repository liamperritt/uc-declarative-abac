from __future__ import annotations

from unittest.mock import MagicMock

from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.policies.executor import execute_policy_diff
from uc_declarative_abac.policies.state import Policy, PolicyDiff
from uc_declarative_abac.principals.state import Principal
from uc_declarative_abac.types import ExecutionError, PolicyType, PrincipalType, SecurableType


def _resolved(name: str, principal_type: PrincipalType = PrincipalType.GROUP) -> Principal:
    """Construct a resolved Principal with identifier == name (for GROUP/USER)."""
    return Principal(principal_type=principal_type, name=name, identifier=name)


def _assert_sql_contains(sql: str, *fragments: str):
    """Assert every fragment appears in the SQL (case-insensitive, ignoring backticks)."""
    normalised = sql.upper().replace("`", "")
    for fragment in fragments:
        needle = fragment.upper().replace("`", "")
        assert needle in normalised, f"Expected {fragment!r} in SQL: {sql}"


def _assert_sql_excludes(sql: str, *fragments: str):
    """Assert none of the fragments appears in the SQL (case-insensitive, ignoring backticks)."""
    normalised = sql.upper().replace("`", "")
    for fragment in fragments:
        needle = fragment.upper().replace("`", "")
        assert needle not in normalised, f"Unexpected {fragment!r} in SQL: {sql}"


def _make_policy(**overrides) -> Policy:
    base = dict(
        securable_type=SecurableType.TABLE,
        securable_full_name="cat.s.t",
        name="mask_pii",
        policy_type=PolicyType.MASK,
        function_name="cat.default.mask_fn",
        to_principals=(_resolved("analysts"),),
        except_principals=(),
        when_condition=None,
        match_columns=(("c", "has_column_tag_value('pii', 'email')"),),
        on_column="c",
        using_columns=(),
    )
    base.update(overrides)
    return Policy(**base)


# ---------------------------------------------------------------------------
# CREATE vs CREATE OR REPLACE
# ---------------------------------------------------------------------------


def test_policy_executor_emits_create_for_to_create():
    uc_helper = MagicMock()
    diff = PolicyDiff(to_create={_make_policy()})

    stmts = execute_policy_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]
    _assert_sql_contains(sql, "CREATE POLICY", "`mask_pii`")
    _assert_sql_excludes(sql, "CREATE OR REPLACE POLICY")
    uc_helper.execute_sql.assert_called_once_with(sql)


def test_policy_executor_emits_create_or_replace_for_to_replace():
    uc_helper = MagicMock()
    diff = PolicyDiff(to_replace={_make_policy()})

    stmts = execute_policy_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]
    _assert_sql_contains(sql, "CREATE OR REPLACE POLICY", "`mask_pii`")


# ---------------------------------------------------------------------------
# Securable attachment (ON CATALOG / ON SCHEMA / ON TABLE)
# ---------------------------------------------------------------------------


def test_policy_executor_attaches_to_catalog():
    uc_helper = MagicMock()
    policy = _make_policy(securable_type=SecurableType.CATALOG, securable_full_name="cat")
    diff = PolicyDiff(to_create={policy})

    (sql,) = execute_policy_diff(uc_helper, diff, ChangeLogger())
    _assert_sql_contains(sql, "ON CATALOG", "`cat`")


def test_policy_executor_attaches_to_schema():
    uc_helper = MagicMock()
    policy = _make_policy(securable_type=SecurableType.SCHEMA, securable_full_name="cat.s")
    diff = PolicyDiff(to_create={policy})

    (sql,) = execute_policy_diff(uc_helper, diff, ChangeLogger())
    _assert_sql_contains(sql, "ON SCHEMA", "`cat`.`s`")


def test_policy_executor_attaches_to_table():
    uc_helper = MagicMock()
    diff = PolicyDiff(to_create={_make_policy()})

    (sql,) = execute_policy_diff(uc_helper, diff, ChangeLogger())
    _assert_sql_contains(sql, "ON TABLE", "`cat`.`s`.`t`")


# ---------------------------------------------------------------------------
# COLUMN MASK vs ROW FILTER bodies
# ---------------------------------------------------------------------------


def test_policy_executor_column_mask_body_includes_on_column():
    uc_helper = MagicMock()
    diff = PolicyDiff(to_create={_make_policy()})

    (sql,) = execute_policy_diff(uc_helper, diff, ChangeLogger())
    _assert_sql_contains(sql, "COLUMN MASK `cat`.`default`.`mask_fn`", "ON COLUMN c")


def test_policy_executor_column_mask_includes_using_when_extra_columns():
    uc_helper = MagicMock()
    diff = PolicyDiff(
        to_create={
            _make_policy(
                match_columns=(
                    ("c_ssn", "has_column_tag_value('pii', 'ssn')"),
                    ("c_region", "has_column_tag('geo')"),
                ),
                on_column="c_ssn",
                using_columns=("c_region",),
            )
        }
    )

    (sql,) = execute_policy_diff(uc_helper, diff, ChangeLogger())
    _assert_sql_contains(sql, "ON COLUMN c_ssn", "USING COLUMNS (c_region)")


def test_policy_executor_column_mask_omits_using_when_no_extras():
    uc_helper = MagicMock()
    diff = PolicyDiff(to_create={_make_policy()})

    (sql,) = execute_policy_diff(uc_helper, diff, ChangeLogger())
    _assert_sql_excludes(sql, "USING COLUMNS")


def test_policy_executor_row_filter_body_omits_on_column():
    uc_helper = MagicMock()
    policy = _make_policy(
        policy_type=PolicyType.FILTER,
        function_name="cat.default.filter_fn",
        match_columns=(("c_region", "has_column_tag('geo')"),),
        on_column=None,
        using_columns=("c_region",),
    )
    diff = PolicyDiff(to_create={policy})

    (sql,) = execute_policy_diff(uc_helper, diff, ChangeLogger())
    _assert_sql_contains(sql, "ROW FILTER `cat`.`default`.`filter_fn`", "USING COLUMNS (c_region)")
    _assert_sql_excludes(sql, "ON COLUMN")


def test_policy_executor_row_filter_omits_using_when_no_columns():
    uc_helper = MagicMock()
    policy = _make_policy(
        policy_type=PolicyType.FILTER,
        function_name="cat.default.filter_fn",
        match_columns=(),
        on_column=None,
        using_columns=(),
    )
    diff = PolicyDiff(to_create={policy})

    (sql,) = execute_policy_diff(uc_helper, diff, ChangeLogger())
    _assert_sql_excludes(sql, "USING COLUMNS", "ON COLUMN", "MATCH COLUMNS")


# ---------------------------------------------------------------------------
# TO / EXCEPT / WHEN / MATCH COLUMNS
# ---------------------------------------------------------------------------


def test_policy_executor_includes_to_principals():
    uc_helper = MagicMock()
    diff = PolicyDiff(to_create={_make_policy(to_principals=(_resolved("a_group"), _resolved("b_group")))})

    (sql,) = execute_policy_diff(uc_helper, diff, ChangeLogger())
    _assert_sql_contains(sql, "TO `a_group`, `b_group`")


def test_policy_executor_includes_except_when_present():
    uc_helper = MagicMock()
    diff = PolicyDiff(to_create={_make_policy(except_principals=(_resolved("admin"),))})

    (sql,) = execute_policy_diff(uc_helper, diff, ChangeLogger())
    _assert_sql_contains(sql, "EXCEPT `admin`")


def test_policy_executor_omits_except_when_empty():
    uc_helper = MagicMock()
    diff = PolicyDiff(to_create={_make_policy(except_principals=())})

    (sql,) = execute_policy_diff(uc_helper, diff, ChangeLogger())
    _assert_sql_excludes(sql, "EXCEPT")


def test_policy_executor_includes_when_condition():
    uc_helper = MagicMock()
    diff = PolicyDiff(to_create={_make_policy(when_condition="has_tag_value('env', 'prod')")})

    (sql,) = execute_policy_diff(uc_helper, diff, ChangeLogger())
    _assert_sql_contains(sql, "WHEN has_tag_value('env', 'prod')")


def test_policy_executor_omits_when_clause_when_none():
    uc_helper = MagicMock()
    diff = PolicyDiff(to_create={_make_policy(when_condition=None)})

    (sql,) = execute_policy_diff(uc_helper, diff, ChangeLogger())
    _assert_sql_excludes(sql, "WHEN ")


def test_policy_executor_includes_match_columns():
    uc_helper = MagicMock()
    diff = PolicyDiff(
        to_create={
            _make_policy(
                match_columns=(
                    ("c_ssn", "has_column_tag_value('pii', 'ssn')"),
                    ("c_region", "has_column_tag('geo')"),
                ),
                on_column="c_ssn",
                using_columns=("c_region",),
            )
        }
    )

    (sql,) = execute_policy_diff(uc_helper, diff, ChangeLogger())
    _assert_sql_contains(
        sql,
        "MATCH COLUMNS",
        "has_column_tag_value('pii', 'ssn') AS c_ssn",
        "has_column_tag('geo') AS c_region",
    )


def test_policy_executor_includes_for_tables_clause():
    uc_helper = MagicMock()
    diff = PolicyDiff(to_create={_make_policy()})

    (sql,) = execute_policy_diff(uc_helper, diff, ChangeLogger())
    _assert_sql_contains(sql, "FOR TABLES")


# ---------------------------------------------------------------------------
# Error handling and dry-run
# ---------------------------------------------------------------------------


def test_policy_executor_logs_error_on_execute_failure():
    uc_helper = MagicMock()
    uc_helper.execute_sql.side_effect = RuntimeError("boom")
    change_logger = ChangeLogger()
    diff = PolicyDiff(to_create={_make_policy()})

    result = execute_policy_diff(uc_helper, diff, change_logger)

    assert result == []
    assert change_logger.has_errors
    (err,) = change_logger.errors
    assert isinstance(err, ExecutionError)
    assert "boom" in str(err.exception)


def test_policy_executor_dry_run_does_not_execute_sql():
    uc_helper = MagicMock()
    diff = PolicyDiff(to_create={_make_policy()})

    result = execute_policy_diff(uc_helper, diff, ChangeLogger(), dry_run=True)

    assert result == []
    uc_helper.execute_sql.assert_not_called()


# ---------------------------------------------------------------------------
# Policy comment
# ---------------------------------------------------------------------------


def test_policy_executor_includes_comment_when_set():
    """CREATE POLICY SQL includes a COMMENT clause when Policy.comment is set."""
    uc_helper = MagicMock()
    diff = PolicyDiff(to_create={_make_policy(comment="Mask email PII")})

    (sql,) = execute_policy_diff(uc_helper, diff, ChangeLogger())
    _assert_sql_contains(sql, "COMMENT 'Mask email PII'")


def test_policy_executor_omits_comment_clause_when_unset():
    uc_helper = MagicMock()
    diff = PolicyDiff(to_create={_make_policy(comment=None)})

    (sql,) = execute_policy_diff(uc_helper, diff, ChangeLogger())
    _assert_sql_excludes(sql, "COMMENT")


def test_policy_executor_escapes_single_quotes_in_comment():
    uc_helper = MagicMock()
    diff = PolicyDiff(to_create={_make_policy(comment="It's broken")})

    (sql,) = execute_policy_diff(uc_helper, diff, ChangeLogger())
    assert "COMMENT 'It\\'s broken'" in sql


def test_policy_executor_comment_appears_between_on_and_body():
    """Per Databricks SQL grammar, COMMENT sits between ON <securable> and {COLUMN MASK|ROW FILTER}."""
    uc_helper = MagicMock()
    diff = PolicyDiff(to_create={_make_policy(comment="My policy")})

    (sql,) = execute_policy_diff(uc_helper, diff, ChangeLogger())
    on_idx = sql.upper().find("ON ")
    comment_idx = sql.upper().find("COMMENT ")
    mask_idx = sql.upper().find("COLUMN MASK")
    assert on_idx < comment_idx < mask_idx
