from __future__ import annotations

from unittest.mock import MagicMock

import sqlglot

from uc_abac_governor.logger import ChangeLogger
from uc_abac_governor.tags.executor import execute_tag_diff
from uc_abac_governor.tags.state import SecurableTag, TagDiff
from uc_abac_governor.types import SecurableType


def _parse_sql(sql: str):
    """Attempt to parse SQL via sqlglot. Returns the parsed expression or None."""
    try:
        return sqlglot.parse_one(sql, dialect="databricks")
    except sqlglot.errors.ParseError:
        return None


def _assert_sql_contains(sql: str, *fragments: str):
    """Assert that every fragment appears in the SQL string (case-insensitive, ignoring backticks)."""
    normalised = sql.upper().replace("`", "")
    for fragment in fragments:
        assert fragment.upper() in normalised, (
            f"Expected {fragment!r} in SQL: {sql}"
        )


# ---------------------------------------------------------------------------
# 1. Adds produce ALTER SET TAGS
# ---------------------------------------------------------------------------


def test_tag_executor_generates_set_tags_sql_for_adds():
    """to_add tags produce ALTER SET TAGS with the expected securable and tag."""
    uc_helper = MagicMock()
    diff = TagDiff(
        to_add={
            SecurableTag(
                securable_type=SecurableType.CATALOG,
                securable_full_name="my_catalog",
                tag_name="env",
                tag_value="prod",
            )
        },
    )

    stmts = execute_tag_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]

    # Try sqlglot parse; fall back to string assertions if Databricks syntax
    # is not fully supported.
    parsed = _parse_sql(sql)
    if parsed is not None:
        sql_text = parsed.sql(dialect="databricks")
        _assert_sql_contains(sql_text, "SET TAGS", "my_catalog", "env", "prod")
    else:
        _assert_sql_contains(sql, "ALTER", "CATALOG", "SET TAGS", "my_catalog", "env", "prod")

    # Securable name should be backtick-quoted
    assert "`my_catalog`" in sql

    uc_helper.execute_sql.assert_called_once_with(sql)


# ---------------------------------------------------------------------------
# 2. Updates produce ALTER SET TAGS (same syntax as adds)
# ---------------------------------------------------------------------------


def test_tag_executor_generates_set_tags_sql_for_updates():
    """to_update tags produce ALTER SET TAGS — same SQL shape as adds."""
    uc_helper = MagicMock()
    diff = TagDiff(
        to_update={
            SecurableTag(
                securable_type=SecurableType.TABLE,
                securable_full_name="cat.schema.orders",
                tag_name="pii",
                tag_value="true",
            )
        },
    )

    stmts = execute_tag_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]

    parsed = _parse_sql(sql)
    if parsed is not None:
        sql_text = parsed.sql(dialect="databricks")
        _assert_sql_contains(sql_text, "SET TAGS", "cat.schema.orders", "pii", "true")
    else:
        _assert_sql_contains(sql, "ALTER", "TABLE", "SET TAGS", "cat.schema.orders", "pii", "true")

    uc_helper.execute_sql.assert_called_once_with(sql)


# ---------------------------------------------------------------------------
# 3. Removes produce ALTER UNSET TAGS
# ---------------------------------------------------------------------------


def test_tag_executor_generates_unset_tags_sql_for_removes():
    """to_remove tags produce ALTER UNSET TAGS containing the tag key only."""
    uc_helper = MagicMock()
    diff = TagDiff(
        to_remove={
            SecurableTag(
                securable_type=SecurableType.CATALOG,
                securable_full_name="my_catalog",
                tag_name="env",
                tag_value="prod",
            )
        },
    )

    stmts = execute_tag_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]

    parsed = _parse_sql(sql)
    if parsed is not None:
        sql_text = parsed.sql(dialect="databricks")
        _assert_sql_contains(sql_text, "UNSET TAGS", "my_catalog", "env")
    else:
        _assert_sql_contains(sql, "ALTER", "CATALOG", "UNSET TAGS", "my_catalog", "env")

    # UNSET TAGS should not include the tag value assignment.
    assert "= 'prod'" not in sql

    uc_helper.execute_sql.assert_called_once_with(sql)


# ---------------------------------------------------------------------------
# 4. Valueless tags — no `= 'value'` part
# ---------------------------------------------------------------------------


def test_tag_executor_handles_valueless_tags():
    """A tag with tag_value=None produces SET TAGS('key') without '= value'."""
    uc_helper = MagicMock()
    diff = TagDiff(
        to_add={
            SecurableTag(
                securable_type=SecurableType.CATALOG,
                securable_full_name="my_catalog",
                tag_name="operations",
                tag_value=None,
            )
        },
    )

    stmts = execute_tag_diff(uc_helper, diff, ChangeLogger())

    assert len(stmts) == 1
    sql = stmts[0]

    _assert_sql_contains(sql, "SET TAGS", "my_catalog", "operations")
    # Must NOT contain an assignment for the valueless tag.
    assert "= '" not in sql.split("operations")[-1].split(",")[0].split(")")[0], (
        f"Valueless tag should not have '= value' assignment: {sql}"
    )

    uc_helper.execute_sql.assert_called_once_with(sql)


# ---------------------------------------------------------------------------
# 5. Batching — multiple tags on the same securable → single statement
# ---------------------------------------------------------------------------


def test_tag_executor_batches_tags_per_securable():
    """Multiple tags on the same securable should be batched into one ALTER."""
    uc_helper = MagicMock()
    diff = TagDiff(
        to_add={
            SecurableTag(
                securable_type=SecurableType.TABLE,
                securable_full_name="cat.schema.table",
                tag_name="a",
                tag_value="1",
            ),
            SecurableTag(
                securable_type=SecurableType.TABLE,
                securable_full_name="cat.schema.table",
                tag_name="b",
                tag_value="2",
            ),
        },
    )

    stmts = execute_tag_diff(uc_helper, diff, ChangeLogger())

    # Only one statement should be generated for the single securable.
    assert len(stmts) == 1
    sql = stmts[0]

    _assert_sql_contains(sql, "SET TAGS", "cat.schema.table")
    # Both tag keys must appear in the same statement.
    _assert_sql_contains(sql, "'a'", "'b'")

    uc_helper.execute_sql.assert_called_once()


# ---------------------------------------------------------------------------
# 6. Return value contains every executed SQL statement
# ---------------------------------------------------------------------------


def test_tag_executor_returns_all_executed_statements():
    """The return list contains every SQL statement that was executed."""
    uc_helper = MagicMock()
    diff = TagDiff(
        to_add={
            SecurableTag(
                securable_type=SecurableType.CATALOG,
                securable_full_name="cat_a",
                tag_name="env",
                tag_value="dev",
            ),
        },
        to_remove={
            SecurableTag(
                securable_type=SecurableType.SCHEMA,
                securable_full_name="cat_b.schema_b",
                tag_name="deprecated",
                tag_value="true",
            ),
        },
    )

    stmts = execute_tag_diff(uc_helper, diff, ChangeLogger())

    # Exactly two statements: one SET TAGS, one UNSET TAGS.
    assert len(stmts) == 2

    set_stmts = [s for s in stmts if "SET TAGS" in s.upper() and "UNSET" not in s.upper()]
    unset_stmts = [s for s in stmts if "UNSET TAGS" in s.upper()]

    assert len(set_stmts) == 1, f"Expected exactly one SET TAGS statement, got {len(set_stmts)}"
    assert len(unset_stmts) == 1, f"Expected exactly one UNSET TAGS statement, got {len(unset_stmts)}"

    # Every returned statement must have been passed to execute_sql.
    executed_sqls = [call.args[0] for call in uc_helper.execute_sql.call_args_list]
    assert set(stmts) == set(executed_sqls)


# ---------------------------------------------------------------------------
# 7. Empty diff — no execute_sql calls
# ---------------------------------------------------------------------------


def test_tag_executor_executes_nothing_given_empty_diff():
    """An empty TagDiff should produce no SQL and no execute_sql calls."""
    uc_helper = MagicMock()
    diff = TagDiff()

    stmts = execute_tag_diff(uc_helper, diff, ChangeLogger())

    assert stmts == []
    uc_helper.execute_sql.assert_not_called()
