from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest
import sqlglot
from databricks.sdk.service.sql import Disposition, StatementState

from uc_abac_governor.configs.models import ResourcesConfig
from uc_abac_governor.helpers.unity_catalog import (
    UnityCatalogHelper,
    _POLL_INTERVAL_SECONDS,  # exception to the "no private imports" rule: needed to
                             # anchor the polling-cadence test to the production constant
)
from uc_abac_governor.policies.state import Policy
from uc_abac_governor.tags.state import SecurableTag
from uc_abac_governor.principals.state import Principal
from uc_abac_governor.privileges.state import SecurablePrivilege
from uc_abac_governor.securables.state import Function, Securable, SecurableAttributes
from uc_abac_governor.types import GovernorError, PolicyType, PrincipalType, PrivilegeType, SecurableType

WAREHOUSE_ID = "test-warehouse-id"

DATABRICKS_DIALECT = "databricks"


def _get_executed_sql(client: MagicMock) -> str:
    """Extract the SQL statement from the most recent execute_statement call."""
    call_kwargs = client.statement_execution.execute_statement.call_args
    statement = call_kwargs.kwargs.get("statement", "")
    if not statement and call_kwargs.args:
        statement = call_kwargs.args[0]
    return statement


def _parse_sql(sql: str) -> sqlglot.Expression:
    """Parse SQL with sqlglot using the Databricks dialect. Asserts it parses."""
    parsed = sqlglot.parse(sql, dialect=DATABRICKS_DIALECT)
    assert len(parsed) == 1, f"Expected 1 statement, got {len(parsed)}"
    assert parsed[0] is not None, f"SQL failed to parse: {sql}"
    return parsed[0]


def _get_table_names(stmt: sqlglot.Expression) -> set[str]:
    """Extract all table names referenced in a parsed SQL statement."""
    return {t.name for t in stmt.find_all(sqlglot.exp.Table)}


def _make_mock_workspace_client(data_array: list[list[str]] | None = None) -> MagicMock:
    """Build a mock WorkspaceClient whose execute_statement returns configurable rows.

    The mock response provides ``result.data_array`` with the given rows.
    If *data_array* is ``None`` it defaults to an empty list.
    """
    client = MagicMock()

    response = MagicMock()
    response.status.state = StatementState.SUCCEEDED
    response.result.data_array = data_array if data_array is not None else []
    response.result.external_links = []
    response.manifest.schema.columns = []

    client.statement_execution.execute_statement.return_value = response
    return client


# ---------------------------------------------------------------------------
# UnityCatalogHelper.fetch_actual_tags
# ---------------------------------------------------------------------------


@patch("uc_abac_governor.helpers.unity_catalog._fetch_external_links_rows")
def test_uc_helper_fetches_actual_tags_from_query_results(mock_fetch):
    """Mock returns aggregated tag rows (one row per securable, tags as JSON) -> correct set of SecurableTag."""
    rows = [
        ["CATALOG", "my_catalog", '[{"tag_name":"env","tag_value":"prod"}]'],
        ["TABLE", "my_catalog.sales.orders", '[{"tag_name":"pii","tag_value":"true"}]'],
    ]
    mock_fetch.return_value = rows
    client = _make_mock_workspace_client()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    result = helper.fetch_actual_tags(["my_catalog"])

    expected = {
        SecurableTag(
            securable_type=SecurableType.CATALOG,
            securable_full_name="my_catalog",
            tag_name="env",
            tag_value="prod",
        ),
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_catalog.sales.orders",
            tag_name="pii",
            tag_value="true",
        ),
    }
    assert result == expected


@patch("uc_abac_governor.helpers.unity_catalog._fetch_external_links_rows")
def test_uc_helper_parses_multiple_tags_from_single_securable_row(mock_fetch):
    """One input row with a JSON array of multiple tag structs produces one SecurableTag per tag,
    all sharing the same (securable_type, securable_full_name)."""
    rows = [
        [
            "TABLE",
            "my_catalog.sales.orders",
            '[{"tag_name":"pii","tag_value":"true"},'
            '{"tag_name":"classification","tag_value":"confidential"},'
            '{"tag_name":"team","tag_value":"sales"}]',
        ],
    ]
    mock_fetch.return_value = rows
    client = _make_mock_workspace_client()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    result = helper.fetch_actual_tags(["my_catalog"])

    assert result == {
        SecurableTag(SecurableType.TABLE, "my_catalog.sales.orders", "pii", "true"),
        SecurableTag(SecurableType.TABLE, "my_catalog.sales.orders", "classification", "confidential"),
        SecurableTag(SecurableType.TABLE, "my_catalog.sales.orders", "team", "sales"),
    }


@patch("uc_abac_governor.helpers.unity_catalog._fetch_external_links_rows")
def test_uc_helper_coerces_null_tag_value_to_empty_string(mock_fetch):
    """A JSON tag_value of null is coerced to the empty string, matching SecurableTag's default."""
    rows = [
        ["TABLE", "my_catalog.sales.orders", '[{"tag_name":"pii","tag_value":null}]'],
    ]
    mock_fetch.return_value = rows
    client = _make_mock_workspace_client()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    result = helper.fetch_actual_tags(["my_catalog"])

    assert result == {
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_catalog.sales.orders",
            tag_name="pii",
            tag_value="",
        ),
    }


def test_uc_helper_fetches_no_tags_given_no_rows():
    """Mock returns no rows -> empty set, but a query was still executed."""
    client = _make_mock_workspace_client(data_array=[])
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    result = helper.fetch_actual_tags(["some_catalog"])

    assert result == set()
    client.statement_execution.execute_statement.assert_called_once()


def test_uc_helper_uses_external_links_disposition():
    """The fetch methods pass disposition=Disposition.EXTERNAL_LINKS to execute_statement."""
    client = _make_mock_workspace_client()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    helper.fetch_actual_tags(["cat1"])

    call_kwargs = client.statement_execution.execute_statement.call_args
    assert call_kwargs.kwargs.get("disposition") == Disposition.EXTERNAL_LINKS


def test_uc_helper_queries_scoped_to_provided_catalog_names():
    """The SQL contains the provided catalog names."""
    client = _make_mock_workspace_client()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    helper.fetch_actual_tags(["alpha_catalog", "beta_catalog"])

    call_kwargs = client.statement_execution.execute_statement.call_args
    statement = call_kwargs.kwargs.get("statement", "")
    if not statement and call_kwargs.args:
        statement = call_kwargs.args[0]

    assert "alpha_catalog" in statement, (
        f"Expected 'alpha_catalog' in SQL: {statement}"
    )
    assert "beta_catalog" in statement, (
        f"Expected 'beta_catalog' in SQL: {statement}"
    )


def test_uc_helper_caches_tags_after_fetch():
    """Calling fetch_actual_tags twice -> execute_statement called only once."""
    client = _make_mock_workspace_client(data_array=[])
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    helper.fetch_actual_tags(["my_catalog"])
    helper.fetch_actual_tags(["my_catalog"])

    assert client.statement_execution.execute_statement.call_count == 1


def test_uc_helper_tags_query_is_valid_sql():
    """The tags fetch query parses as valid SQL, references the expected system tables,
    and aggregates tags per securable via collect_list + GROUP BY."""
    client = _make_mock_workspace_client()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    helper.fetch_actual_tags(["my_catalog", "other_catalog"])

    sql = _get_executed_sql(client)
    stmt = _parse_sql(sql)

    # Should be a valid SQL statement (UNION ALL of SELECTs)
    assert isinstance(stmt, (sqlglot.exp.Select, sqlglot.exp.Union))

    # Should reference all four tag system tables
    tables = _get_table_names(stmt)
    assert "catalog_tags" in tables
    assert "schema_tags" in tables
    assert "table_tags" in tables
    assert "volume_tags" in tables

    # Output columns should still include the securable identity; tags are now aggregated
    sql_upper = sql.upper()
    assert "SECURABLE_TYPE" in sql_upper
    assert "SECURABLE_FULL_NAME" in sql_upper

    # Aggregation pattern must be present
    assert "COLLECT_LIST" in sql_upper
    assert "GROUP BY" in sql_upper
    assert "TO_JSON" in sql_upper

    # Catalog names should appear in WHERE IN clauses
    assert "'my_catalog'" in sql
    assert "'other_catalog'" in sql


def test_uc_helper_tags_query_groups_by_securable_columns_per_arm():
    """Each UNION ALL arm GROUPs BY the securable's identifying columns so the result is
    at the securable grain (one row per securable)."""
    client = _make_mock_workspace_client()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    helper.fetch_actual_tags(["my_catalog"])

    sql = _get_executed_sql(client).lower()

    # Each arm must carry an appropriate GROUP BY covering its securable's identity.
    # Loose substring checks — GROUP BY clauses are on the same line as the table.
    assert "from system.information_schema.catalog_tags" in sql
    assert "group by catalog_name" in sql

    assert "from system.information_schema.schema_tags" in sql
    assert "group by catalog_name, schema_name" in sql

    assert "from system.information_schema.table_tags" in sql
    assert "group by catalog_name, schema_name, table_name" in sql

    assert "from system.information_schema.volume_tags" in sql
    assert "group by catalog_name, schema_name, volume_name" in sql

    assert "from system.information_schema.column_tags" in sql
    assert "group by catalog_name, schema_name, table_name, column_name" in sql


# ---------------------------------------------------------------------------
# UnityCatalogHelper.fetch_actual_privileges
# ---------------------------------------------------------------------------


@patch("uc_abac_governor.helpers.unity_catalog._fetch_external_links_rows")
def test_uc_helper_fetches_actual_privileges_from_query_results(mock_fetch):
    """Mock returns privilege rows -> correct set of SecurablePrivilege."""
    rows = [
        ["CATALOG", "my_catalog", "data_engineers", "USE_CATALOG"],
        ["SCHEMA", "my_catalog.sales", "analysts", "SELECT"],
    ]
    mock_fetch.return_value = rows
    client = _make_mock_workspace_client()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    result = helper.fetch_actual_privileges(["my_catalog"])

    expected = {
        SecurablePrivilege(
            securable_type=SecurableType.CATALOG,
            securable_full_name="my_catalog",
            principal=Principal(principal_type=PrincipalType.UNKNOWN, identifier="data_engineers"),
            privilege_type=PrivilegeType.USE_CATALOG,
        ),
        SecurablePrivilege(
            securable_type=SecurableType.SCHEMA,
            securable_full_name="my_catalog.sales",
            principal=Principal(principal_type=PrincipalType.UNKNOWN, identifier="analysts"),
            privilege_type=PrivilegeType.SELECT,
        ),
    }
    assert result == expected


@patch("uc_abac_governor.helpers.unity_catalog._fetch_external_links_rows")
def test_uc_helper_fetches_volume_privileges_from_query_results(mock_fetch):
    """Mock returns volume privilege rows -> correct set of SecurablePrivilege."""
    rows = [
        ["VOLUME", "my_catalog.landing.raw_events", "data_engineers", "READ_VOLUME"],
        ["VOLUME", "my_catalog.landing.raw_events", "data_engineers", "WRITE_VOLUME"],
    ]
    mock_fetch.return_value = rows
    client = _make_mock_workspace_client()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    result = helper.fetch_actual_privileges(["my_catalog"])

    expected = {
        SecurablePrivilege(
            securable_type=SecurableType.VOLUME,
            securable_full_name="my_catalog.landing.raw_events",
            principal=Principal(principal_type=PrincipalType.UNKNOWN, identifier="data_engineers"),
            privilege_type=PrivilegeType.READ_VOLUME,
        ),
        SecurablePrivilege(
            securable_type=SecurableType.VOLUME,
            securable_full_name="my_catalog.landing.raw_events",
            principal=Principal(principal_type=PrincipalType.UNKNOWN, identifier="data_engineers"),
            privilege_type=PrivilegeType.WRITE_VOLUME,
        ),
    }
    assert result == expected


def test_uc_helper_fetches_no_privileges_given_no_rows():
    """Mock returns no rows -> empty set, but a query was still executed."""
    client = _make_mock_workspace_client(data_array=[])
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    result = helper.fetch_actual_privileges(["some_catalog"])

    assert result == set()
    client.statement_execution.execute_statement.assert_called_once()


def test_uc_helper_caches_privileges_after_fetch():
    """Calling fetch_actual_privileges twice -> execute_statement called only once."""
    client = _make_mock_workspace_client(data_array=[])
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    helper.fetch_actual_privileges(["my_catalog"])
    helper.fetch_actual_privileges(["my_catalog"])

    assert client.statement_execution.execute_statement.call_count == 1


def test_uc_helper_privileges_query_is_valid_sql():
    """The privileges fetch query parses as valid SQL and references the expected system table."""
    client = _make_mock_workspace_client()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    helper.fetch_actual_privileges(["my_catalog"])

    sql = _get_executed_sql(client)
    stmt = _parse_sql(sql)

    # Should be a SELECT statement
    assert isinstance(stmt, sqlglot.exp.Select)

    # Should reference all privilege system tables
    tables = _get_table_names(stmt)
    assert "catalog_privileges" in tables
    assert "schema_privileges" in tables
    assert "table_privileges" in tables
    assert "volume_privileges" in tables

    # Output columns should include the expected aliases
    sql_upper = sql.upper()
    assert "SECURABLE_TYPE" in sql_upper
    assert "SECURABLE_FULL_NAME" in sql_upper
    assert "PRIVILEGE_TYPE" in sql_upper

    # Should NOT reference grantor_type (wrong column)
    assert "GRANTOR_TYPE" not in sql_upper

    # Catalog name should appear in WHERE clause
    assert "'my_catalog'" in sql


# ---------------------------------------------------------------------------
# UnityCatalogHelper.execute_sql
# ---------------------------------------------------------------------------


def test_uc_helper_passes_statement_to_workspace_client():
    """execute_sql calls statement_execution.execute_statement with the SQL."""
    client = _make_mock_workspace_client()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    helper.execute_sql("CREATE SCHEMA my_catalog.new_schema")

    client.statement_execution.execute_statement.assert_called_once()
    call_kwargs = client.statement_execution.execute_statement.call_args
    # The SQL statement should appear in the call (as positional or keyword arg).
    assert "CREATE SCHEMA my_catalog.new_schema" in (
        call_kwargs.kwargs.get("statement", ""),
        *(call_kwargs.args if call_kwargs.args else []),
    )


# ---------------------------------------------------------------------------
# Hybrid polling
# ---------------------------------------------------------------------------


def _make_statement_response(
    state: StatementState,
    statement_id: str = "stmt-123",
    error_message: str | None = None,
) -> MagicMock:
    """Build a mock StatementResponse with the given state and optional error."""
    response = MagicMock()
    response.status.state = state
    response.statement_id = statement_id
    response.result.data_array = []
    response.result.external_links = []
    response.manifest.schema.columns = []
    if error_message is not None:
        response.status.error.message = error_message
    else:
        response.status.error = None
    return response


@patch("uc_abac_governor.helpers.unity_catalog._fetch_external_links_rows")
def test_uc_helper_returns_results_when_query_completes_within_timeout(mock_fetch):
    """When execute_statement returns SUCCEEDED, results are returned without polling."""
    tag_rows = [
        ["CATALOG", "my_catalog", '[{"tag_name":"env","tag_value":"prod"}]'],
    ]
    mock_fetch.return_value = tag_rows

    response = _make_statement_response(StatementState.SUCCEEDED)
    client = MagicMock()
    client.statement_execution.execute_statement.return_value = response

    helper = UnityCatalogHelper(client, WAREHOUSE_ID)
    result = helper.fetch_actual_tags(["my_catalog"])

    # Should NOT have polled via get_statement
    client.statement_execution.get_statement.assert_not_called()

    # Should have returned the parsed tags
    expected = {
        SecurableTag(
            securable_type=SecurableType.CATALOG,
            securable_full_name="my_catalog",
            tag_name="env",
            tag_value="prod",
        ),
    }
    assert result == expected


@patch("time.sleep")
@patch("uc_abac_governor.helpers.unity_catalog._fetch_external_links_rows")
def test_uc_helper_polls_for_results_when_query_exceeds_timeout(mock_fetch, mock_sleep):
    """When execute_statement returns PENDING, polls get_statement until SUCCEEDED."""
    tag_rows = [
        ["TABLE", "my_catalog.sales.orders", '[{"tag_name":"pii","tag_value":"true"}]'],
    ]

    # execute_statement returns PENDING
    initial_response = _make_statement_response(StatementState.PENDING, statement_id="stmt-123")
    client = MagicMock()
    client.statement_execution.execute_statement.return_value = initial_response

    # First poll: RUNNING, second poll: SUCCEEDED
    running_response = _make_statement_response(StatementState.RUNNING, statement_id="stmt-123")
    succeeded_response = _make_statement_response(StatementState.SUCCEEDED, statement_id="stmt-123")
    client.statement_execution.get_statement.side_effect = [running_response, succeeded_response]

    # _fetch_external_links_rows returns rows for the final succeeded response
    mock_fetch.return_value = tag_rows

    helper = UnityCatalogHelper(client, WAREHOUSE_ID)
    result = helper.fetch_actual_tags(["my_catalog"])

    # Should have polled exactly 2 times
    assert client.statement_execution.get_statement.call_count == 2
    client.statement_execution.get_statement.assert_any_call("stmt-123")

    # Should have slept with the production polling interval
    mock_sleep.assert_called_with(_POLL_INTERVAL_SECONDS)

    # Should return parsed results
    assert len(result) == 1


@patch("uc_abac_governor.helpers.unity_catalog._fetch_external_links_rows")
def test_uc_helper_raises_on_failed_query(mock_fetch):
    """When execute_statement returns FAILED, a GovernorError is raised."""
    mock_fetch.return_value = []

    response = _make_statement_response(
        StatementState.FAILED,
        error_message="Something went wrong",
    )
    client = MagicMock()
    client.statement_execution.execute_statement.return_value = response

    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    with pytest.raises((GovernorError, RuntimeError)):
        helper.fetch_actual_tags(["my_catalog"])


@patch("uc_abac_governor.helpers.unity_catalog._fetch_external_links_rows")
def test_uc_helper_uses_continue_on_wait_timeout(mock_fetch):
    """execute_statement is called with on_wait_timeout=CONTINUE for hybrid polling."""
    mock_fetch.return_value = []

    response = _make_statement_response(StatementState.SUCCEEDED)
    client = MagicMock()
    client.statement_execution.execute_statement.return_value = response

    helper = UnityCatalogHelper(client, WAREHOUSE_ID)
    helper.fetch_actual_tags(["my_catalog"])

    call_kwargs = client.statement_execution.execute_statement.call_args.kwargs
    on_wait_timeout = call_kwargs.get("on_wait_timeout")
    assert on_wait_timeout is not None, "on_wait_timeout kwarg not passed to execute_statement"
    # Accept either the enum value or its string representation
    on_wait_str = str(on_wait_timeout).upper() if on_wait_timeout else ""
    assert "CONTINUE" in on_wait_str, (
        f"Expected on_wait_timeout to contain CONTINUE, got {on_wait_timeout}"
    )


# ---------------------------------------------------------------------------
# Column tags query
# ---------------------------------------------------------------------------


def test_uc_helper_tags_query_includes_column_tags():
    """The tags fetch query references the column_tags system table."""
    client = _make_mock_workspace_client()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    helper.fetch_actual_tags(["my_catalog"])

    sql = _get_executed_sql(client)

    # Should reference column_tags alongside the other tag tables
    assert "column_tags" in sql, (
        f"Expected 'column_tags' in SQL: {sql}"
    )


# ---------------------------------------------------------------------------
# Empty catalog list
# ---------------------------------------------------------------------------


def test_uc_helper_returns_empty_tags_for_empty_catalog_list():
    """Passing an empty catalog list returns an empty set without executing any SQL."""
    client = _make_mock_workspace_client()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    result = helper.fetch_actual_tags([])

    assert result == set()
    client.statement_execution.execute_statement.assert_not_called()


def test_uc_helper_returns_empty_privileges_for_empty_catalog_list():
    """Passing an empty catalog list returns an empty set without executing any SQL."""
    client = _make_mock_workspace_client()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    result = helper.fetch_actual_privileges([])

    assert result == set()
    client.statement_execution.execute_statement.assert_not_called()


# ---------------------------------------------------------------------------
# UnityCatalogHelper.fetch_actual_securables
# ---------------------------------------------------------------------------


@patch("uc_abac_governor.helpers.unity_catalog._fetch_external_links_rows")
def test_uc_helper_parses_securable_rows_for_attributes(mock_fetch):
    """Non-function rows produce SecurableAttributes plus a base Securable per row."""
    rows = [
        ["CATALOG", "my_catalog", "admin_user", None, None],
        ["SCHEMA", "my_catalog.sales", "schema_owner", None, None],
        ["TABLE", "my_catalog.sales.orders", "table_owner", None, None],
        ["VOLUME", "my_catalog.landing.files", "vol_owner", None, None],
    ]
    mock_fetch.return_value = rows
    client = _make_mock_workspace_client()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    securables, attributes = helper.fetch_actual_securables(["my_catalog"])

    expected_attributes = {
        SecurableAttributes(
            securable_type=SecurableType.CATALOG,
            full_name="my_catalog",
            owner=Principal(principal_type=PrincipalType.UNKNOWN, identifier="admin_user"),
        ),
        SecurableAttributes(
            securable_type=SecurableType.SCHEMA,
            full_name="my_catalog.sales",
            owner=Principal(principal_type=PrincipalType.UNKNOWN, identifier="schema_owner"),
        ),
        SecurableAttributes(
            securable_type=SecurableType.TABLE,
            full_name="my_catalog.sales.orders",
            owner=Principal(principal_type=PrincipalType.UNKNOWN, identifier="table_owner"),
        ),
        SecurableAttributes(
            securable_type=SecurableType.VOLUME,
            full_name="my_catalog.landing.files",
            owner=Principal(principal_type=PrincipalType.UNKNOWN, identifier="vol_owner"),
        ),
    }
    assert attributes == expected_attributes
    assert securables == {
        Securable(securable_type=SecurableType.CATALOG, full_name="my_catalog"),
        Securable(securable_type=SecurableType.SCHEMA, full_name="my_catalog.sales"),
        Securable(securable_type=SecurableType.TABLE, full_name="my_catalog.sales.orders"),
        Securable(securable_type=SecurableType.VOLUME, full_name="my_catalog.landing.files"),
    }


@patch("uc_abac_governor.helpers.unity_catalog._fetch_external_links_rows")
def test_uc_helper_fetch_actual_securables_returns_base_securable_for_catalog_rows(mock_fetch):
    """A CATALOG row produces a base Securable(CATALOG, full_name) in the securables set."""
    mock_fetch.return_value = [["CATALOG", "cat_a", None, None, None]]
    helper = UnityCatalogHelper(_make_mock_workspace_client(), WAREHOUSE_ID)

    securables, _ = helper.fetch_actual_securables(["cat_a"])

    assert Securable(securable_type=SecurableType.CATALOG, full_name="cat_a") in securables


@patch("uc_abac_governor.helpers.unity_catalog._fetch_external_links_rows")
def test_uc_helper_fetch_actual_securables_returns_base_securable_for_schema_rows(mock_fetch):
    """A SCHEMA row produces a base Securable(SCHEMA, full_name)."""
    mock_fetch.return_value = [["SCHEMA", "cat.sales", None, None, None]]
    helper = UnityCatalogHelper(_make_mock_workspace_client(), WAREHOUSE_ID)

    securables, _ = helper.fetch_actual_securables(["cat"])

    assert Securable(securable_type=SecurableType.SCHEMA, full_name="cat.sales") in securables


@patch("uc_abac_governor.helpers.unity_catalog._fetch_external_links_rows")
def test_uc_helper_fetch_actual_securables_returns_base_securable_for_table_rows(mock_fetch):
    """A TABLE row produces a base Securable(TABLE, full_name)."""
    mock_fetch.return_value = [["TABLE", "cat.sales.orders", None, None, None]]
    helper = UnityCatalogHelper(_make_mock_workspace_client(), WAREHOUSE_ID)

    securables, _ = helper.fetch_actual_securables(["cat"])

    assert Securable(securable_type=SecurableType.TABLE, full_name="cat.sales.orders") in securables


@patch("uc_abac_governor.helpers.unity_catalog._fetch_external_links_rows")
def test_uc_helper_fetch_actual_securables_returns_base_securable_for_volume_rows(mock_fetch):
    """A VOLUME row produces a base Securable(VOLUME, full_name)."""
    mock_fetch.return_value = [["VOLUME", "cat.landing.files", None, None, None]]
    helper = UnityCatalogHelper(_make_mock_workspace_client(), WAREHOUSE_ID)

    securables, _ = helper.fetch_actual_securables(["cat"])

    assert Securable(securable_type=SecurableType.VOLUME, full_name="cat.landing.files") in securables


@patch("uc_abac_governor.helpers.unity_catalog._fetch_external_links_rows")
def test_uc_helper_parses_securable_rows_for_functions(mock_fetch):
    """Function rows produce Function in the securables set."""
    rows = [
        [
            "FUNCTION",
            "my_catalog.shared.mask_email",
            "func_owner",
            '[{"parameter_name":"col","data_type":"STRING"}]',
            "CASE WHEN is_member('admins') THEN col ELSE '***' END",
            None,
        ],
    ]
    mock_fetch.return_value = rows
    client = _make_mock_workspace_client()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    securables, _attributes = helper.fetch_actual_securables(["my_catalog"])

    expected = {
        Function(
            securable_type=SecurableType.FUNCTION,
            full_name="my_catalog.shared.mask_email",
            parameters=(("col", "STRING"),),
            definition="CASE WHEN is_member('admins') THEN col ELSE '***' END",
            comment=None,
        ),
    }
    assert securables == expected


@patch("uc_abac_governor.helpers.unity_catalog._fetch_external_links_rows")
def test_uc_helper_parses_function_routine_comment_into_function_comment(mock_fetch):
    """When routine_comment is populated, it appears on Function.comment."""
    rows = [
        [
            "FUNCTION",
            "my_catalog.shared.mask_email",
            "func_owner",
            "",
            "col",
            "Masks email column",
        ],
    ]
    mock_fetch.return_value = rows
    client = _make_mock_workspace_client()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    securables, _ = helper.fetch_actual_securables(["my_catalog"])
    (func,) = securables
    assert func.comment == "Masks email column"


@patch("uc_abac_governor.helpers.unity_catalog._fetch_external_links_rows")
def test_uc_helper_parses_securable_rows_emits_function_attributes(mock_fetch):
    """Function rows also emit SecurableAttributes with the owner."""
    rows = [
        [
            "FUNCTION",
            "my_catalog.shared.mask_email",
            "func_owner",
            '[{"parameter_name":"col","data_type":"STRING"}]',
            "CASE WHEN is_member('admins') THEN col ELSE '***' END",
        ],
    ]
    mock_fetch.return_value = rows
    client = _make_mock_workspace_client()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    _securables, attributes = helper.fetch_actual_securables(["my_catalog"])

    expected = {
        SecurableAttributes(
            securable_type=SecurableType.FUNCTION,
            full_name="my_catalog.shared.mask_email",
            owner=Principal(principal_type=PrincipalType.UNKNOWN, identifier="func_owner"),
        ),
    }
    assert attributes == expected


def test_uc_helper_securables_query_is_valid_sql():
    """The securables query parses as valid SQL and references the expected info-schema tables."""
    client = _make_mock_workspace_client()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    helper.fetch_actual_securables(["my_catalog"])

    sql = _get_executed_sql(client)
    stmt = _parse_sql(sql)

    # Should be a valid SQL statement (UNION ALL of SELECTs)
    assert isinstance(stmt, (sqlglot.exp.Select, sqlglot.exp.Union))

    # Should reference the five info-schema tables
    tables = _get_table_names(stmt)
    assert "catalogs" in tables, f"Expected 'catalogs' in tables: {tables}"
    assert "schemata" in tables, f"Expected 'schemata' in tables: {tables}"
    assert "tables" in tables, f"Expected 'tables' in tables: {tables}"
    assert "volumes" in tables, f"Expected 'volumes' in tables: {tables}"
    assert "routines" in tables, f"Expected 'routines' in tables: {tables}"

    # Catalog name should appear in the SQL
    assert "'my_catalog'" in sql


def test_uc_helper_returns_empty_securables_for_empty_catalog_list():
    """Passing an empty catalog list returns empty sets without executing any SQL."""
    client = _make_mock_workspace_client()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    securables, attributes = helper.fetch_actual_securables([])

    assert securables == set()
    assert attributes == set()
    client.statement_execution.execute_statement.assert_not_called()


# ---------------------------------------------------------------------------
# UnityCatalogHelper.update_owner
# ---------------------------------------------------------------------------


def test_uc_helper_update_owner_dispatches_to_catalog_api():
    """update_owner for CATALOG calls client.catalogs.update."""
    client = MagicMock()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    helper.update_owner(SecurableType.CATALOG, "my_catalog", "new_owner")

    client.catalogs.update.assert_called_once_with("my_catalog", owner="new_owner")


def test_uc_helper_update_owner_dispatches_to_function_api():
    """update_owner for FUNCTION calls client.functions.update."""
    client = MagicMock()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    helper.update_owner(SecurableType.FUNCTION, "my_catalog.shared.mask_email", "new_owner")

    client.functions.update.assert_called_once_with(
        "my_catalog.shared.mask_email", owner="new_owner"
    )


# ---------------------------------------------------------------------------
# UnityCatalogHelper.fetch_actual_policies
# ---------------------------------------------------------------------------


def _mask_policy_dict(**overrides) -> dict:
    base = {
        "name": "p1",
        "type": "mask",
        "function": "cat.default.fn",
        "to": ["analysts"],
        "except": ["admins"],
        "columns": [{"alias": "c", "has_tags": {"pii": "email"}}],
    }
    base.update(overrides)
    return base


def _config_with_policy(level: str = "table", **policy_overrides) -> ResourcesConfig:
    policy = _mask_policy_dict(**policy_overrides)
    if level == "catalog":
        data = {"catalogs": {"cat": {"name": "cat", "policies": [policy]}}}
    elif level == "schema":
        data = {
            "catalogs": {
                "cat": {
                    "name": "cat",
                    "schemas": [{"name": "s", "policies": [policy]}],
                }
            }
        }
    else:
        data = {
            "catalogs": {
                "cat": {
                    "name": "cat",
                    "schemas": [
                        {
                            "name": "s",
                            "tables": [{"name": "t", "policies": [policy]}],
                        }
                    ],
                }
            }
        }
    return ResourcesConfig.model_validate(data)


def _make_column_mask_policy_info(
    *,
    name: str = "p1",
    on_securable_type: str = "TABLE",
    on_securable_fullname: str = "cat.s.t",
    function_name: str = "cat.default.fn",
    on_column: str = "c",
    using_column_aliases: tuple[str, ...] = (),
    to_principals: tuple[str, ...] = ("analysts",),
    except_principals: tuple[str, ...] | None = ("admins",),
    when_condition: str | None = None,
    match_column_defs: tuple[tuple[str, str], ...] = (("c", "has_column_tag_value('pii', 'email')"),),
) -> MagicMock:
    """Build a minimal fake PolicyInfo-like object for a column mask policy."""
    from databricks.sdk.service.catalog import PolicyType as SdkPolicyType

    info = MagicMock()
    info.name = name
    info.on_securable_type = MagicMock()
    info.on_securable_type.value = on_securable_type
    info.on_securable_fullname = on_securable_fullname
    info.policy_type = SdkPolicyType.POLICY_TYPE_COLUMN_MASK
    info.column_mask = MagicMock()
    info.column_mask.function_name = function_name
    info.column_mask.on_column = on_column
    info.column_mask.using = [MagicMock(column=a, constant=None) for a in using_column_aliases]
    info.row_filter = None
    info.to_principals = list(to_principals)
    info.except_principals = list(except_principals) if except_principals else None
    info.when_condition = when_condition
    info.match_columns = [MagicMock(alias=a, condition=c) for a, c in match_column_defs]
    info.comment = None
    return info


def _make_row_filter_policy_info(
    *,
    name: str = "p1",
    on_securable_type: str = "TABLE",
    on_securable_fullname: str = "cat.s.t",
    function_name: str = "cat.default.filter_fn",
    using_column_aliases: tuple[str, ...] = ("c_region",),
    to_principals: tuple[str, ...] = ("analysts",),
    except_principals: tuple[str, ...] | None = None,
    when_condition: str | None = None,
    match_column_defs: tuple[tuple[str, str], ...] = (("c_region", "has_column_tag('geo')"),),
) -> MagicMock:
    from databricks.sdk.service.catalog import PolicyType as SdkPolicyType

    info = MagicMock()
    info.name = name
    info.on_securable_type = MagicMock()
    info.on_securable_type.value = on_securable_type
    info.on_securable_fullname = on_securable_fullname
    info.policy_type = SdkPolicyType.POLICY_TYPE_ROW_FILTER
    info.column_mask = None
    info.row_filter = MagicMock()
    info.row_filter.function_name = function_name
    info.row_filter.using = [MagicMock(column=a, constant=None) for a in using_column_aliases]
    info.to_principals = list(to_principals)
    info.except_principals = list(except_principals) if except_principals else None
    info.when_condition = when_condition
    info.match_columns = [MagicMock(alias=a, condition=c) for a, c in match_column_defs]
    info.comment = None
    return info


def test_uc_helper_fetch_actual_policies_skips_sdk_when_no_policies_configured():
    """A config with no mask/filter policies returns empty set without calling list_policies."""
    config = ResourcesConfig.model_validate({"catalogs": {"cat": {"name": "cat"}}})
    client = MagicMock()
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    assert helper.fetch_actual_policies(config) == set()
    client.policies.list_policies.assert_not_called()


def test_uc_helper_fetch_actual_policies_calls_list_per_configured_securable():
    """list_policies is called once per securable that has a mask/filter policy configured."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "name": "cat",
                    "policies": [_mask_policy_dict(name="cp")],
                    "schemas": [
                        {
                            "name": "s",
                            "policies": [_mask_policy_dict(name="sp")],
                            "tables": [
                                {"name": "t", "policies": [_mask_policy_dict(name="tp")]}
                            ],
                        }
                    ],
                }
            }
        }
    )
    client = MagicMock()
    client.policies.list_policies.return_value = iter([])
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    helper.fetch_actual_policies(config)

    assert client.policies.list_policies.call_count == 3
    call_args = {
        (c.kwargs.get("on_securable_type"), c.kwargs.get("on_securable_fullname"))
        for c in client.policies.list_policies.call_args_list
    }
    assert call_args == {
        ("CATALOG", "cat"),
        ("SCHEMA", "cat.s"),
        ("TABLE", "cat.s.t"),
    }


def test_uc_helper_fetch_actual_policies_normalises_column_mask():
    config = _config_with_policy("table")
    client = MagicMock()
    client.policies.list_policies.return_value = iter([
        _make_column_mask_policy_info(
            using_column_aliases=("c_extra",),
            match_column_defs=(
                ("c", "has_column_tag_value('pii', 'email')"),
                ("c_extra", "has_column_tag('geo')"),
            ),
        )
    ])
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    result = helper.fetch_actual_policies(config)
    (policy,) = result
    assert isinstance(policy, Policy)
    assert policy.policy_type == PolicyType.MASK
    assert policy.securable_type == SecurableType.TABLE
    assert policy.securable_full_name == "cat.s.t"
    assert policy.name == "p1"
    assert policy.function_name == "cat.default.fn"
    assert policy.to_principals == (
        Principal(principal_type=PrincipalType.UNKNOWN, identifier="analysts"),
    )
    assert policy.except_principals == (
        Principal(principal_type=PrincipalType.UNKNOWN, identifier="admins"),
    )
    assert policy.on_column == "c"
    assert policy.using_columns == ("c_extra",)
    assert policy.match_columns == (
        ("c", "has_column_tag_value('pii', 'email')"),
        ("c_extra", "has_column_tag('geo')"),
    )


def test_uc_helper_fetch_actual_policies_normalises_row_filter():
    config = _config_with_policy("table", type="filter", function="cat.default.filter_fn")
    client = MagicMock()
    client.policies.list_policies.return_value = iter([_make_row_filter_policy_info()])
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    (policy,) = helper.fetch_actual_policies(config)
    assert policy.policy_type == PolicyType.FILTER
    assert policy.function_name == "cat.default.filter_fn"
    assert policy.on_column is None
    assert policy.using_columns == ("c_region",)


def test_uc_helper_fetch_actual_policies_filters_out_unknown_policy_types():
    """Policies of non-mask/filter types (future SDK additions) are skipped."""
    config = _config_with_policy("table")
    fake = MagicMock()
    fake.policy_type = MagicMock()
    fake.policy_type.value = "POLICY_TYPE_OTHER"
    client = MagicMock()
    client.policies.list_policies.return_value = iter([fake])
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    assert helper.fetch_actual_policies(config) == set()


def test_uc_helper_fetch_actual_policies_caches_result():
    config = _config_with_policy("table")
    client = MagicMock()
    client.policies.list_policies.side_effect = [iter([_make_column_mask_policy_info()])]
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    first = helper.fetch_actual_policies(config)
    second = helper.fetch_actual_policies(config)

    assert first == second
    client.policies.list_policies.assert_called_once()


def test_uc_helper_fetch_actual_policies_handles_empty_except_principals():
    config = _config_with_policy("table")
    client = MagicMock()
    client.policies.list_policies.return_value = iter([
        _make_column_mask_policy_info(except_principals=None)
    ])
    helper = UnityCatalogHelper(client, WAREHOUSE_ID)

    (policy,) = helper.fetch_actual_policies(config)
    assert policy.except_principals == ()
