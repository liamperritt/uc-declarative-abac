from __future__ import annotations

from unittest.mock import MagicMock, patch

import sqlglot
from databricks.sdk.service.sql import Disposition

from uc_governor.helpers.unity_catalog import UnityCatalogHelper
from uc_governor.privileges.state import SecurablePrivilege
from uc_governor.tags.state import SecurableTag
from uc_governor.types import SecurableType

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
    response.result.data_array = data_array if data_array is not None else []
    response.result.external_links = []
    response.manifest.schema.columns = []

    client.statement_execution.execute_statement.return_value = response
    return client


# ---------------------------------------------------------------------------
# UnityCatalogHelper.fetch_actual_tags
# ---------------------------------------------------------------------------


@patch("uc_governor.helpers.unity_catalog._fetch_external_links_rows")
def test_uc_helper_fetches_actual_tags_from_query_results(mock_fetch):
    """Mock returns tag rows -> correct set of SecurableTag."""
    rows = [
        ["CATALOG", "my_catalog", "env", "prod"],
        ["TABLE", "my_catalog.sales.orders", "pii", "true"],
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
    """The tags fetch query parses as valid SQL and references the expected system tables."""
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

    # Output columns should include the expected names
    sql_upper = sql.upper()
    assert "SECURABLE_TYPE" in sql_upper
    assert "SECURABLE_FULL_NAME" in sql_upper
    assert "TAG_NAME" in sql_upper
    assert "TAG_VALUE" in sql_upper

    # Catalog names should appear in WHERE IN clauses
    assert "'my_catalog'" in sql
    assert "'other_catalog'" in sql


# ---------------------------------------------------------------------------
# UnityCatalogHelper.fetch_actual_privileges
# ---------------------------------------------------------------------------


@patch("uc_governor.helpers.unity_catalog._fetch_external_links_rows")
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
            principal="data_engineers",
            privilege_type="USE_CATALOG",
        ),
        SecurablePrivilege(
            securable_type=SecurableType.SCHEMA,
            securable_full_name="my_catalog.sales",
            principal="analysts",
            privilege_type="SELECT",
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

    # Should reference the privileges system table
    tables = _get_table_names(stmt)
    assert "table_privileges" in tables

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
