from __future__ import annotations

import json
import time

import requests
from databricks.sdk import WorkspaceClient
from databricks.sdk.service.sql import (
    Disposition,
    ExecuteStatementRequestOnWaitTimeout,
    StatementResponse,
    StatementState,
)

from uc_governor.privileges.state import SecurablePrivilege
from uc_governor.tags.state import SecurableTag
from uc_governor.types import GovernorError, SecurableType

_POLL_INTERVAL_SECONDS = 10


def _build_catalog_in_clause(catalog_names: list[str]) -> str:
    """Build a SQL IN clause from a list of catalog names."""
    quoted = ", ".join(f"'{name}'" for name in catalog_names)
    return f"({quoted})"


def _build_tags_query(catalog_names: list[str]) -> str:
    """Build a UNION ALL query across all tag system tables for the given catalogs."""
    in_clause = _build_catalog_in_clause(catalog_names)
    full_name_exprs = {
        "catalog_tags": ("CATALOG", "catalog_name"),
        "schema_tags": ("SCHEMA", "concat(catalog_name, '.', schema_name)"),
        "table_tags": ("TABLE", "concat(catalog_name, '.', schema_name, '.', table_name)"),
        "volume_tags": ("VOLUME", "concat(catalog_name, '.', schema_name, '.', volume_name)"),
    }
    parts = []
    for table, (sec_type, full_name_expr) in full_name_exprs.items():
        parts.append(
            f"SELECT '{sec_type}' AS securable_type, "
            f"{full_name_expr} AS securable_full_name, "
            f"tag_name, tag_value "
            f"FROM system.information_schema.{table} "
            f"WHERE catalog_name IN {in_clause}"
        )
    return " UNION ALL ".join(parts)


def _build_privileges_query(catalog_names: list[str]) -> str:
    """Build a UNION ALL query across privilege system tables for the given catalogs."""
    in_clause = _build_catalog_in_clause(catalog_names)
    parts = [
        f"SELECT 'CATALOG' AS securable_type, catalog_name AS securable_full_name, "
        f"grantee, privilege_type "
        f"FROM system.information_schema.catalog_privileges "
        f"WHERE catalog_name IN {in_clause} AND inherited_from = 'NONE'",

        f"SELECT 'SCHEMA' AS securable_type, "
        f"concat(catalog_name, '.', schema_name) AS securable_full_name, "
        f"grantee, privilege_type "
        f"FROM system.information_schema.schema_privileges "
        f"WHERE catalog_name IN {in_clause} AND inherited_from = 'NONE'",

        f"SELECT 'TABLE' AS securable_type, "
        f"concat(table_catalog, '.', table_schema, '.', table_name) AS securable_full_name, "
        f"grantee, privilege_type "
        f"FROM system.information_schema.table_privileges "
        f"WHERE table_catalog IN {in_clause} AND inherited_from = 'NONE'",

        f"SELECT 'VOLUME' AS securable_type, "
        f"concat(volume_catalog, '.', volume_schema, '.', volume_name) AS securable_full_name, "
        f"grantee, privilege_type "
        f"FROM system.information_schema.volume_privileges "
        f"WHERE volume_catalog IN {in_clause} AND inherited_from = 'NONE'",
    ]
    inner = " UNION ALL ".join(parts)
    return f"SELECT securable_type, securable_full_name, grantee, privilege_type FROM ({inner})"


def _parse_tag_rows(rows: list[list[str]]) -> set[SecurableTag]:
    """Parse raw SQL result rows into a set of SecurableTag."""
    return {
        SecurableTag(
            securable_type=SecurableType(row[0]),
            securable_full_name=row[1],
            tag_name=row[2],
            tag_value=row[3],
        )
        for row in rows
    }


def _parse_privilege_rows(rows: list[list[str]]) -> set[SecurablePrivilege]:
    """Parse raw SQL result rows into a set of SecurablePrivilege."""
    return {
        SecurablePrivilege(
            securable_type=SecurableType(row[0]),
            securable_full_name=row[1],
            principal=row[2],
            privilege_type=row[3],
        )
        for row in rows
    }


def _fetch_external_links_rows(response: StatementResponse) -> list[list[str]]:
    """Fetch all rows from a statement response using external links."""
    rows: list[list[str]] = []
    if not response.result or not response.result.external_links:
        return rows
    for link in response.result.external_links:
        resp = requests.get(link.external_link, headers=link.http_headers)
        resp.raise_for_status()
        rows.extend(json.loads(resp.text))
    return rows


class UnityCatalogHelper:
    """Wraps WorkspaceClient for querying UC state and executing SQL.

    Uses the Statement Execution API with external links disposition
    for efficient result streaming. Caches results after initial fetch.
    """

    def __init__(self, workspace_client: WorkspaceClient, warehouse_id: str) -> None:
        self._client = workspace_client
        self._warehouse_id = warehouse_id
        self._tags_cache: set[SecurableTag] | None = None
        self._privileges_cache: set[SecurablePrivilege] | None = None

    def _execute_and_poll(self, statement: str) -> StatementResponse:
        """Execute a SQL statement with hybrid polling for long-running queries.

        Waits up to 50s for results. If the query is still running, polls
        every 10s via get_statement until it completes.
        Raises GovernorError on FAILED or CANCELED states.
        """
        response = self._client.statement_execution.execute_statement(
            statement=statement,
            warehouse_id=self._warehouse_id,
            disposition=Disposition.EXTERNAL_LINKS,
            wait_timeout="50s",
            on_wait_timeout=ExecuteStatementRequestOnWaitTimeout.CONTINUE,
        )
        while response.status.state in (StatementState.PENDING, StatementState.RUNNING):
            time.sleep(_POLL_INTERVAL_SECONDS)
            response = self._client.statement_execution.get_statement(response.statement_id)

        if response.status.state != StatementState.SUCCEEDED:
            error_msg = getattr(response.status.error, "message", "Unknown error")
            raise GovernorError(f"SQL query failed ({response.status.state}): {error_msg}")

        return response

    def fetch_actual_tags(self, catalog_names: list[str]) -> set[SecurableTag]:
        """Query system tables for all tags on securables in the given catalogs.

        Results are cached after the first call.
        """
        if self._tags_cache is not None:
            return self._tags_cache

        response = self._execute_and_poll(_build_tags_query(catalog_names))
        rows = _fetch_external_links_rows(response)
        self._tags_cache = _parse_tag_rows(rows)
        return self._tags_cache

    def fetch_actual_privileges(self, catalog_names: list[str]) -> set[SecurablePrivilege]:
        """Query system tables for all explicit privileges on securables in the given catalogs.

        Filters to inherited_from='NONE' to only return directly granted privileges.
        Results are cached after the first call.
        """
        if self._privileges_cache is not None:
            return self._privileges_cache

        response = self._execute_and_poll(_build_privileges_query(catalog_names))
        rows = _fetch_external_links_rows(response)
        self._privileges_cache = _parse_privilege_rows(rows)
        return self._privileges_cache

    def execute_sql(self, statement: str) -> None:
        """Execute a SQL statement via the Statement Execution API."""
        self._execute_and_poll(statement)
