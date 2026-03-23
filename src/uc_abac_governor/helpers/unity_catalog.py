from __future__ import annotations

from databricks.sdk import WorkspaceClient
from databricks.sdk.service.sql import Disposition

from uc_abac_governor.privileges.state import SecurablePrivilege
from uc_abac_governor.tags.state import SecurableTag
from uc_abac_governor.types import SecurableType


def _build_catalog_in_clause(catalog_names: list[str]) -> str:
    """Build a SQL IN clause from a list of catalog names."""
    quoted = ", ".join(f"'{name}'" for name in catalog_names)
    return f"({quoted})"


def _build_tags_query(catalog_names: list[str]) -> str:
    """Build a UNION ALL query across all tag system tables for the given catalogs."""
    in_clause = _build_catalog_in_clause(catalog_names)
    tag_tables = [
        "catalog_tags",
        "schema_tags",
        "table_tags",
        "volume_tags",
    ]
    parts = []
    for table in tag_tables:
        parts.append(
            f"SELECT tag_name, tag_value, catalog_name, schema_name, "
            f"  CASE WHEN '{table}' = 'catalog_tags' THEN 'CATALOG' "
            f"      WHEN '{table}' = 'schema_tags' THEN 'SCHEMA' "
            f"      WHEN '{table}' = 'table_tags' THEN 'TABLE' "
            f"      WHEN '{table}' = 'volume_tags' THEN 'VOLUME' "
            f"  END AS securable_type, "
            f"  CASE WHEN '{table}' = 'catalog_tags' THEN catalog_name "
            f"      WHEN '{table}' = 'schema_tags' THEN concat(catalog_name, '.', schema_name) "
            f"      WHEN '{table}' = 'table_tags' THEN concat(catalog_name, '.', schema_name, '.', table_name) "
            f"      WHEN '{table}' = 'volume_tags' THEN concat(catalog_name, '.', schema_name, '.', volume_name) "
            f"  END AS securable_full_name "
            f"FROM system.information_schema.{table} "
            f"WHERE catalog_name IN {in_clause}"
        )
    inner = " UNION ALL ".join(parts)
    return (
        f"SELECT securable_type, securable_full_name, tag_name, tag_value "
        f"FROM ({inner})"
    )


def _build_privileges_query(catalog_names: list[str]) -> str:
    """Build a query for privileges across the given catalogs."""
    in_clause = _build_catalog_in_clause(catalog_names)
    return (
        f"SELECT grantor_type AS securable_type, "
        f"  table_catalog || '.' || table_schema || '.' || table_name AS securable_full_name, "
        f"  grantee AS principal, privilege_type "
        f"FROM system.information_schema.table_privileges "
        f"WHERE table_catalog IN {in_clause}"
    )


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

    def fetch_actual_tags(self, catalog_names: list[str]) -> set[SecurableTag]:
        """Query system tables for all tags on securables in the given catalogs.

        Results are cached after the first call.
        """
        if self._tags_cache is not None:
            return self._tags_cache

        sql = _build_tags_query(catalog_names)
        response = self._client.statement_execution.execute_statement(
            statement=sql,
            warehouse_id=self._warehouse_id,
            disposition=Disposition.EXTERNAL_LINKS,
        )
        rows = response.result.data_array or []
        self._tags_cache = _parse_tag_rows(rows)
        return self._tags_cache

    def fetch_actual_privileges(self, catalog_names: list[str]) -> set[SecurablePrivilege]:
        """Query system tables for all explicit privileges on securables in the given catalogs.

        Filters to inherited_from='NONE' to only return directly granted privileges.
        Results are cached after the first call.
        """
        if self._privileges_cache is not None:
            return self._privileges_cache

        sql = _build_privileges_query(catalog_names)
        response = self._client.statement_execution.execute_statement(
            statement=sql,
            warehouse_id=self._warehouse_id,
            disposition=Disposition.EXTERNAL_LINKS,
        )
        rows = response.result.data_array or []
        self._privileges_cache = _parse_privilege_rows(rows)
        return self._privileges_cache

    def execute_sql(self, statement: str) -> None:
        """Execute a SQL statement via the Statement Execution API."""
        self._client.statement_execution.execute_statement(
            statement=statement,
            warehouse_id=self._warehouse_id,
        )
