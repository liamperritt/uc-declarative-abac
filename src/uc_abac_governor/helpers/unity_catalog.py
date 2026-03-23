from __future__ import annotations

from databricks.sdk import WorkspaceClient

from uc_abac_governor.privileges.state import SecurablePrivilege
from uc_abac_governor.tags.state import SecurableTag


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
        raise NotImplementedError

    def fetch_actual_privileges(self, catalog_names: list[str]) -> set[SecurablePrivilege]:
        """Query system tables for all explicit privileges on securables in the given catalogs.

        Filters to inherited_from='NONE' to only return directly granted privileges.
        Results are cached after the first call.
        """
        raise NotImplementedError

    def execute_sql(self, statement: str) -> None:
        """Execute a SQL statement via the Statement Execution API."""
        raise NotImplementedError
