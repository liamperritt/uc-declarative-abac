from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from databricks.sdk import WorkspaceClient
from databricks.sdk.service.catalog import PolicyInfo
from databricks.sdk.service.catalog import PolicyType as SdkPolicyType
from databricks.sdk.service.sql import (
    Disposition,
    ExecuteStatementRequestOnWaitTimeout,
    StatementResponse,
    StatementState,
)

import logging

from uc_abac_governor.configs.models import (
    BaseFgacPolicyConfig,
    ResourcesConfig,
)
from uc_abac_governor.policies.state import Policy
from uc_abac_governor.principals.state import Principal
from uc_abac_governor.tags.state import SecurableTag
from uc_abac_governor.privileges.state import SecurablePrivilege
from uc_abac_governor.securables.state import FunctionInfo, SecurableAttributes, SecurableInfo
from uc_abac_governor.types import GovernorError, PolicyType, PrincipalType, PrivilegeType, SecurableType

_logger = logging.getLogger("uc_abac_governor")

_POLL_INTERVAL_SECONDS = 10

_MAX_POLICY_LIST_WORKERS = 32


def _build_catalog_in_clause(catalog_names: list[str]) -> str:
    """Build a SQL IN clause from a list of catalog names."""
    quoted = ", ".join(f"'{name}'" for name in catalog_names)
    return f"({quoted})"


def _build_tags_query(catalog_names: list[str]) -> str:
    """Build a UNION ALL query across all tag system tables for the given catalogs."""
    in_clause = _build_catalog_in_clause(catalog_names)
    full_name_exprs = {
        "catalog_tags": ("CATALOG", "catalog_name", False),
        "schema_tags": ("SCHEMA", "concat(catalog_name, '.', schema_name)", True),
        "table_tags": ("TABLE", "concat(catalog_name, '.', schema_name, '.', table_name)", True),
        "volume_tags": ("VOLUME", "concat(catalog_name, '.', schema_name, '.', volume_name)", True),
        "column_tags": ("COLUMN", "concat(catalog_name, '.', schema_name, '.', table_name, '.', column_name)", True),
    }
    parts = []
    for table, (sec_type, full_name_expr, has_schema) in full_name_exprs.items():
        where = f"catalog_name IN {in_clause}"
        if has_schema:
            where += " AND schema_name != 'information_schema'"
        parts.append(
            f"SELECT '{sec_type}' AS securable_type, "
            f"{full_name_expr} AS securable_full_name, "
            f"tag_name, tag_value "
            f"FROM system.information_schema.{table} "
            f"WHERE {where}"
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
        f"WHERE catalog_name IN {in_clause} AND inherited_from = 'NONE' AND schema_name != 'information_schema'",

        f"SELECT 'TABLE' AS securable_type, "
        f"concat(table_catalog, '.', table_schema, '.', table_name) AS securable_full_name, "
        f"grantee, privilege_type "
        f"FROM system.information_schema.table_privileges "
        f"WHERE table_catalog IN {in_clause} AND inherited_from = 'NONE' AND table_schema != 'information_schema'",

        f"SELECT 'VOLUME' AS securable_type, "
        f"concat(volume_catalog, '.', volume_schema, '.', volume_name) AS securable_full_name, "
        f"grantee, privilege_type "
        f"FROM system.information_schema.volume_privileges "
        f"WHERE volume_catalog IN {in_clause} AND inherited_from = 'NONE' AND volume_schema != 'information_schema'",
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
    """Parse raw SQL result rows into a set of SecurablePrivilege with
    unresolved Principals.

    Converts privilege_type strings to PrivilegeType enums. Rows with
    unsupported privilege types are skipped with a logged error. Each
    grantee becomes an unresolved Principal carrying the raw identifier;
    resolution happens in the per-domain resolver post-fetch.
    """
    result: set[SecurablePrivilege] = set()
    for row in rows:
        try:
            privilege_type = PrivilegeType(row[3].lower())
        except ValueError:
            _logger.error(f"Skipping privilege from system table: unsupported type '{row[3]}'")
            continue
        result.add(
            SecurablePrivilege(
                securable_type=SecurableType(row[0]),
                securable_full_name=row[1],
                principal=Principal(principal_type=PrincipalType.UNKNOWN, identifier=row[2]),
                privilege_type=privilege_type,
            )
        )
    return result


def _fetch_external_links_rows(response: StatementResponse) -> list[list[str]]:
    """Fetch all rows from a statement response using external links."""
    rows: list[list[str]] = []
    if not response.result or not response.result.external_links:
        return rows
    for link in response.result.external_links:
        resp = requests.get(link.external_link, headers=link.http_headers)
        resp.raise_for_status()
        try:
            rows.extend(json.loads(resp.text))
        except json.JSONDecodeError as e:
            raise GovernorError(f"Failed to parse external link response: {e}") from e
    return rows


def _build_securables_query(catalog_names: list[str]) -> str:
    """Build a UNION ALL query for securable attributes and function definitions."""
    in_clause = _build_catalog_in_clause(catalog_names)
    parts = [
        f"SELECT 'CATALOG' AS securable_type, catalog_name AS full_name, "
        f"catalog_owner AS owner, NULL AS parameters, NULL AS routine_definition "
        f"FROM system.information_schema.catalogs "
        f"WHERE catalog_name IN {in_clause}",

        f"SELECT 'SCHEMA' AS securable_type, "
        f"concat(catalog_name, '.', schema_name) AS full_name, "
        f"schema_owner AS owner, NULL AS parameters, NULL AS routine_definition "
        f"FROM system.information_schema.schemata "
        f"WHERE catalog_name IN {in_clause} AND schema_name != 'information_schema'",

        f"SELECT 'TABLE' AS securable_type, "
        f"concat(table_catalog, '.', table_schema, '.', table_name) AS full_name, "
        f"table_owner AS owner, NULL AS parameters, NULL AS routine_definition "
        f"FROM system.information_schema.tables "
        f"WHERE table_catalog IN {in_clause} AND table_schema != 'information_schema'",

        f"SELECT 'VOLUME' AS securable_type, "
        f"concat(volume_catalog, '.', volume_schema, '.', volume_name) AS full_name, "
        f"volume_owner AS owner, NULL AS parameters, NULL AS routine_definition "
        f"FROM system.information_schema.volumes "
        f"WHERE volume_catalog IN {in_clause} AND volume_schema != 'information_schema'",

        f"SELECT 'FUNCTION' AS securable_type, "
        f"concat(r.specific_catalog, '.', r.specific_schema, '.', r.specific_name) AS full_name, "
        f"r.routine_owner AS owner, "
        f"to_json(transform(sort_array(collect_list(struct(p.ordinal_position, p.parameter_name, p.data_type))), x -> struct(x.parameter_name, x.data_type))) AS parameters, "
        f"r.routine_definition AS routine_definition "
        f"FROM system.information_schema.routines r "
        f"LEFT JOIN system.information_schema.parameters p "
        f"ON r.specific_catalog = p.specific_catalog "
        f"AND r.specific_schema = p.specific_schema "
        f"AND r.specific_name = p.specific_name "
        f"WHERE r.specific_catalog IN {in_clause} AND r.routine_type = 'FUNCTION' AND r.specific_schema != 'information_schema' "
        f"GROUP BY r.specific_catalog, r.specific_schema, r.specific_name, r.routine_owner, r.routine_definition",
    ]
    return " UNION ALL ".join(parts)


def _parse_securable_rows(
    rows: list[list[str]],
) -> tuple[set[SecurableInfo], set[SecurableAttributes]]:
    """Parse raw SQL rows into securables and attributes.

    Row columns: [securable_type, full_name, owner, parameters_json, routine_definition]
    """
    securables: set[SecurableInfo] = set()
    attributes: set[SecurableAttributes] = set()
    for row in rows:
        securable_type = SecurableType(row[0])
        full_name = row[1]
        owner = row[2]
        parameters_json = row[3]
        routine_definition = row[4]

        owner_principal = (
            Principal(principal_type=PrincipalType.UNKNOWN, identifier=owner)
            if owner else None
        )
        attributes.add(
            SecurableAttributes(
                securable_type=securable_type,
                full_name=full_name,
                owner=owner_principal,
            )
        )

        if securable_type == SecurableType.FUNCTION:
            if parameters_json:
                parsed_params = json.loads(parameters_json)
                params = tuple(
                    (p["parameter_name"], p["data_type"]) for p in parsed_params
                )
            else:
                params = ()
            securables.add(
                FunctionInfo(
                    securable_type=SecurableType.FUNCTION,
                    full_name=full_name,
                    parameters=params,
                    definition=routine_definition,
                )
            )

    return securables, attributes


def _collect_policy_securables(
    config: ResourcesConfig,
) -> set[tuple[SecurableType, str]]:
    """Return the set of securables that have at least one mask/filter policy."""
    result: set[tuple[SecurableType, str]] = set()
    for catalog in config.catalogs.values():
        if _has_fgac_policy(catalog.policies):
            result.add((SecurableType.CATALOG, catalog.full_name))
        for schema in catalog.schemas or []:
            if _has_fgac_policy(schema.policies):
                result.add((SecurableType.SCHEMA, schema.full_name))
            for table in schema.tables or []:
                if _has_fgac_policy(table.policies):
                    result.add((SecurableType.TABLE, table.full_name))
    return result


def _has_fgac_policy(policies) -> bool:
    if not policies:
        return False
    return any(isinstance(p, BaseFgacPolicyConfig) for p in policies)


def _normalise_policy_info(
    info: PolicyInfo,
    securable_type: SecurableType,
    securable_full_name: str,
) -> Policy | None:
    """Convert an SDK PolicyInfo to a Policy. Returns None for unsupported types."""
    sdk_type = getattr(info.policy_type, "value", info.policy_type)
    if sdk_type == SdkPolicyType.POLICY_TYPE_COLUMN_MASK.value:
        policy_type = PolicyType.MASK
        function_name = info.column_mask.function_name
        on_column = info.column_mask.on_column
        using_columns = _extract_using_columns(info.column_mask.using)
    elif sdk_type == SdkPolicyType.POLICY_TYPE_ROW_FILTER.value:
        policy_type = PolicyType.FILTER
        function_name = info.row_filter.function_name
        on_column = None
        using_columns = _extract_using_columns(info.row_filter.using)
    else:
        return None

    to_principals = tuple(
        Principal(principal_type=PrincipalType.UNKNOWN, identifier=p)
        for p in (info.to_principals or [])
    )
    except_principals = tuple(
        Principal(principal_type=PrincipalType.UNKNOWN, identifier=p)
        for p in (info.except_principals or [])
    )
    match_columns = tuple(
        (mc.alias, mc.condition) for mc in (info.match_columns or [])
    )
    return Policy(
        securable_type=securable_type,
        securable_full_name=securable_full_name,
        name=info.name,
        policy_type=policy_type,
        function_name=function_name,
        to_principals=to_principals,
        except_principals=except_principals,
        when_condition=info.when_condition,
        match_columns=match_columns,
        on_column=on_column,
        using_columns=using_columns,
    )


def _extract_using_columns(using) -> tuple[str, ...]:
    if not using:
        return ()
    return tuple(arg.column for arg in using if arg.column is not None)


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
        self._securables_cache: set[SecurableInfo] | None = None
        self._attributes_cache: set[SecurableAttributes] | None = None
        self._policies_cache: set[Policy] | None = None

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
            raise GovernorError(f"SQL query failed ({response.status.state}): {error_msg}\nStatement: {statement}")

        return response

    def fetch_actual_tags(self, catalog_names: list[str]) -> set[SecurableTag]:
        """Query system tables for all tags on securables in the given catalogs.

        Results are cached after the first call.
        """
        if self._tags_cache is not None:
            return self._tags_cache

        if not catalog_names:
            self._tags_cache = set()
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

        if not catalog_names:
            self._privileges_cache = set()
            return self._privileges_cache

        response = self._execute_and_poll(_build_privileges_query(catalog_names))
        rows = _fetch_external_links_rows(response)
        self._privileges_cache = _parse_privilege_rows(rows)
        return self._privileges_cache

    def fetch_actual_securables(
        self, catalog_names: list[str]
    ) -> tuple[set[SecurableInfo], set[SecurableAttributes]]:
        """Query system tables for securable attributes and function definitions.

        Returns a tuple of (securables, attributes) for the given catalogs.
        Results are cached after the first call.
        """
        if self._securables_cache is not None and self._attributes_cache is not None:
            return self._securables_cache, self._attributes_cache

        if not catalog_names:
            self._securables_cache = set()
            self._attributes_cache = set()
            return self._securables_cache, self._attributes_cache

        response = self._execute_and_poll(_build_securables_query(catalog_names))
        rows = _fetch_external_links_rows(response)
        self._securables_cache, self._attributes_cache = _parse_securable_rows(rows)
        return self._securables_cache, self._attributes_cache

    def update_owner(
        self, securable_type: SecurableType, full_name: str, new_owner: str
    ) -> None:
        """Update the owner of a securable via the WorkspaceClient API."""
        match securable_type:
            case SecurableType.CATALOG:
                self._client.catalogs.update(full_name, owner=new_owner)
            case SecurableType.SCHEMA:
                self._client.schemas.update(full_name, owner=new_owner)
            case SecurableType.TABLE:
                self._client.tables.update(full_name, owner=new_owner)
            case SecurableType.VOLUME:
                self._client.volumes.update(full_name, owner=new_owner)
            case SecurableType.FUNCTION:
                self._client.functions.update(full_name, owner=new_owner)

    def fetch_actual_policies(self, config: ResourcesConfig) -> set[Policy]:
        """Return mask/filter policies attached to any configured securable.

        Walks the config to find every catalog/schema/table that declares at
        least one mask or filter policy, then fans out one list_policies SDK
        call per securable via a thread pool (max 32 concurrent). Results
        from the SDK are normalised into Policy instances. Policies of
        non-mask/filter types are skipped.

        Results are cached after the first call.
        """
        if self._policies_cache is not None:
            return self._policies_cache

        securables = _collect_policy_securables(config)
        if not securables:
            self._policies_cache = set()
            return self._policies_cache

        result: set[Policy] = set()
        with ThreadPoolExecutor(max_workers=_MAX_POLICY_LIST_WORKERS) as pool:
            futures = {
                pool.submit(self._list_policies, sec_type, full_name): (sec_type, full_name)
                for sec_type, full_name in securables
            }
            for future in as_completed(futures):
                result |= future.result()

        self._policies_cache = result
        return self._policies_cache

    def _list_policies(
        self, securable_type: SecurableType, full_name: str
    ) -> set[Policy]:
        infos = self._client.policies.list_policies(
            on_securable_type=securable_type.value,
            on_securable_fullname=full_name,
            include_inherited=False,
        )
        result: set[Policy] = set()
        for info in infos:
            normalised = _normalise_policy_info(info, securable_type, full_name)
            if normalised is not None:
                result.add(normalised)
        return result

    def execute_sql(self, statement: str) -> None:
        """Execute a SQL statement via the Statement Execution API."""
        self._execute_and_poll(statement)
