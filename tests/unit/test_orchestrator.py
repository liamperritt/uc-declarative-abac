from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from uc_declarative_abac.orchestrator import run
from uc_declarative_abac.utils import ExecutionBatchError, PrincipalValidationError, UngovernedTagError
from uc_declarative_abac.policies.state import Policy, PolicyDiff
from uc_declarative_abac.privileges.state import PrivilegeDiff
from uc_declarative_abac.tags.state import TagDiff
from uc_declarative_abac.types import PolicyType, SecurableType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_group(display_name: str) -> MagicMock:
    """Create a mock group object with a display_name attribute."""
    group = MagicMock()
    group.display_name = display_name
    return group


def _catalog_with_tags_config() -> dict:
    """A minimal YAML dict: one catalog with tags on catalog and a schema."""
    return {
        "resources": {
            "catalogs": {
                "my_catalog": {
                    "tags": {"env": "prod"},
                    "schemas": [
                        {"name": "sales", "tags": {"team": "data"}},
                    ],
                }
            }
        }
    }


def _catalog_with_grant_policy_config() -> dict:
    """A YAML dict with a grant policy that matches on a tag."""
    return {
        "resources": {
            "governed_tags": {
                "team": {"allowed_values": ["data"]},
                "env": {"allowed_values": ["prod"]},
            },
            "catalogs": {
                "my_catalog": {
                    "tags": {"env": "prod"},
                    "schemas": [
                        {"name": "sales", "tags": {"team": "data"}},
                    ],
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["data_engineers"],
                            "has_tags": {"team": "data"},
                        },
                    ],
                }
            }
        }
    }


def _catalog_with_tags_and_grants_config() -> dict:
    """A YAML dict that exercises both tags and privilege workflows."""
    return {
        "resources": {
            "governed_tags": {
                "team": {"allowed_values": ["data"]},
                "env": {"allowed_values": ["prod"]},
            },
            "catalogs": {
                "my_catalog": {
                    "tags": {"env": "prod"},
                    "schemas": [
                        {"name": "sales", "tags": {"team": "data"}},
                    ],
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["data_engineers"],
                            "has_tags": {"team": "data"},
                        },
                    ],
                }
            }
        }
    }


def _run_all_enabled(**kwargs):
    """Shorthand that passes every ``enable_*`` flag as True plus ``force=True`` so
    governed-tag deletion (if any) doesn't prompt. Preserves pre-flag test intent for
    tests that exercise the full reconciliation pipeline. New skip-path / gate tests
    call ``run(...)`` directly to verify default-off behaviour."""
    defaults = {
        "enable_tag_management": True,
        "enable_taggable_management": True,
        "enable_taggable_creation": True,
        "enable_privilege_management": True,
        "enable_governed_tag_deletion": True,
        "force": True,
    }
    defaults.update(kwargs)
    return run(**defaults)


def _setup_mock_workspace_empty_state(mock_workspace_client: MagicMock) -> None:
    """Configure the mock workspace client to return empty actual state.

    Each returned response carries ``._sql`` (the executed statement) so that a
    monkeypatched ``_fetch_external_links_rows`` can route by SQL content.
    """
    from databricks.sdk.service.sql import StatementState

    def _capture_and_return(*args, **kwargs):
        statement = kwargs.get("statement", args[0] if args else None)
        if statement:
            mock_workspace_client.executed_sql.append(statement)
        response = MagicMock()
        response.status.state = StatementState.SUCCEEDED
        response.result.data_array = []
        response.result.external_links = []
        response._sql = statement
        return response

    mock_workspace_client.statement_execution.execute_statement.side_effect = (
        _capture_and_return
    )


def _securable_existence_rows(config_dict: dict) -> list[list]:
    """Build securables-fetch rows matching every catalog/schema/table/volume declared
    in a resources-config dict, *after consolidation* (so consolidator-auto-created
    schemas like ``default`` are included). Row format matches fetch_actual_securables:
    ``[securable_type, full_name, owner, parameters_json, routine_definition, routine_comment]``.
    """
    import copy

    from uc_declarative_abac.configs.consolidator import consolidate_resources

    resources = copy.deepcopy(config_dict.get("resources") or {})
    consolidated = consolidate_resources(resources)
    catalogs = consolidated.get("catalogs") or {}

    rows: list[list] = []
    for cat_key, cat in catalogs.items():
        cat_data = cat if isinstance(cat, dict) else {}
        cat_name = cat_data.get("name", cat_key)
        rows.append(["CATALOG", cat_name, None, None, None, None])
        for schema in cat_data.get("schemas") or []:
            if not isinstance(schema, dict):
                continue
            schema_name = schema.get("name")
            if not schema_name:
                continue
            schema_full = f"{cat_name}.{schema_name}"
            rows.append(["SCHEMA", schema_full, None, None, None, None])
            for table in schema.get("tables") or []:
                if isinstance(table, dict) and table.get("name"):
                    rows.append(["TABLE", f"{schema_full}.{table['name']}", None, None, None, None])
            for vol in schema.get("volumes") or []:
                if isinstance(vol, dict) and vol.get("name"):
                    rows.append(["VOLUME", f"{schema_full}.{vol['name']}", None, None, None, None])
    return rows


def _install_fetch_router(
    monkeypatch,
    config_dict: dict,
    tag_rows: list[list] | None = None,
    privilege_rows: list[list] | None = None,
) -> None:
    """Monkeypatch ``_fetch_external_links_rows`` so it routes by the executed SQL:

    - securables query -> existence rows for every declared catalog/schema/table/volume
      in ``config_dict`` (so the differ's nonexistent-securable check passes),
    - tags query -> ``tag_rows`` or ``[]``,
    - privileges query -> ``privilege_rows`` or ``[]``,
    - anything else -> ``[]``.

    Assumes each response returned by execute_statement carries ``._sql`` — set by
    ``_setup_mock_workspace_empty_state`` and its cousins.
    """
    sec_rows = _securable_existence_rows(config_dict)

    def _route(response):
        sql = (getattr(response, "_sql", "") or "").lower()
        if "catalog_owner" in sql or "schema_owner" in sql or "routine_owner" in sql:
            return sec_rows
        if any(t in sql for t in ("catalog_tags", "schema_tags", "table_tags", "volume_tags", "column_tags")):
            return tag_rows or []
        if "_privileges" in sql:
            return privilege_rows or []
        return []

    monkeypatch.setattr(
        "uc_declarative_abac.helpers.unity_catalog._fetch_external_links_rows",
        _route,
    )


def _setup_mock_principals(
    mock_workspace_client: MagicMock, group_name: str
) -> None:
    """Configure the mock workspace client's account SCIM proxy to return a single group."""
    original_do = mock_workspace_client.api_client.do.side_effect

    def _scim_do(method, path, **kwargs):
        if "/account/scim/v2/Groups" in path:
            return {"totalResults": 1, "startIndex": 1, "itemsPerPage": 100, "Resources": [{"displayName": group_name}]}
        if "/account/scim/v2/Users" in path:
            return {"totalResults": 0, "startIndex": 1, "itemsPerPage": 100, "Resources": []}
        if "/account/scim/v2/ServicePrincipals" in path:
            return {"totalResults": 0, "startIndex": 1, "itemsPerPage": 100, "Resources": []}
        return {}

    mock_workspace_client.api_client.do.side_effect = _scim_do


def _setup_mock_empty_principals(mock_workspace_client: MagicMock) -> None:
    """Configure the mock workspace client's account SCIM proxy to return no principals."""
    def _scim_do(method, path, **kwargs):
        return {"totalResults": 0, "startIndex": 1, "itemsPerPage": 100, "Resources": []}
    mock_workspace_client.api_client.do.side_effect = _scim_do


def _setup_mock_principals_with_groups(
    mock_workspace_client: MagicMock, group_names: list[str]
) -> None:
    """Configure the mock account SCIM proxy to return specific groups and no users/SPs."""
    def _scim_do(method, path, **kwargs):
        if "/account/scim/v2/Groups" in path:
            resources = [{"displayName": name} for name in group_names]
            return {"totalResults": len(resources), "startIndex": 1, "itemsPerPage": 100, "Resources": resources}
        return {"totalResults": 0, "startIndex": 1, "itemsPerPage": 100, "Resources": []}
    mock_workspace_client.api_client.do.side_effect = _scim_do


# ---------------------------------------------------------------------------
# End-to-end workflows
# ---------------------------------------------------------------------------


def test_orchestrator_runs_tags_workflow_end_to_end(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """YAML configs with tagged catalog -> tag_diff.to_add is non-empty, SQL was executed."""
    config = _catalog_with_tags_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    result = _run_all_enabled(
        config_dir=root,
        workspace_client=mock_workspace_client,

        warehouse_id="test-warehouse-id",
    )

    assert isinstance(result.tag_diff, TagDiff)
    assert len(result.tag_diff.to_add) > 0, "Expected tags to be added for the tagged catalog"

    executed = mock_workspace_client.executed_sql
    set_tags_stmts = [s for s in executed if "SET TAGS" in s.upper()]
    assert len(set_tags_stmts) > 0, (
        f"Expected SET TAGS SQL to be executed, got: {executed}"
    )


def test_orchestrator_runs_privileges_workflow_end_to_end(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """YAML with grant policy + tagged objects, empty actual privileges -> privilege_diff.to_grant is non-empty."""
    config = _catalog_with_grant_policy_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    result = _run_all_enabled(
        config_dir=root,
        workspace_client=mock_workspace_client,

        warehouse_id="test-warehouse-id",
    )

    assert isinstance(result.privilege_diff, PrivilegeDiff)
    assert len(result.privilege_diff.to_grant) > 0, (
        "Expected privileges to be granted for the grant policy"
    )

    executed = mock_workspace_client.executed_sql
    grant_stmts = [s for s in executed if s.upper().startswith("GRANT")]
    assert len(grant_stmts) > 0, (
        f"Expected GRANT SQL to be executed, got: {executed}"
    )


def test_orchestrator_runs_both_domains_independently(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """Both tag and privilege changes are computed; verify both diffs are populated."""
    config = _catalog_with_tags_and_grants_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    result = _run_all_enabled(
        config_dir=root,
        workspace_client=mock_workspace_client,

        warehouse_id="test-warehouse-id",
    )

    assert len(result.tag_diff.to_add) >= 2, (
        f"Expected at least 2 tags to add, got {len(result.tag_diff.to_add)}: {result.tag_diff.to_add}"
    )
    assert len(result.privilege_diff.to_grant) >= 1, (
        f"Expected at least 1 privilege to grant, got {len(result.privilege_diff.to_grant)}: "
        f"{result.privilege_diff.to_grant}"
    )

    executed = mock_workspace_client.executed_sql
    assert any("SET TAGS" in s.upper() for s in executed), (
        "Expected SET TAGS SQL to be executed"
    )
    assert any(s.upper().startswith("GRANT") for s in executed), (
        "Expected GRANT SQL to be executed"
    )


# ---------------------------------------------------------------------------
# Idempotency and state sync
# ---------------------------------------------------------------------------


@patch("uc_declarative_abac.helpers.unity_catalog._fetch_external_links_rows")
def test_orchestrator_produces_empty_diffs_when_in_sync(
    mock_fetch, tmp_yaml_dir, mock_workspace_client):
    """When actual state matches desired, both diffs are empty and no SQL is executed."""
    config = _catalog_with_grant_policy_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})

    actual_tags = [
        ["CATALOG", "my_catalog", '[{"tag_name":"env","tag_value":"prod"}]'],
        ["SCHEMA", "my_catalog.sales", '[{"tag_name":"team","tag_value":"data"}]'],
    ]
    actual_privileges = [
        ["SCHEMA", "my_catalog.sales", "data_engineers", "select"],
    ]
    actual_securables = _securable_existence_rows(config)

    def _route_rows_by_sql(response):
        sql = (getattr(response, "_sql", "") or "").lower()
        if "catalog_owner" in sql or "schema_owner" in sql or "routine_owner" in sql:
            return actual_securables
        if "tag" in sql:
            return actual_tags
        if "privilege" in sql:
            return actual_privileges
        return []

    mock_fetch.side_effect = _route_rows_by_sql

    # Store the SQL on each response so _route_rows_by_sql can identify the query
    from databricks.sdk.service.sql import StatementState

    def _execute_with_sql_tag(*args, **kwargs):
        statement = kwargs.get("statement", args[0] if args else None)
        if statement:
            mock_workspace_client.executed_sql.append(statement)
        response = MagicMock()
        response.status.state = StatementState.SUCCEEDED
        response.result.external_links = []
        response._sql = statement
        return response

    mock_workspace_client.statement_execution.execute_statement.side_effect = (
        _execute_with_sql_tag
    )
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    result = _run_all_enabled(
        config_dir=root,
        workspace_client=mock_workspace_client,

        warehouse_id="test-warehouse-id",
    )

    assert result.tag_diff.to_add == set()
    assert result.tag_diff.to_update == set()
    assert result.tag_diff.to_remove == set()
    assert result.privilege_diff.to_grant == set()
    assert result.privilege_diff.to_revoke == set()

    mutation_stmts = [
        s
        for s in mock_workspace_client.executed_sql
        if any(kw in s.upper() for kw in ["ALTER", "GRANT ", "REVOKE"])
    ]
    assert mutation_stmts == [], (
        f"Expected no mutation SQL when in sync, got: {mutation_stmts}"
    )


# ---------------------------------------------------------------------------
# Validation and safety
# ---------------------------------------------------------------------------


def test_orchestrator_validates_principals_before_applying(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """Policy references unknown principal -> ExecutionBatchError, no GRANT/REVOKE SQL executed."""
    config = _catalog_with_grant_policy_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_empty_principals(mock_workspace_client)

    with pytest.raises(ExecutionBatchError):
        _run_all_enabled(
            config_dir=root,
            workspace_client=mock_workspace_client,

            warehouse_id="test-warehouse-id",
        )

    grant_revoke = [
        s
        for s in mock_workspace_client.executed_sql
        if s.upper().startswith("GRANT") or s.upper().startswith("REVOKE")
    ]
    assert grant_revoke == [], (
        f"Expected no GRANT/REVOKE SQL when principal validation fails, got: {grant_revoke}"
    )


def test_orchestrator_dry_run_does_not_execute_sql(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """dry_run=True -> diffs are computed but no mutation SQL is executed."""
    config = _catalog_with_tags_and_grants_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    result = _run_all_enabled(
        config_dir=root,
        workspace_client=mock_workspace_client,

        warehouse_id="test-warehouse-id",
        dry_run=True,
    )

    assert isinstance(result.tag_diff, TagDiff)
    assert isinstance(result.privilege_diff, PrivilegeDiff)

    mutation_stmts = [
        s
        for s in mock_workspace_client.executed_sql
        if any(kw in s.upper() for kw in ["ALTER", "GRANT ", "REVOKE"])
    ]
    assert mutation_stmts == [], (
        f"Expected no mutation SQL in dry-run mode, got: {mutation_stmts}"
    )


# ---------------------------------------------------------------------------
# Parallelism
# ---------------------------------------------------------------------------


def test_orchestrator_fetches_tags_privileges_and_principals_in_parallel(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """Mock delays on fetch methods; total elapsed < sum of delays proves parallelism."""
    config = _catalog_with_tags_and_grants_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})

    delay_seconds = 0.3
    total_sequential_time = delay_seconds * 3

    def _slow_execute(*args, **kwargs):
        from databricks.sdk.service.sql import StatementState

        statement = kwargs.get("statement", args[0] if args else None)
        if statement and statement.strip().upper().startswith("SELECT"):
            time.sleep(delay_seconds)
        if statement:
            mock_workspace_client.executed_sql.append(statement)
        result = MagicMock()
        result.status.state = StatementState.SUCCEEDED
        result.result.data_array = []
        result.result.external_links = []
        result._sql = statement
        return result

    mock_workspace_client.statement_execution.execute_statement.side_effect = (
        _slow_execute
    )
    _install_fetch_router(monkeypatch, config)

    def _slow_scim_do(method, path, **kwargs):
        if "/account/scim/v2/Groups" in path:
            time.sleep(delay_seconds)
            return {"totalResults": 1, "startIndex": 1, "itemsPerPage": 100, "Resources": [{"displayName": "data_engineers"}]}
        return {"totalResults": 0, "startIndex": 1, "itemsPerPage": 100, "Resources": []}

    mock_workspace_client.api_client.do.side_effect = _slow_scim_do

    start = time.monotonic()
    _run_all_enabled(
        config_dir=root,
        workspace_client=mock_workspace_client,

        warehouse_id="test-warehouse-id",
    )
    elapsed = time.monotonic() - start

    assert elapsed < total_sequential_time, (
        f"Fetches appear to be sequential: elapsed {elapsed:.2f}s >= "
        f"total sequential time {total_sequential_time:.2f}s"
    )


# ---------------------------------------------------------------------------
# Error collection
# ---------------------------------------------------------------------------


def test_orchestrator_raises_execution_batch_error_when_sql_fails(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """When mutation SQL fails, orchestrator.run() raises ExecutionBatchError with collected errors."""
    from uc_declarative_abac.utils import ExecutionBatchError
    config = _catalog_with_tags_and_grants_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})

    def _fail_mutations(*args, **kwargs):
        from databricks.sdk.service.sql import StatementState

        statement = kwargs.get("statement", args[0] if args else None)
        if statement:
            mock_workspace_client.executed_sql.append(statement)
        upper = (statement or "").upper().strip()
        # Mutation statements should fail
        if upper.startswith(("ALTER", "GRANT", "REVOKE")):
            raise RuntimeError("SQL execution failed")
        # State fetch queries succeed with empty results
        result = MagicMock()
        result.status.state = StatementState.SUCCEEDED
        result.result.data_array = []
        result.result.external_links = []
        result._sql = statement
        return result

    mock_workspace_client.statement_execution.execute_statement.side_effect = (
        _fail_mutations
    )
    _install_fetch_router(monkeypatch, config)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    with pytest.raises(ExecutionBatchError) as exc_info:
        _run_all_enabled(
            config_dir=root,
            workspace_client=mock_workspace_client,

            warehouse_id="test-warehouse-id",
        )

    assert len(exc_info.value.errors) > 0, (
        "Expected at least one ExecutionError in the batch"
    )


# ---------------------------------------------------------------------------
# Principal validation error collection
# ---------------------------------------------------------------------------


def _catalog_with_two_grant_policies_config() -> dict:
    return {
        "resources": {
            "governed_tags": {
                "team": {"allowed_values": ["data"]},
                "env": {"allowed_values": ["prod"]},
            },
            "catalogs": {
                "my_catalog": {
                    "tags": {"env": "prod"},
                    "schemas": [
                        {"name": "sales", "tags": {"team": "data"}},
                    ],
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["data_engineers"],
                            "has_tags": {"team": "data"},
                        },
                        {
                            "type": "grant",
                            "privileges": ["modify"],
                            "to": ["ghost_team"],
                            "has_tags": {"team": "data"},
                        },
                    ],
                }
            }
        }
    }


def _catalog_with_mask_policy_config() -> dict:
    """A YAML dict with a catalog-level MASK policy targeting a tagged column."""
    return {
        "resources": {
            "governed_tags": {
                "pii": {"allowed_values": ["email"]},
            },
            "catalogs": {
                "my_catalog": {
                    "policies": [
                        {
                            "name": "mask_pii",
                            "type": "mask",
                            "function": "my_catalog.default.mask_fn",
                            "to": ["analysts"],
                            "except": ["admins"],
                            "columns": [
                                {"alias": "c_pii", "has_tags": {"pii": "email"}}
                            ],
                        }
                    ],
                }
            }
        }
    }


# ---------------------------------------------------------------------------
# Policies workflow
# ---------------------------------------------------------------------------


def test_orchestrator_runs_policies_workflow_end_to_end(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """A MASK policy with no corresponding actual UC policy -> CREATE POLICY SQL is executed."""
    config = _catalog_with_mask_policy_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_principals_with_groups(mock_workspace_client, ["analysts", "admins"])

    result = _run_all_enabled(
        config_dir=root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
    )

    assert isinstance(result.policy_diff, PolicyDiff)
    assert len(result.policy_diff.to_create) == 1
    create_stmts = [s for s in mock_workspace_client.executed_sql if "CREATE POLICY" in s.upper()]
    assert len(create_stmts) == 1, f"Expected CREATE POLICY SQL, got: {mock_workspace_client.executed_sql}"


def test_orchestrator_policies_workflow_is_idempotent(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """When list_policies returns the same policy already exists, no CREATE POLICY SQL is executed."""
    config = _catalog_with_mask_policy_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_principals_with_groups(mock_workspace_client, ["analysts", "admins"])

    # Configure list_policies to return the matching desired policy
    from databricks.sdk.service.catalog import PolicyType as SdkPolicyType

    fake_policy = MagicMock()
    fake_policy.name = "mask_pii"
    fake_policy.on_securable_type = MagicMock(value="CATALOG")
    fake_policy.on_securable_fullname = "my_catalog"
    fake_policy.policy_type = SdkPolicyType.POLICY_TYPE_COLUMN_MASK
    fake_policy.column_mask = MagicMock()
    fake_policy.column_mask.function_name = "my_catalog.default.mask_fn"
    fake_policy.column_mask.on_column = "c_pii"
    fake_policy.column_mask.using = []
    fake_policy.row_filter = None
    fake_policy.to_principals = ["analysts"]
    fake_policy.except_principals = ["admins"]
    fake_policy.when_condition = None
    fake_policy.match_columns = [MagicMock(alias="c_pii", condition="has_tag_value('pii', 'email')")]
    fake_policy.comment = None
    mock_workspace_client.policies.list_policies.return_value = iter([fake_policy])

    result = _run_all_enabled(
        config_dir=root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
    )

    assert result.policy_diff.to_create == set()
    assert result.policy_diff.to_replace == set()
    create_stmts = [s for s in mock_workspace_client.executed_sql if "CREATE POLICY" in s.upper()]
    assert create_stmts == []


# ---------------------------------------------------------------------------
# Service principal display-name ↔ application_id idempotency
# ---------------------------------------------------------------------------


def _setup_mock_principals_with_sp(
    mock_workspace_client: MagicMock,
    sp_display_name: str,
    sp_application_id: str,
) -> None:
    """Configure the mock account SCIM proxy to return a single service principal."""
    def _scim_do(method, path, **kwargs):
        if "/account/scim/v2/ServicePrincipals" in path:
            return {
                "totalResults": 1,
                "startIndex": 1,
                "itemsPerPage": 100,
                "Resources": [{
                    "displayName": sp_display_name,
                    "applicationId": sp_application_id,
                }],
            }
        return {"totalResults": 0, "startIndex": 1, "itemsPerPage": 100, "Resources": []}
    mock_workspace_client.api_client.do.side_effect = _scim_do


def test_orchestrator_is_idempotent_for_service_principal_across_display_name_and_app_id():
    """Same workspace principal referenced by display_name in YAML and application_id in UC
    state (GRANT system tables, list_policies SDK response) should produce an empty diff on
    the second run — proving that PrincipalResolver bridges the two representations correctly."""
    sp_display = "sp_sales_runner"
    sp_app_id = "abc-1234-app-id"

    # YAML: one grant policy + one mask policy, both referencing the SP by display name
    config = {
        "resources": {
            "governed_tags": {
                "team": {"allowed_values": ["sales"]},
                "pii": {"allowed_values": ["email"]},
            },
            "catalogs": {
                "my_catalog": {
                    "tags": {"team": "sales"},
                    "policies": [
                        {
                            "name": "grant_sales_select",
                            "type": "grant",
                            "privileges": ["select"],
                            "to": [sp_display],
                            "has_tags": {"team": "sales"},
                        },
                        {
                            "name": "mask_sales_pii",
                            "type": "mask",
                            "function": "my_catalog.default.mask_fn",
                            "to": [sp_display],
                            "except": [],
                            "columns": [{"alias": "c_pii", "has_tags": {"pii": "email"}}],
                        },
                    ],
                }
            }
        }
    }

    mock_workspace_client = _new_mock_client()
    tmp_root = _tmp_yaml_root(config)

    # Mock SCIM: the SP exists; app_id is the identifier UC uses in system tables.
    _setup_mock_principals_with_sp(mock_workspace_client, sp_display, sp_app_id)

    # Mock UC state: grant to sp by app_id on the tagged catalog + a matching column mask.
    # Seed: catalog tag {team: sales}, privilege GRANT SELECT ON CATALOG my_catalog to app_id,
    # and list_policies returns the matching mask policy with app_id in to_principals.
    _seed_actual_state_for_sp_idempotency(mock_workspace_client, sp_app_id)

    # Run and assert empty diffs
    result = _run_all_enabled(
        config_dir=tmp_root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
    )

    assert result.tag_diff.to_add == set(), f"Expected no tag changes, got to_add: {result.tag_diff.to_add}"
    assert result.tag_diff.to_update == set()
    assert result.tag_diff.to_remove == set()
    assert result.privilege_diff.to_grant == set(), f"Expected no grants, got: {result.privilege_diff.to_grant}"
    assert result.privilege_diff.to_revoke == set(), f"Expected no revokes, got: {result.privilege_diff.to_revoke}"
    assert result.policy_diff.to_create == set(), f"Expected no policy creates, got: {result.policy_diff.to_create}"
    assert result.policy_diff.to_replace == set(), f"Expected no policy replaces, got: {result.policy_diff.to_replace}"

    # No mutation SQL executed
    mutation_stmts = [
        s for s in mock_workspace_client.executed_sql
        if any(kw in s.upper() for kw in ["ALTER", "GRANT ", "REVOKE", "CREATE POLICY"])
    ]
    assert mutation_stmts == [], f"Expected no mutation SQL on second run, got: {mutation_stmts}"


def _new_mock_client() -> MagicMock:
    """Construct a fresh MagicMock workspace client with the baseline wiring
    used by conftest.mock_workspace_client (empty SQL results + empty policies)."""
    from databricks.sdk.service.sql import StatementState
    client = MagicMock()
    client.executed_sql = []
    client.policies.list_policies.return_value = iter([])

    def _capture_sql(*args, **kwargs):
        statement = kwargs.get("statement", args[0] if args else None)
        if statement:
            client.executed_sql.append(statement)
        response = MagicMock()
        response.status.state = StatementState.SUCCEEDED
        return response

    client.statement_execution.execute_statement.side_effect = _capture_sql
    return client


def _tmp_yaml_root(config: dict) -> "pathlib.Path":
    """Write the single-file config to a fresh tmp dir and return the dir path."""
    import pathlib
    import tempfile
    import yaml
    root = pathlib.Path(tempfile.mkdtemp())
    (root / "resources").mkdir()
    (root / "resources" / "catalog.yaml").write_text(yaml.dump(config))
    return root


def _seed_actual_state_for_sp_idempotency(mock_workspace_client: MagicMock, sp_app_id: str) -> None:
    """Seed tags, grants, and policies system-table/SDK responses so that actual ==
    desired for the SP test. The catalog has tag {team: sales}; a GRANT SELECT is
    present for the SP (app_id) on the catalog; a mask policy matches desired fields."""
    from databricks.sdk.service.catalog import PolicyType as SdkPolicyType
    from databricks.sdk.service.sql import StatementState

    # _fetch_external_links_rows is called per-query; route by SQL content.
    def _rows_for_sql(sql: str) -> list[list[str]]:
        lower = sql.lower()
        # Securables query — return rows for the declared catalog (plus the default
        # schema auto-created by the consolidator because the catalog has catalog-
        # level policies) so the nonexistent-securable check in the differ passes.
        if "catalog_owner" in lower or "schema_owner" in lower or "routine_owner" in lower:
            return [
                ["CATALOG", "my_catalog", None, None, None, None],
                ["SCHEMA", "my_catalog.default", None, None, None, None],
            ]
        # Tags query (aggregated: one row per securable, tags as JSON array)
        if "catalog_tags" in lower or "schema_tags" in lower:
            return [["CATALOG", "my_catalog", '[{"tag_name":"team","tag_value":"sales"}]']]
        # Privileges query
        if "catalog_privileges" in lower or "schema_privileges" in lower:
            return [["CATALOG", "my_catalog", sp_app_id, "SELECT"]]
        return []

    def _execute_with_sql_tag(*args, **kwargs):
        statement = kwargs.get("statement", args[0] if args else None)
        if statement:
            mock_workspace_client.executed_sql.append(statement)
        response = MagicMock()
        response.status.state = StatementState.SUCCEEDED
        response.result.external_links = []
        response._sql = statement
        return response

    mock_workspace_client.statement_execution.execute_statement.side_effect = _execute_with_sql_tag

    # Patch _fetch_external_links_rows at test scope
    import unittest.mock as _mock
    patcher = _mock.patch(
        "uc_declarative_abac.helpers.unity_catalog._fetch_external_links_rows",
        side_effect=lambda response: _rows_for_sql(getattr(response, "_sql", "") or ""),
    )
    patcher.start()

    # Actual mask policy (list_policies SDK response) — identifier is the SP app_id
    fake_policy = MagicMock()
    fake_policy.name = "mask_sales_pii"
    fake_policy.on_securable_type = MagicMock(value="CATALOG")
    fake_policy.on_securable_fullname = "my_catalog"
    fake_policy.policy_type = SdkPolicyType.POLICY_TYPE_COLUMN_MASK
    fake_policy.column_mask = MagicMock()
    fake_policy.column_mask.function_name = "my_catalog.default.mask_fn"
    fake_policy.column_mask.on_column = "c_pii"
    fake_policy.column_mask.using = []
    fake_policy.row_filter = None
    fake_policy.to_principals = [sp_app_id]
    fake_policy.except_principals = []
    fake_policy.when_condition = None
    fake_policy.match_columns = [MagicMock(alias="c_pii", condition="has_tag_value('pii', 'email')")]
    fake_policy.comment = None
    mock_workspace_client.policies.list_policies.return_value = iter([fake_policy])


def test_orchestrator_collects_unknown_principal_errors(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """Unknown principals are collected as errors in ExecutionBatchError, not raised as PrincipalValidationError."""
    from uc_declarative_abac.utils import ExecutionBatchError, ExecutionError
    config = _catalog_with_grant_policy_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_empty_principals(mock_workspace_client)

    with pytest.raises(ExecutionBatchError) as exc_info:
        _run_all_enabled(
            config_dir=root,
            workspace_client=mock_workspace_client,

            warehouse_id="test-warehouse-id",
        )

    # At least one error should be a PrincipalValidationError
    principal_errors = [
        e for e in exc_info.value.errors
        if isinstance(e.exception, PrincipalValidationError)
    ]
    assert len(principal_errors) > 0, (
        f"Expected at least one PrincipalValidationError in errors, got: {exc_info.value.errors}"
    )


def test_orchestrator_continues_with_valid_principals_when_some_are_unknown(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """Valid principals get GRANT SQL executed; unknown ones become errors in ExecutionBatchError."""
    from uc_declarative_abac.utils import ExecutionBatchError
    config = _catalog_with_two_grant_policies_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_principals_with_groups(mock_workspace_client, ["data_engineers"])

    with pytest.raises(ExecutionBatchError) as exc_info:
        _run_all_enabled(
            config_dir=root,
            workspace_client=mock_workspace_client,

            warehouse_id="test-warehouse-id",
        )

    # GRANT SQL should have been executed for the valid principal
    grant_stmts = [
        s for s in mock_workspace_client.executed_sql
        if s.upper().startswith("GRANT") and "data_engineers" in s
    ]
    assert len(grant_stmts) > 0, (
        f"Expected GRANT SQL for data_engineers, got: {mock_workspace_client.executed_sql}"
    )

    # The batch error should contain a PrincipalValidationError for ghost_team
    principal_errors = [
        e for e in exc_info.value.errors
        if isinstance(e.exception, PrincipalValidationError)
    ]
    assert len(principal_errors) > 0, (
        f"Expected PrincipalValidationError for ghost_team in errors, got: {exc_info.value.errors}"
    )


# ---------------------------------------------------------------------------
# --enable-* flag gating (skip-path tests)
# ---------------------------------------------------------------------------


def test_orchestrator_skips_tags_workflow_when_tag_management_disabled(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """With enable_tag_management=False, no tag diff is computed and no ALTER SET TAGS SQL runs."""
    config = _catalog_with_tags_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    result = run(
        config_dir=root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
        enable_tag_management=False,
        enable_taggable_management=True,
        enable_privilege_management=True,
    )

    assert result.tag_diff == TagDiff()
    alter_stmts = [s for s in mock_workspace_client.executed_sql if "SET TAGS" in s.upper()]
    assert alter_stmts == [], (
        f"Expected no ALTER ... SET TAGS SQL when tag management is off, got: {alter_stmts}"
    )


def test_orchestrator_does_not_fetch_actual_tags_when_both_tag_and_privilege_management_disabled(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """When neither tag nor privilege management is enabled, the engine skips the
    actual_tags fetch entirely — no SELECT against any *_tags system table."""
    config = _catalog_with_tags_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    run(
        config_dir=root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
        enable_tag_management=False,
        enable_privilege_management=False,
        enable_taggable_management=False,
    )

    tag_queries = [s for s in mock_workspace_client.executed_sql if "_tags" in s.lower()]
    assert tag_queries == [], (
        f"Expected no tag-table queries when both flags off, got: {tag_queries}"
    )


def test_orchestrator_skips_privileges_workflow_when_privilege_management_disabled(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """With enable_privilege_management=False, no privilege diff is computed and no
    GRANT/REVOKE SQL runs."""
    config = _catalog_with_grant_policy_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    result = run(
        config_dir=root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
        enable_tag_management=True,
        enable_taggable_management=True,
        enable_privilege_management=False,
    )

    assert result.privilege_diff == PrivilegeDiff()
    grant_stmts = [
        s for s in mock_workspace_client.executed_sql
        if s.upper().startswith("GRANT") or s.upper().startswith("REVOKE")
    ]
    assert grant_stmts == [], (
        f"Expected no GRANT/REVOKE SQL when privilege management is off, got: {grant_stmts}"
    )


def test_orchestrator_does_not_fetch_actual_privileges_when_privilege_management_disabled(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """When privilege management is off, no SELECT against any *_privileges system table runs."""
    config = _catalog_with_grant_policy_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    run(
        config_dir=root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
        enable_tag_management=True,
        enable_taggable_management=True,
        enable_privilege_management=False,
    )

    privilege_queries = [s for s in mock_workspace_client.executed_sql if "_privileges" in s.lower()]
    assert privilege_queries == [], (
        f"Expected no privilege-table queries when privilege management off, got: {privilege_queries}"
    )


def test_orchestrator_privileges_use_actual_tags_when_tag_management_disabled(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """Config declares a grant policy with has_tags {env: prod} but does NOT declare
    the env tag on the catalog. UC's actual_tags fetch returns that tag on the catalog.
    With tag management off + privilege management on, the privileges compiler must
    match against the on-disk tags, emitting the grant."""
    config = {
        "resources": {
            "governed_tags": {
                "env": {"allowed_values": ["prod"]},
            },
            "catalogs": {
                "my_catalog": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["data_engineers"],
                            "has_tags": {"env": "prod"},
                        },
                    ],
                }
            }
        }
    }
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    # actual_tags: env=prod is set on the catalog in UC, even though config doesn't declare it.
    actual_tag_rows = [
        ["CATALOG", "my_catalog", '[{"tag_name":"env","tag_value":"prod"}]'],
    ]
    _install_fetch_router(monkeypatch, config, tag_rows=actual_tag_rows)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    result = run(
        config_dir=root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
        enable_tag_management=False,
        enable_taggable_management=True,
        enable_privilege_management=True,
    )

    assert len(result.privilege_diff.to_grant) >= 1, (
        f"Expected grant emitted from UC's actual env=prod tag, got to_grant={result.privilege_diff.to_grant}"
    )


def test_orchestrator_privileges_use_config_tags_when_tag_management_enabled(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """Opposite pattern: config DOES declare the env=prod tag on the catalog, but UC
    does not. With tag management on, the privileges compiler uses the config tags
    (which will be applied this run) and emits the grant."""
    config = {
        "resources": {
            "governed_tags": {
                "env": {"allowed_values": ["prod"]},
            },
            "catalogs": {
                "my_catalog": {
                    "tags": {"env": "prod"},
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["data_engineers"],
                            "has_tags": {"env": "prod"},
                        },
                    ],
                }
            }
        }
    }
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    # UC has no tags on the catalog — only config declares env=prod.
    _install_fetch_router(monkeypatch, config, tag_rows=[])
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    result = _run_all_enabled(
        config_dir=root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
    )

    assert len(result.privilege_diff.to_grant) >= 1, (
        f"Expected grant emitted from config's env=prod tag, got to_grant={result.privilege_diff.to_grant}"
    )


def test_orchestrator_skips_non_function_attribute_updates_when_taggable_management_disabled(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """Config declares a catalog owner; with taggable management off, the resulting
    diff contains no CATALOG attribute updates."""
    config = {
        "resources": {
            "catalogs": {
                "my_catalog": {
                    "owner": "data_engineers",
                }
            }
        }
    }
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    result = run(
        config_dir=root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
        enable_tag_management=False,
        enable_privilege_management=False,
        enable_taggable_management=False,
    )

    catalog_updates = [
        u for u in result.securable_diff.attributes_to_update
        if u.securable_type == SecurableType.CATALOG
    ]
    assert catalog_updates == [], (
        f"Expected no CATALOG attribute updates with taggable management off, got: {catalog_updates}"
    )


def test_orchestrator_creates_missing_taggables_when_taggable_creation_enabled(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """With --enable-taggable-creation on, a catalog declared in config but absent
    from UC produces a CREATE CATALOG statement in executed SQL."""
    config = {
        "resources": {
            "catalogs": {
                "brand_new_cat": {},
            }
        }
    }
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    # Route every fetch to empty rows — the catalog doesn't exist in UC.
    monkeypatch.setattr(
        "uc_declarative_abac.helpers.unity_catalog._fetch_external_links_rows",
        lambda response: [],
    )
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    run(
        config_dir=root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
        enable_taggable_creation=True,
    )

    create_catalog_stmts = [s for s in mock_workspace_client.executed_sql if "CREATE CATALOG" in s.upper()]
    assert len(create_catalog_stmts) == 1
    assert "brand_new_cat" in create_catalog_stmts[0]


def test_orchestrator_does_not_create_missing_taggables_when_taggable_creation_disabled(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """Without --enable-taggable-creation, a missing catalog raises ExecutionBatchError
    with a NonexistentSecurableError (the pre-flag behaviour)."""
    from uc_declarative_abac.utils import ExecutionBatchError, NonexistentSecurableError
    config = {
        "resources": {
            "catalogs": {
                "ghost_cat": {},
            }
        }
    }
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    monkeypatch.setattr(
        "uc_declarative_abac.helpers.unity_catalog._fetch_external_links_rows",
        lambda response: [],
    )
    _setup_mock_empty_principals(mock_workspace_client)

    with pytest.raises(ExecutionBatchError) as exc_info:
        run(
            config_dir=root,
            workspace_client=mock_workspace_client,
            warehouse_id="test-warehouse-id",
            enable_taggable_creation=False,
        )

    nonexistent_errors = [
        e for e in exc_info.value.errors
        if isinstance(e.exception, NonexistentSecurableError)
    ]
    assert len(nonexistent_errors) >= 1
    create_stmts = [s for s in mock_workspace_client.executed_sql if "CREATE CATALOG" in s.upper()]
    assert create_stmts == []


def test_orchestrator_still_checks_nonexistent_securables_when_taggable_management_disabled(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """A catalog declared in config but absent from UC still produces a
    NonexistentSecurableError even when taggable management is off — the validation
    is independent of the attribute-management flag."""
    from uc_declarative_abac.utils import ExecutionBatchError, NonexistentSecurableError
    config = {
        "resources": {
            "catalogs": {
                "ghost_catalog": {},
            }
        }
    }
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    # Route EVERY query to empty rows — ghost_catalog absent from actual securables.
    monkeypatch.setattr(
        "uc_declarative_abac.helpers.unity_catalog._fetch_external_links_rows",
        lambda response: [],
    )
    _setup_mock_empty_principals(mock_workspace_client)

    with pytest.raises(ExecutionBatchError) as exc_info:
        run(
            config_dir=root,
            workspace_client=mock_workspace_client,
            warehouse_id="test-warehouse-id",
            enable_tag_management=False,
            enable_privilege_management=False,
            enable_taggable_management=False,
        )

    nonexistent_errors = [
        e for e in exc_info.value.errors
        if isinstance(e.exception, NonexistentSecurableError)
    ]
    assert len(nonexistent_errors) >= 1, (
        f"Expected a NonexistentSecurableError for ghost_catalog, got: {exc_info.value.errors}"
    )


# ---------------------------------------------------------------------------
# Per-catalog filter flags (--*-for-catalogs)
# ---------------------------------------------------------------------------


def _two_catalog_tags_config() -> dict:
    """Two catalogs, each with a tag declared on the catalog itself."""
    return {
        "resources": {
            "catalogs": {
                "cat_a": {"tags": {"env": "prod"}},
                "cat_b": {"tags": {"env": "prod"}},
            }
        }
    }


def _two_catalog_grants_config() -> dict:
    """Two catalogs, each with a tag and a grant policy keyed by that tag."""
    return {
        "resources": {
            "governed_tags": {
                "env": {"allowed_values": ["prod"]},
            },
            "catalogs": {
                "cat_a": {
                    "tags": {"env": "prod"},
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["data_engineers"],
                            "has_tags": {"env": "prod"},
                        },
                    ],
                },
                "cat_b": {
                    "tags": {"env": "prod"},
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["data_engineers"],
                            "has_tags": {"env": "prod"},
                        },
                    ],
                },
            }
        }
    }


def _two_catalog_owners_config() -> dict:
    """Two catalogs, each declaring an owner — exercises taggable-management."""
    return {
        "resources": {
            "catalogs": {
                "cat_a": {"owner": "data_engineers"},
                "cat_b": {"owner": "data_engineers"},
            }
        }
    }


def test_orchestrator_tag_filter_scopes_tag_set_sql_to_listed_catalog_only(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """With --manage-tags-for-catalogs=cat_a, only cat_a tags emit SET TAGS SQL."""
    config = _two_catalog_tags_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    run(
        config_dir=root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
        enable_tag_management=True,
        manage_tags_for_catalogs="cat_a",
    )

    set_tag_stmts = [s for s in mock_workspace_client.executed_sql if "SET TAGS" in s.upper()]
    assert any("cat_a" in s for s in set_tag_stmts), (
        f"Expected at least one SET TAGS for cat_a, got: {set_tag_stmts}"
    )
    assert all("cat_b" not in s for s in set_tag_stmts), (
        f"Expected no SET TAGS touching cat_b, got: {set_tag_stmts}"
    )


def test_orchestrator_tag_filter_excludes_out_of_scope_catalogs_from_tag_diff(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """The returned tag_diff.to_add contains only in-scope catalog tags."""
    config = _two_catalog_tags_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    result = run(
        config_dir=root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
        enable_tag_management=True,
        manage_tags_for_catalogs="cat_a",
    )

    catalogs_in_diff = {t.securable_full_name.split(".", 1)[0] for t in result.tag_diff.to_add}
    assert catalogs_in_diff == {"cat_a"}, (
        f"Expected tag_diff.to_add to only contain cat_a entries, got catalogs: {catalogs_in_diff}"
    )


def test_orchestrator_privilege_filter_scopes_grants_to_listed_catalog_only(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """With --manage-privileges-for-catalogs=cat_a, only cat_a privileges are granted."""
    config = _two_catalog_grants_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    result = run(
        config_dir=root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
        enable_tag_management=True,
        enable_privilege_management=True,
        manage_privileges_for_catalogs="cat_a",
    )

    catalogs_in_grants = {
        p.securable_full_name.split(".", 1)[0] for p in result.privilege_diff.to_grant
    }
    assert catalogs_in_grants == {"cat_a"}, (
        f"Expected to_grant to only contain cat_a entries, got catalogs: {catalogs_in_grants}"
    )
    grant_stmts = [s for s in mock_workspace_client.executed_sql if s.upper().startswith("GRANT")]
    assert all("cat_b" not in s for s in grant_stmts), (
        f"Expected no GRANT touching cat_b, got: {grant_stmts}"
    )


def test_orchestrator_taggable_management_filter_scopes_attribute_updates_to_listed_catalog_only(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """Owner is declared on both catalogs but the filter pins management to cat_a."""
    config = _two_catalog_owners_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    result = run(
        config_dir=root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
        enable_taggable_management=True,
        manage_taggables_for_catalogs="cat_a",
    )

    catalog_updates = [
        u for u in result.securable_diff.attributes_to_update
        if u.securable_type == SecurableType.CATALOG
    ]
    full_names = {u.full_name for u in catalog_updates}
    assert "cat_a" in full_names, f"Expected cat_a owner update, got: {full_names}"
    assert "cat_b" not in full_names, f"Expected no cat_b owner update, got: {full_names}"


def test_orchestrator_taggable_creation_filter_creates_only_listed_catalog(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """With --create-taggables-for-catalogs=cat_a and both catalogs missing from UC,
    only cat_a gets a CREATE CATALOG statement. cat_b surfaces as NonexistentSecurableError."""
    from uc_declarative_abac.utils import ExecutionBatchError, NonexistentSecurableError
    config = {
        "resources": {
            "catalogs": {
                "cat_a": {},
                "cat_b": {},
            }
        }
    }
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    monkeypatch.setattr(
        "uc_declarative_abac.helpers.unity_catalog._fetch_external_links_rows",
        lambda response: [],
    )
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    with pytest.raises(ExecutionBatchError) as exc_info:
        run(
            config_dir=root,
            workspace_client=mock_workspace_client,
            warehouse_id="test-warehouse-id",
            enable_taggable_creation=True,
            create_taggables_for_catalogs="cat_a",
        )

    nonexistent = [e for e in exc_info.value.errors if isinstance(e.exception, NonexistentSecurableError)]
    cat_b_errors = [e for e in nonexistent if e.exception.full_name == "cat_b"]
    cat_a_errors = [e for e in nonexistent if e.exception.full_name == "cat_a"]
    assert cat_b_errors, "Expected NonexistentSecurableError for out-of-scope cat_b"
    assert not cat_a_errors, "Expected NO NonexistentSecurableError for in-scope cat_a"

    create_stmts = [s for s in mock_workspace_client.executed_sql if "CREATE CATALOG" in s.upper()]
    assert any("cat_a" in s for s in create_stmts), (
        f"Expected CREATE CATALOG for cat_a, got: {create_stmts}"
    )
    assert all("cat_b" not in s for s in create_stmts), (
        f"Expected no CREATE CATALOG for cat_b, got: {create_stmts}"
    )


def test_orchestrator_taggable_creation_filter_still_creates_functions_in_out_of_scope_catalogs(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """Functions are always engine-managed — they flow through the creation filter
    regardless of catalog scope."""
    config = {
        "resources": {
            "catalogs": {
                "cat_a": {
                    "schemas": [{
                        "name": "sch",
                        "functions": [{
                            "name": "mask_email",
                            "parameters": [{"name": "x", "type": "STRING"}],
                            "return": "x",
                        }],
                    }],
                },
                "cat_b": {
                    "schemas": [{
                        "name": "sch",
                        "functions": [{
                            "name": "mask_phone",
                            "parameters": [{"name": "x", "type": "STRING"}],
                            "return": "x",
                        }],
                    }],
                },
            }
        }
    }
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    # Both catalogs (with their schemas) exist in UC; the functions are missing.
    sec_rows = _securable_existence_rows(config)
    monkeypatch.setattr(
        "uc_declarative_abac.helpers.unity_catalog._fetch_external_links_rows",
        lambda response: sec_rows if (
            "catalog_owner" in (getattr(response, "_sql", "") or "").lower()
            or "schema_owner" in (getattr(response, "_sql", "") or "").lower()
            or "routine_owner" in (getattr(response, "_sql", "") or "").lower()
        ) else [],
    )
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    run(
        config_dir=root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
        enable_taggable_creation=True,
        create_taggables_for_catalogs="cat_a",
    )

    create_func_stmts = [
        s for s in mock_workspace_client.executed_sql if "FUNCTION" in s.upper() and "CREATE" in s.upper()
    ]
    assert any("mask_email" in s for s in create_func_stmts), (
        f"Expected mask_email function created in cat_a, got: {create_func_stmts}"
    )
    assert any("mask_phone" in s for s in create_func_stmts), (
        f"Expected mask_phone function created in cat_b (functions always engine-managed), "
        f"got: {create_func_stmts}"
    )


def test_orchestrator_tag_filter_uses_actual_tags_for_out_of_scope_catalogs_when_grants_match(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """With tag mgmt scoped to cat_a, privileges compiler must read out-of-scope cat_b's
    tag state from UC (actual_tags) — because cat_b's tags aren't being reconciled
    this run, so the desired tag state for cat_b is irrelevant for grant matching."""
    config = _two_catalog_grants_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    # cat_b has env=prod in UC (actual), cat_a does not yet.
    actual_tag_rows = [
        ["CATALOG", "cat_b", '[{"tag_name":"env","tag_value":"prod"}]'],
    ]
    _install_fetch_router(monkeypatch, config, tag_rows=actual_tag_rows)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    result = run(
        config_dir=root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
        enable_tag_management=True,
        enable_privilege_management=True,
        manage_tags_for_catalogs="cat_a",  # cat_b's tags untouched this run
    )

    # cat_b's grant policy matches against UC's actual env=prod tag → grant emitted.
    cat_b_grants = [p for p in result.privilege_diff.to_grant if p.securable_full_name.startswith("cat_b")]
    assert cat_b_grants, (
        f"Expected cat_b grant from actual tag state, got: {result.privilege_diff.to_grant}"
    )


def test_orchestrator_raises_when_catalog_filter_references_unknown_catalog(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """Typos in the filter list raise ValueError early — before any UC operations."""
    config = _two_catalog_tags_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    with pytest.raises(ValueError) as exc_info:
        run(
            config_dir=root,
            workspace_client=mock_workspace_client,
            warehouse_id="test-warehouse-id",
            enable_tag_management=True,
            manage_tags_for_catalogs="cat_a,typo_cat",
        )
    assert "typo_cat" in str(exc_info.value)


def test_orchestrator_filter_is_no_op_when_corresponding_enable_flag_is_off(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """A non-default filter value with the enable flag off is silently ignored —
    even unknown catalog names don't error, because parsing is skipped entirely."""
    config = _two_catalog_tags_config()
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    result = run(
        config_dir=root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
        enable_tag_management=False,
        manage_tags_for_catalogs="totally_made_up_catalog",
    )

    assert result.tag_diff == TagDiff()
    set_tag_stmts = [s for s in mock_workspace_client.executed_sql if "SET TAGS" in s.upper()]
    assert set_tag_stmts == []


def test_orchestrator_deletes_governed_tag_when_flag_and_force_enabled(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """With enable_governed_tag_deletion=True and force=True, a governed tag that
    exists in UC but is absent from config triggers a delete_tag_policy call."""
    # Config declares no governed tags.
    config = {
        "resources": {
            "catalogs": {"cat": {"name": "cat"}},
        }
    }
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    # UC has a legacy governed tag that's not in config.
    from unittest.mock import MagicMock as _MagicMock
    legacy_policy = _MagicMock()
    legacy_policy.tag_key = "legacy_pii"
    legacy_policy.description = "legacy"
    legacy_policy.values = []
    mock_workspace_client.tag_policies.list_tag_policies.return_value = iter([legacy_policy])

    run(
        config_dir=root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
        enable_governed_tag_deletion=True,
        force=True,
    )

    mock_workspace_client.tag_policies.delete_tag_policy.assert_called_once_with("legacy_pii")


def test_orchestrator_does_not_delete_governed_tag_when_flag_disabled(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """Without enable_governed_tag_deletion, UC-only governed tags are left alone."""
    config = {
        "resources": {
            "catalogs": {"cat": {"name": "cat"}},
        }
    }
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    from unittest.mock import MagicMock as _MagicMock
    legacy_policy = _MagicMock()
    legacy_policy.tag_key = "legacy_pii"
    legacy_policy.description = "legacy"
    legacy_policy.values = []
    mock_workspace_client.tag_policies.list_tag_policies.return_value = iter([legacy_policy])

    run(
        config_dir=root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
        enable_governed_tag_deletion=False,
    )

    mock_workspace_client.tag_policies.delete_tag_policy.assert_not_called()


def test_orchestrator_raises_ungoverned_tag_error_when_grant_policy_references_ungoverned_tag(
    tmp_yaml_dir, mock_workspace_client, monkeypatch):
    """A grant policy whose has_tags key is not declared as a governed tag
    (neither in config nor in UC) surfaces as an UngovernedTagError inside the
    final ExecutionBatchError. The run does not crash during compilation; the
    offending policy is simply dropped and its validation failure is surfaced
    at the end via the batch-error pattern."""
    # Config: one grant policy referencing the tag key 'ungoverned_key', and
    # no governed_tags block declaring it.
    config = {
        "resources": {
            "catalogs": {
                "my_catalog": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["data_engineers"],
                            "has_tags": {"ungoverned_key": "*"},
                        },
                    ],
                }
            }
        }
    }
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _install_fetch_router(monkeypatch, config)
    _setup_mock_principals(mock_workspace_client, "data_engineers")
    # UC has no governed tags either — union of desired+actual is empty.
    mock_workspace_client.tag_policies.list_tag_policies.return_value = iter([])

    with pytest.raises(ExecutionBatchError) as exc_info:
        _run_all_enabled(
            config_dir=root,
            workspace_client=mock_workspace_client,
            warehouse_id="test-warehouse-id",
        )

    ungoverned_errors = [
        e for e in exc_info.value.errors
        if isinstance(e.exception, UngovernedTagError)
    ]
    assert len(ungoverned_errors) >= 1, (
        f"Expected at least one UngovernedTagError, got: {exc_info.value.errors}"
    )
    assert any("ungoverned_key" in str(e.exception) for e in ungoverned_errors)


# ---------------------------------------------------------------------------
# rfa_targets threading into fetch_actual_securables
# ---------------------------------------------------------------------------


def _capture_fetch_actual_securables_calls(monkeypatch) -> list[tuple]:
    """Patch UnityCatalogHelper.fetch_actual_securables to record its call args
    while still returning empty state. Returns the live list of recorded calls."""
    from uc_declarative_abac.helpers.unity_catalog import UnityCatalogHelper

    calls: list[tuple] = []
    original = UnityCatalogHelper.fetch_actual_securables

    def _spy(self, catalog_names, rfa_targets=None):
        calls.append((tuple(catalog_names), frozenset(rfa_targets or ())))
        # Return empty actual state so the rest of the orchestrator short-circuits cleanly.
        return set(), set()

    monkeypatch.setattr(UnityCatalogHelper, "fetch_actual_securables", _spy)
    return calls


def test_orchestrator_passes_rfa_targets_for_securables_with_destinations(
    tmp_yaml_dir, mock_workspace_client, monkeypatch,
):
    """When the config declares rfa_destinations and taggable management is on,
    fetch_actual_securables is invoked with rfa_targets containing exactly those
    (securable_type, full_name) pairs.

    The run raises ``ExecutionBatchError`` because the mock returns empty actual
    state so every declared securable surfaces as nonexistent — that's fine for
    this test, we only care about how ``fetch_actual_securables`` was invoked.
    """
    config = {
        "resources": {
            "catalogs": {
                "my_catalog": {
                    "rfa_destinations": ["data-gov@example.com"],
                    "schemas": [
                        {"name": "sales", "rfa_destinations": ["https://hook.example.com"]},
                    ],
                }
            }
        }
    }
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _setup_mock_empty_principals(mock_workspace_client)
    calls = _capture_fetch_actual_securables_calls(monkeypatch)

    with pytest.raises(ExecutionBatchError):
        run(
            config_dir=root,
            workspace_client=mock_workspace_client,
            warehouse_id="test-warehouse-id",
            enable_taggable_management=True,
        )

    assert len(calls) == 1
    _catalog_names, rfa_targets = calls[0]
    assert rfa_targets == frozenset({
        (SecurableType.CATALOG, "my_catalog"),
        (SecurableType.SCHEMA, "my_catalog.sales"),
    })


def test_orchestrator_passes_empty_rfa_targets_when_taggable_management_off(
    tmp_yaml_dir, mock_workspace_client, monkeypatch,
):
    """rfa_destinations updates are gated by enable_taggable_management — when it's
    off, no RFA fetch fires (rfa_targets is an empty set)."""
    config = {
        "resources": {
            "catalogs": {
                "my_catalog": {
                    "rfa_destinations": ["data-gov@example.com"],
                }
            }
        }
    }
    root = tmp_yaml_dir({"resources/catalog.yaml": config})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _setup_mock_empty_principals(mock_workspace_client)
    calls = _capture_fetch_actual_securables_calls(monkeypatch)

    with pytest.raises(ExecutionBatchError):
        run(
            config_dir=root,
            workspace_client=mock_workspace_client,
            warehouse_id="test-warehouse-id",
            enable_taggable_management=False,
        )

    assert len(calls) == 1
    _catalog_names, rfa_targets = calls[0]
    assert rfa_targets == frozenset()
