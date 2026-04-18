from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from uc_abac_governor.governor import run
from uc_abac_governor.policies.state import Policy, PolicyDiff
from uc_abac_governor.privileges.state import PrivilegeDiff
from uc_abac_governor.tags.state import TagDiff
from uc_abac_governor.types import ExecutionBatchError, PolicyType, PrincipalValidationError, SecurableType


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


def _setup_mock_workspace_empty_state(mock_workspace_client: MagicMock) -> None:
    """Configure the mock workspace client to return empty actual state."""
    from databricks.sdk.service.sql import StatementState

    result_mock = MagicMock()
    result_mock.status.state = StatementState.SUCCEEDED
    result_mock.result.data_array = []
    result_mock.result.external_links = []

    def _capture_and_return(*args, **kwargs):
        statement = kwargs.get("statement", args[0] if args else None)
        if statement:
            mock_workspace_client.executed_sql.append(statement)
        return result_mock

    mock_workspace_client.statement_execution.execute_statement.side_effect = (
        _capture_and_return
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


def test_governor_runs_tags_workflow_end_to_end(
    tmp_yaml_dir, mock_workspace_client):
    """YAML configs with tagged catalog -> tag_diff.to_add is non-empty, SQL was executed."""
    root = tmp_yaml_dir({"resources/catalog.yaml": _catalog_with_tags_config()})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    _, tag_diff, _, _ = run(
        config_dir=root,
        workspace_client=mock_workspace_client,

        warehouse_id="test-warehouse-id",
    )

    assert isinstance(tag_diff, TagDiff)
    assert len(tag_diff.to_add) > 0, "Expected tags to be added for the tagged catalog"

    executed = mock_workspace_client.executed_sql
    set_tags_stmts = [s for s in executed if "SET TAGS" in s.upper()]
    assert len(set_tags_stmts) > 0, (
        f"Expected SET TAGS SQL to be executed, got: {executed}"
    )


def test_governor_runs_privileges_workflow_end_to_end(
    tmp_yaml_dir, mock_workspace_client):
    """YAML with grant policy + tagged objects, empty actual privileges -> privilege_diff.to_grant is non-empty."""
    root = tmp_yaml_dir(
        {"resources/catalog.yaml": _catalog_with_grant_policy_config()}
    )
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    _, _, _, privilege_diff = run(
        config_dir=root,
        workspace_client=mock_workspace_client,

        warehouse_id="test-warehouse-id",
    )

    assert isinstance(privilege_diff, PrivilegeDiff)
    assert len(privilege_diff.to_grant) > 0, (
        "Expected privileges to be granted for the grant policy"
    )

    executed = mock_workspace_client.executed_sql
    grant_stmts = [s for s in executed if s.upper().startswith("GRANT")]
    assert len(grant_stmts) > 0, (
        f"Expected GRANT SQL to be executed, got: {executed}"
    )


def test_governor_runs_both_domains_independently(
    tmp_yaml_dir, mock_workspace_client):
    """Both tag and privilege changes are computed; verify both diffs are populated."""
    root = tmp_yaml_dir(
        {"resources/catalog.yaml": _catalog_with_tags_and_grants_config()}
    )
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    _, tag_diff, _, privilege_diff = run(
        config_dir=root,
        workspace_client=mock_workspace_client,

        warehouse_id="test-warehouse-id",
    )

    assert len(tag_diff.to_add) >= 2, (
        f"Expected at least 2 tags to add, got {len(tag_diff.to_add)}: {tag_diff.to_add}"
    )
    assert len(privilege_diff.to_grant) >= 1, (
        f"Expected at least 1 privilege to grant, got {len(privilege_diff.to_grant)}: "
        f"{privilege_diff.to_grant}"
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


@patch("uc_abac_governor.helpers.unity_catalog._fetch_external_links_rows")
def test_governor_produces_empty_diffs_when_in_sync(
    mock_fetch, tmp_yaml_dir, mock_workspace_client):
    """When actual state matches desired, both diffs are empty and no SQL is executed."""
    root = tmp_yaml_dir(
        {"resources/catalog.yaml": _catalog_with_grant_policy_config()}
    )

    actual_tags = [
        ["CATALOG", "my_catalog", "env", "prod"],
        ["SCHEMA", "my_catalog.sales", "team", "data"],
    ]
    actual_privileges = [
        ["SCHEMA", "my_catalog.sales", "data_engineers", "select"],
    ]

    def _route_rows_by_sql(response):
        sql = getattr(response, "_sql", "") or ""
        sql_lower = sql.lower()
        if "tag" in sql_lower:
            return actual_tags
        if "privilege" in sql_lower:
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

    _, tag_diff, _, privilege_diff = run(
        config_dir=root,
        workspace_client=mock_workspace_client,

        warehouse_id="test-warehouse-id",
    )

    assert tag_diff.to_add == set()
    assert tag_diff.to_update == set()
    assert tag_diff.to_remove == set()
    assert privilege_diff.to_grant == set()
    assert privilege_diff.to_revoke == set()

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


def test_governor_validates_principals_before_applying(
    tmp_yaml_dir, mock_workspace_client):
    """Policy references unknown principal -> ExecutionBatchError, no GRANT/REVOKE SQL executed."""
    root = tmp_yaml_dir(
        {"resources/catalog.yaml": _catalog_with_grant_policy_config()}
    )
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _setup_mock_empty_principals(mock_workspace_client)

    with pytest.raises(ExecutionBatchError):
        run(
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


def test_governor_dry_run_does_not_execute_sql(
    tmp_yaml_dir, mock_workspace_client):
    """dry_run=True -> diffs are computed but no mutation SQL is executed."""
    root = tmp_yaml_dir(
        {"resources/catalog.yaml": _catalog_with_tags_and_grants_config()}
    )
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    _, tag_diff, _, privilege_diff = run(
        config_dir=root,
        workspace_client=mock_workspace_client,

        warehouse_id="test-warehouse-id",
        dry_run=True,
    )

    assert isinstance(tag_diff, TagDiff)
    assert isinstance(privilege_diff, PrivilegeDiff)

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


def test_governor_fetches_tags_privileges_and_principals_in_parallel(
    tmp_yaml_dir, mock_workspace_client):
    """Mock delays on fetch methods; total elapsed < sum of delays proves parallelism."""
    root = tmp_yaml_dir(
        {"resources/catalog.yaml": _catalog_with_tags_and_grants_config()}
    )

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
        return result

    mock_workspace_client.statement_execution.execute_statement.side_effect = (
        _slow_execute
    )

    def _slow_scim_do(method, path, **kwargs):
        if "/account/scim/v2/Groups" in path:
            time.sleep(delay_seconds)
            return {"totalResults": 1, "startIndex": 1, "itemsPerPage": 100, "Resources": [{"displayName": "data_engineers"}]}
        return {"totalResults": 0, "startIndex": 1, "itemsPerPage": 100, "Resources": []}

    mock_workspace_client.api_client.do.side_effect = _slow_scim_do

    start = time.monotonic()
    run(
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


def test_governor_raises_execution_batch_error_when_sql_fails(
    tmp_yaml_dir, mock_workspace_client):
    """When mutation SQL fails, governor.run() raises ExecutionBatchError with collected errors."""
    from uc_abac_governor.types import ExecutionBatchError

    root = tmp_yaml_dir(
        {"resources/catalog.yaml": _catalog_with_tags_and_grants_config()}
    )

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
        return result

    mock_workspace_client.statement_execution.execute_statement.side_effect = (
        _fail_mutations
    )
    _setup_mock_principals(mock_workspace_client, "data_engineers")

    with pytest.raises(ExecutionBatchError) as exc_info:
        run(
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


def test_governor_runs_policies_workflow_end_to_end(
    tmp_yaml_dir, mock_workspace_client):
    """A MASK policy with no corresponding actual UC policy -> CREATE POLICY SQL is executed."""
    root = tmp_yaml_dir({"resources/catalog.yaml": _catalog_with_mask_policy_config()})
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _setup_mock_principals_with_groups(mock_workspace_client, ["analysts", "admins"])

    _, _, policy_diff, _ = run(
        config_dir=root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
    )

    assert isinstance(policy_diff, PolicyDiff)
    assert len(policy_diff.to_create) == 1
    create_stmts = [s for s in mock_workspace_client.executed_sql if "CREATE POLICY" in s.upper()]
    assert len(create_stmts) == 1, f"Expected CREATE POLICY SQL, got: {mock_workspace_client.executed_sql}"


def test_governor_policies_workflow_is_idempotent(
    tmp_yaml_dir, mock_workspace_client):
    """When list_policies returns the same policy already exists, no CREATE POLICY SQL is executed."""
    root = tmp_yaml_dir({"resources/catalog.yaml": _catalog_with_mask_policy_config()})
    _setup_mock_workspace_empty_state(mock_workspace_client)
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
    mock_workspace_client.policies.list_policies.return_value = iter([fake_policy])

    _, _, policy_diff, _ = run(
        config_dir=root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
    )

    assert policy_diff.to_create == set()
    assert policy_diff.to_replace == set()
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


def test_governor_is_idempotent_for_service_principal_across_display_name_and_app_id():
    """Same workspace principal referenced by display_name in YAML and application_id in UC
    state (GRANT system tables, list_policies SDK response) should produce an empty diff on
    the second run — proving that PrincipalResolver bridges the two representations correctly."""
    sp_display = "sp_sales_runner"
    sp_app_id = "abc-1234-app-id"

    # YAML: one grant policy + one mask policy, both referencing the SP by display name
    config = {
        "resources": {
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
    _, tag_diff, policy_diff, privilege_diff = run(
        config_dir=tmp_root,
        workspace_client=mock_workspace_client,
        warehouse_id="test-warehouse-id",
    )

    assert tag_diff.to_add == set(), f"Expected no tag changes, got to_add: {tag_diff.to_add}"
    assert tag_diff.to_update == set()
    assert tag_diff.to_remove == set()
    assert privilege_diff.to_grant == set(), f"Expected no grants, got: {privilege_diff.to_grant}"
    assert privilege_diff.to_revoke == set(), f"Expected no revokes, got: {privilege_diff.to_revoke}"
    assert policy_diff.to_create == set(), f"Expected no policy creates, got: {policy_diff.to_create}"
    assert policy_diff.to_replace == set(), f"Expected no policy replaces, got: {policy_diff.to_replace}"

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
        # Tags query
        if "catalog_tags" in lower or "schema_tags" in lower:
            return [["CATALOG", "my_catalog", "team", "sales"]]
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
        "uc_abac_governor.helpers.unity_catalog._fetch_external_links_rows",
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
    mock_workspace_client.policies.list_policies.return_value = iter([fake_policy])


def test_governor_collects_unknown_principal_errors(
    tmp_yaml_dir, mock_workspace_client):
    """Unknown principals are collected as errors in ExecutionBatchError, not raised as PrincipalValidationError."""
    from uc_abac_governor.types import ExecutionBatchError, ExecutionError

    root = tmp_yaml_dir(
        {"resources/catalog.yaml": _catalog_with_grant_policy_config()}
    )
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _setup_mock_empty_principals(mock_workspace_client)

    with pytest.raises(ExecutionBatchError) as exc_info:
        run(
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


def test_governor_continues_with_valid_principals_when_some_are_unknown(
    tmp_yaml_dir, mock_workspace_client):
    """Valid principals get GRANT SQL executed; unknown ones become errors in ExecutionBatchError."""
    from uc_abac_governor.types import ExecutionBatchError

    root = tmp_yaml_dir(
        {"resources/catalog.yaml": _catalog_with_two_grant_policies_config()}
    )
    _setup_mock_workspace_empty_state(mock_workspace_client)
    _setup_mock_principals_with_groups(mock_workspace_client, ["data_engineers"])

    with pytest.raises(ExecutionBatchError) as exc_info:
        run(
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
