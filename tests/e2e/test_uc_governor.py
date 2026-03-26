"""End-to-end tests for UC Governor against a live Databricks workspace.

Tests run the full governor pipeline against the liam_perritt catalog in
the field-eng-east workspace, exercising tags and grant policies at the
catalog, schema, table, and volume levels.

Prerequisites:
  - Databricks CLI profile 'field-eng-east' configured
  - Catalog 'liam_perritt' accessible
  - Warehouse 'e9a9c8bab075bb70' available
  - Principals exist: group 'uc_governor_test_team', user 'j.wang@databricks.com',
    service principal 'sp_uc_governor_test'

Run with:
  .venv/bin/python -m pytest tests/e2e/ -v
"""
from __future__ import annotations

from pathlib import Path

from databricks.sdk import WorkspaceClient

from uc_governor.governor import run
from uc_governor.tags.state import SecurableTag
from uc_governor.privileges.state import SecurablePrivilege
from uc_governor.types import Principal, PrincipalType, SecurableType


# ---------------------------------------------------------------------------
# Expected state derived from the e2e YAML configs
# ---------------------------------------------------------------------------

EXPECTED_TAGS = {
    # Catalog
    SecurableTag(SecurableType.CATALOG, "liam_perritt", "uc_gov_env", "test"),
    SecurableTag(SecurableType.CATALOG, "liam_perritt", "uc_gov_managed_by", "uc_governor"),
    # Schema: default
    SecurableTag(SecurableType.SCHEMA, "liam_perritt.default", "uc_gov_team", "platform"),
    # Schema: lff_sqlserver_bronze
    SecurableTag(SecurableType.SCHEMA, "liam_perritt.lff_sqlserver_bronze", "uc_gov_team", "data_engineering"),
    SecurableTag(SecurableType.SCHEMA, "liam_perritt.lff_sqlserver_bronze", "uc_gov_zone", "bronze"),
    # Schema: sqlserver_lff
    SecurableTag(SecurableType.SCHEMA, "liam_perritt.sqlserver_lff", "uc_gov_team", "data_engineering"),
    # Table: default.batch_table
    SecurableTag(SecurableType.TABLE, "liam_perritt.default.batch_table", "uc_gov_classification", "internal"),
    # Table: lff_sqlserver_bronze.dummy_cdc_sink
    SecurableTag(SecurableType.TABLE, "liam_perritt.lff_sqlserver_bronze.dummy_cdc_sink", "uc_gov_classification", "internal"),
    SecurableTag(SecurableType.TABLE, "liam_perritt.lff_sqlserver_bronze.dummy_cdc_sink", "uc_gov_pipeline", "lff"),
    # Table: lff_sqlserver_bronze.dummy_table_cdc_st
    SecurableTag(SecurableType.TABLE, "liam_perritt.lff_sqlserver_bronze.dummy_table_cdc_st", "uc_gov_classification", "internal"),
    SecurableTag(SecurableType.TABLE, "liam_perritt.lff_sqlserver_bronze.dummy_table_cdc_st", "uc_gov_pipeline", "lff"),
    # Table: sqlserver_lff.feature_python_extension_source
    SecurableTag(SecurableType.TABLE, "liam_perritt.sqlserver_lff.feature_python_extension_source", "uc_gov_classification", "internal"),
    # Volume: lff_sqlserver_bronze.test
    SecurableTag(SecurableType.VOLUME, "liam_perritt.lff_sqlserver_bronze.test", "uc_gov_zone", "landing"),
}

EXPECTED_PRIVILEGES = {
    # Catalog-level policy: USE_CATALOG to test group (matches uc_gov_managed_by=uc_governor)
    SecurablePrivilege(SecurableType.CATALOG, "liam_perritt", Principal(PrincipalType.GROUP, "uc_governor_test_team", "uc_governor_test_team"), "USE_CATALOG"),
    # Catalog-level policy: SELECT to test user (AND semantics — matches both uc_gov_env=test AND uc_gov_managed_by=uc_governor)
    SecurablePrivilege(SecurableType.CATALOG, "liam_perritt", Principal(PrincipalType.USER, "j.wang@databricks.com", "j.wang@databricks.com"), "SELECT"),
    # Schema-level policy on default: USE_SCHEMA + SELECT to test user (matches uc_gov_team=platform)
    SecurablePrivilege(SecurableType.SCHEMA, "liam_perritt.default", Principal(PrincipalType.USER, "j.wang@databricks.com", "j.wang@databricks.com"), "USE_SCHEMA"),
    SecurablePrivilege(SecurableType.SCHEMA, "liam_perritt.default", Principal(PrincipalType.USER, "j.wang@databricks.com", "j.wang@databricks.com"), "SELECT"),
    # Schema-level policy on lff_sqlserver_bronze: USE_SCHEMA to test SP (matches uc_gov_zone=bronze)
    SecurablePrivilege(SecurableType.SCHEMA, "liam_perritt.lff_sqlserver_bronze", Principal(PrincipalType.SERVICE_PRINCIPAL, "sp_uc_governor_test", "sp_uc_governor_test"), "USE_SCHEMA"),
    # Table-level policy on dummy_cdc_sink: SELECT to test group (matches uc_gov_pipeline=lff)
    SecurablePrivilege(SecurableType.TABLE, "liam_perritt.lff_sqlserver_bronze.dummy_cdc_sink", Principal(PrincipalType.GROUP, "uc_governor_test_team", "uc_governor_test_team"), "SELECT"),
    # dummy_table_cdc_st also has uc_gov_pipeline=lff, so the grant_pipeline_select policy matches it too
    SecurablePrivilege(SecurableType.TABLE, "liam_perritt.lff_sqlserver_bronze.dummy_table_cdc_st", Principal(PrincipalType.GROUP, "uc_governor_test_team", "uc_governor_test_team"), "SELECT"),
    # Volume-level policy: READ_VOLUME to test group (matches uc_gov_zone=landing)
    SecurablePrivilege(SecurableType.VOLUME, "liam_perritt.lff_sqlserver_bronze.test", Principal(PrincipalType.GROUP, "uc_governor_test_team", "uc_governor_test_team"), "READ_VOLUME"),
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_uc_governor_dry_run(
    config_dir: Path,
    workspace_client: WorkspaceClient,
    warehouse_id: str,
):
    """Dry run computes correct tag and privilege diffs without applying changes."""
    tag_diff, privilege_diff = run(
        config_dir=config_dir,
        workspace_client=workspace_client,

        warehouse_id=warehouse_id,
        dry_run=True,
    )

    # All expected tags should be pending add/update or already in sync
    pending_tags = tag_diff.to_add | tag_diff.to_update
    for tag in EXPECTED_TAGS:
        in_diff = tag in pending_tags
        not_being_removed = tag not in tag_diff.to_remove
        assert in_diff or not_being_removed, (
            f"Expected tag not found in diff and not in sync: {tag}"
        )

    # No unexpected tags should appear in the diff
    assert pending_tags <= EXPECTED_TAGS, (
        f"Unexpected tags in diff: {pending_tags - EXPECTED_TAGS}"
    )

    # All expected privileges should be pending grant or already in sync
    for priv in EXPECTED_PRIVILEGES:
        in_diff = priv in privilege_diff.to_grant
        not_being_revoked = priv not in privilege_diff.to_revoke
        assert in_diff or not_being_revoked, (
            f"Expected privilege not found in diff and not in sync: {priv}"
        )

    # No unexpected principals should appear in the grants
    actual_principals = {p.principal for p in privilege_diff.to_grant}
    expected_principals = {p.principal for p in EXPECTED_PRIVILEGES}
    assert actual_principals <= expected_principals, (
        f"Unexpected principals in grants: {actual_principals - expected_principals}"
    )


def test_uc_governor_deploy_and_idempotency(
    config_dir: Path,
    workspace_client: WorkspaceClient,
    warehouse_id: str,
):
    """First run applies all changes; second run confirms idempotency."""
    # First run — apply changes
    tag_diff_1, priv_diff_1 = run(
        config_dir=config_dir,
        workspace_client=workspace_client,

        warehouse_id=warehouse_id,
        dry_run=False,
    )

    # All expected tags should have been added or updated (or already in sync)
    applied_tags = tag_diff_1.to_add | tag_diff_1.to_update
    for tag in EXPECTED_TAGS:
        in_applied = tag in applied_tags
        already_in_sync = tag not in applied_tags and tag not in tag_diff_1.to_remove
        assert in_applied or already_in_sync, (
            f"Expected tag was not applied and not already in sync: {tag}"
        )

    # All expected privileges should have been granted (or already in sync)
    for priv in EXPECTED_PRIVILEGES:
        in_granted = priv in priv_diff_1.to_grant
        already_in_sync = priv not in priv_diff_1.to_revoke
        assert in_granted or already_in_sync, (
            f"Expected privilege was not granted and not already in sync: {priv}"
        )
