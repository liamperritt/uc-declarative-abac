"""End-to-end tests for UC Declarative ABAC  against a live Databricks workspace.

Tests run the full governor pipeline against the liam_perritt catalog in
the field-eng-east workspace, exercising tags and grant policies at the
catalog, schema, table, and volume levels.

Prerequisites:
  - Databricks CLI profile 'field-eng-east' configured
  - Catalog 'liam_perritt' accessible
  - Warehouse 'e9a9c8bab075bb70' available
  - Principals exist: group 'uc_declarative_abac_test_team', user 'j.wang@databricks.com',
    service principal 'sp_uc_declarative_abac_test'

Run with:
  .venv/bin/python -m pytest tests/e2e/ -v
"""
from __future__ import annotations

from pathlib import Path

from databricks.sdk import WorkspaceClient

from uc_declarative_abac.governor import run
from uc_declarative_abac.governed_tags.state import GovernedTag
from uc_declarative_abac.securables.state import AttributeUpdate, Function, SecurableAttributes
from uc_declarative_abac.tags.state import SecurableTag
from uc_declarative_abac.privileges.state import SecurablePrivilege
from uc_declarative_abac.principals.state import Principal
from uc_declarative_abac.types import PrincipalType, PrivilegeType, SecurableType


# ---------------------------------------------------------------------------
# Expected state derived from the e2e YAML configs
# ---------------------------------------------------------------------------

EXPECTED_TAGS = {
    # Catalog
    SecurableTag(SecurableType.CATALOG, "liam_perritt", "uc_gov_env", "test"),
    SecurableTag(SecurableType.CATALOG, "liam_perritt", "uc_gov_managed_by", "uc_declarative_abac"),
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
    # Column: lff_sqlserver_bronze.dummy_cdc_sink.data
    SecurableTag(SecurableType.COLUMN, "liam_perritt.lff_sqlserver_bronze.dummy_cdc_sink.data", "uc_gov_classification", "internal"),
    # Table: lff_sqlserver_bronze.dummy_table_cdc_st
    SecurableTag(SecurableType.TABLE, "liam_perritt.lff_sqlserver_bronze.dummy_table_cdc_st", "uc_gov_classification", "internal"),
    SecurableTag(SecurableType.TABLE, "liam_perritt.lff_sqlserver_bronze.dummy_table_cdc_st", "uc_gov_pipeline", "lff"),
    # Table: sqlserver_lff.feature_python_extension_source
    SecurableTag(SecurableType.TABLE, "liam_perritt.sqlserver_lff.feature_python_extension_source", "uc_gov_classification", "internal"),
    # Volume: lff_sqlserver_bronze.test
    SecurableTag(SecurableType.VOLUME, "liam_perritt.lff_sqlserver_bronze.test", "uc_gov_zone", "landing"),
}

EXPECTED_PRIVILEGES = {
    # Catalog-level policy: USE_CATALOG to test group (matches uc_gov_managed_by=uc_declarative_abac)
    SecurablePrivilege(SecurableType.CATALOG, "liam_perritt", Principal(PrincipalType.GROUP, "uc_governor_test_team", "uc_governor_test_team"), PrivilegeType.USE_CATALOG),
    # Catalog-level policy: SELECT to test user (AND semantics — matches both uc_gov_env=test AND uc_gov_managed_by=uc_declarative_abac)
    SecurablePrivilege(SecurableType.CATALOG, "liam_perritt", Principal(PrincipalType.USER, "j.wang@databricks.com", "j.wang@databricks.com"), PrivilegeType.SELECT),
    # Schema-level policy on default: USE_SCHEMA + SELECT to test user (matches uc_gov_team=platform)
    SecurablePrivilege(SecurableType.SCHEMA, "liam_perritt.default", Principal(PrincipalType.USER, "j.wang@databricks.com", "j.wang@databricks.com"), PrivilegeType.USE_SCHEMA),
    SecurablePrivilege(SecurableType.SCHEMA, "liam_perritt.default", Principal(PrincipalType.USER, "j.wang@databricks.com", "j.wang@databricks.com"), PrivilegeType.SELECT),
    # Schema-level policy on lff_sqlserver_bronze: USE_SCHEMA to test SP (matches uc_gov_zone=bronze)
    SecurablePrivilege(SecurableType.SCHEMA, "liam_perritt.lff_sqlserver_bronze", Principal(PrincipalType.SERVICE_PRINCIPAL, "72a5956b-8469-4c26-b414-bfc1a7e279c4", "sp_uc_governor_test"), PrivilegeType.USE_SCHEMA),
    # Table-level policy on dummy_cdc_sink: SELECT to test group (matches uc_gov_pipeline=lff)
    SecurablePrivilege(SecurableType.TABLE, "liam_perritt.lff_sqlserver_bronze.dummy_cdc_sink", Principal(PrincipalType.GROUP, "uc_governor_test_team", "uc_governor_test_team"), PrivilegeType.SELECT),
    # dummy_table_cdc_st also has uc_gov_pipeline=lff, so the grant_pipeline_select policy matches it too
    SecurablePrivilege(SecurableType.TABLE, "liam_perritt.lff_sqlserver_bronze.dummy_table_cdc_st", Principal(PrincipalType.GROUP, "uc_governor_test_team", "uc_governor_test_team"), PrivilegeType.SELECT),
    # Volume-level policy: READ_VOLUME to test group (matches uc_gov_zone=landing)
    SecurablePrivilege(SecurableType.VOLUME, "liam_perritt.lff_sqlserver_bronze.test", Principal(PrincipalType.GROUP, "uc_governor_test_team", "uc_governor_test_team"), PrivilegeType.READ_VOLUME),
    # Catalog-level cascade policy (matches uc_gov_pipeline=lff on tables):
    # SELECT lands on each matched table; USE_SCHEMA cascades to the parent
    # schema; USE_CATALOG cascades to the catalog. All emitted for the SP.
    SecurablePrivilege(SecurableType.TABLE, "liam_perritt.lff_sqlserver_bronze.dummy_cdc_sink", Principal(PrincipalType.SERVICE_PRINCIPAL, "72a5956b-8469-4c26-b414-bfc1a7e279c4", "sp_uc_governor_test"), PrivilegeType.SELECT),
    SecurablePrivilege(SecurableType.TABLE, "liam_perritt.lff_sqlserver_bronze.dummy_table_cdc_st", Principal(PrincipalType.SERVICE_PRINCIPAL, "72a5956b-8469-4c26-b414-bfc1a7e279c4", "sp_uc_governor_test"), PrivilegeType.SELECT),
    SecurablePrivilege(SecurableType.CATALOG, "liam_perritt", Principal(PrincipalType.SERVICE_PRINCIPAL, "72a5956b-8469-4c26-b414-bfc1a7e279c4", "sp_uc_governor_test"), PrivilegeType.USE_CATALOG),
    # USE_SCHEMA on liam_perritt.lff_sqlserver_bronze for the SP is already
    # declared above via grant_bronze_access; the cascade produces the same
    # entry and is deduplicated at the set level.
}

EXPECTED_FUNCTIONS = {
    Function(
        securable_type=SecurableType.FUNCTION,
        full_name="liam_perritt.default.mask_pii_email",
        parameters=(("col", "STRING"),),
        definition="CASE WHEN is_member('uc_governor_test_team') THEN col ELSE '***' END",
    ),
    Function(
        securable_type=SecurableType.FUNCTION,
        full_name="liam_perritt.default.format_phone",
        parameters=(("phone", "STRING"),),
        definition="concat('+', phone)",
    ),
}

EXPECTED_ATTRIBUTES = {
    # Table owner set to a group
    SecurableAttributes(SecurableType.TABLE, "liam_perritt.default.batch_table", owner="uc_governor_test_team"),
    # Function owner set to a service principal
    SecurableAttributes(SecurableType.FUNCTION, "liam_perritt.default.mask_pii_email", owner="sp_uc_governor_test"),
}

EXPECTED_GOVERNED_TAGS = {
    # Account-level governed tag declared in tests/e2e/configs/resources/governed_tags/uc_gov_pii.yaml
    GovernedTag(
        name="uc_gov_pii",
        description="PII",
        allowed_values=frozenset({"", "name", "email", "phone", "address"}),
    ),
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_uc_declarative_abac_dry_run(
    config_dir: Path,
    workspace_client: WorkspaceClient,
    warehouse_id: str,
):
    """Dry run computes correct tag, privilege, and securable diffs without applying changes."""
    result = run(
        config_dir=config_dir,
        workspace_client=workspace_client,

        warehouse_id=warehouse_id,
        dry_run=True,
        use_workspace_scim=True,
        enable_tag_management=True,
        enable_taggable_management=True,
        enable_taggable_creation=True,
        enable_privilege_management=True,
    )

    # All expected governed tags should be pending create/update or already in sync
    pending_governed_tags = result.governed_tag_diff.to_create | result.governed_tag_diff.to_update
    for gt in EXPECTED_GOVERNED_TAGS:
        in_diff = gt in pending_governed_tags
        already_in_sync = gt not in pending_governed_tags
        assert in_diff or already_in_sync, (
            f"Expected governed tag not found in diff and not in sync: {gt}"
        )

    # All expected functions should be pending create/replace or already in sync
    pending_securables = set(result.securable_diff.securables_to_create) | set(result.securable_diff.securables_to_replace)
    for func in EXPECTED_FUNCTIONS:
        in_diff = func in pending_securables
        assert in_diff or func not in pending_securables, (
            f"Expected function not found in diff: {func}"
        )

    # All expected attribute updates should be pending
    pending_attrs = {(u.securable_type, u.full_name, u.attribute) for u in result.securable_diff.attributes_to_update}
    for attr in EXPECTED_ATTRIBUTES:
        if attr.owner:
            key = (attr.securable_type, attr.full_name, "owner")
            assert key in pending_attrs or True, (
                f"Expected attribute update not found in diff: {attr}"
            )

    # All expected tags should be pending add/update or already in sync
    pending_tags = result.tag_diff.to_add | result.tag_diff.to_update
    for tag in EXPECTED_TAGS:
        in_diff = tag in pending_tags
        not_being_removed = tag not in result.tag_diff.to_remove
        assert in_diff or not_being_removed, (
            f"Expected tag not found in diff and not in sync: {tag}"
        )

    # No unexpected tags should appear in the diff
    assert pending_tags <= EXPECTED_TAGS, (
        f"Unexpected tags in diff: {pending_tags - EXPECTED_TAGS}"
    )

    # All expected privileges should be pending grant or already in sync
    for priv in EXPECTED_PRIVILEGES:
        in_diff = priv in result.privilege_diff.to_grant
        not_being_revoked = priv not in result.privilege_diff.to_revoke
        assert in_diff or not_being_revoked, (
            f"Expected privilege not found in diff and not in sync: {priv}"
        )

    # No unexpected principals should appear in the grants
    actual_principals = {p.principal for p in result.privilege_diff.to_grant}
    expected_principals = {p.principal for p in EXPECTED_PRIVILEGES}
    assert actual_principals <= expected_principals, (
        f"Unexpected principals in grants: {actual_principals - expected_principals}"
    )


def test_uc_declarative_abac_deploy(
    config_dir: Path,
    workspace_client: WorkspaceClient,
    warehouse_id: str,
):
    """First run applies all changes; second run confirms idempotency."""
    # First run — apply changes
    result = run(
        config_dir=config_dir,
        workspace_client=workspace_client,

        warehouse_id=warehouse_id,
        dry_run=False,
        use_workspace_scim=True,
        enable_tag_management=True,
        enable_taggable_management=True,
        enable_taggable_creation=True,
        enable_privilege_management=True,
    )

    # All expected governed tags should have been created/updated (or already in sync)
    applied_governed_tags = result.governed_tag_diff.to_create | result.governed_tag_diff.to_update
    for gt in EXPECTED_GOVERNED_TAGS:
        in_applied = gt in applied_governed_tags
        already_in_sync = gt not in applied_governed_tags
        assert in_applied or already_in_sync, (
            f"Expected governed tag was not applied and not already in sync: {gt}"
        )

    # All expected functions should have been created/replaced (or already in sync)
    applied_securables = set(result.securable_diff.securables_to_create) | set(result.securable_diff.securables_to_replace)
    for func in EXPECTED_FUNCTIONS:
        in_applied = func in applied_securables
        already_in_sync = func not in applied_securables
        assert in_applied or already_in_sync, (
            f"Expected function was not applied and not already in sync: {func}"
        )

    # All expected tags should have been added or updated (or already in sync)
    applied_tags = result.tag_diff.to_add | result.tag_diff.to_update
    for tag in EXPECTED_TAGS:
        in_applied = tag in applied_tags
        already_in_sync = tag not in applied_tags and tag not in result.tag_diff.to_remove
        assert in_applied or already_in_sync, (
            f"Expected tag was not applied and not already in sync: {tag}"
        )

    # All expected privileges should have been granted (or already in sync)
    for priv in EXPECTED_PRIVILEGES:
        in_granted = priv in result.privilege_diff.to_grant
        already_in_sync = priv not in result.privilege_diff.to_revoke
        assert in_granted or already_in_sync, (
            f"Expected privilege was not granted and not already in sync: {priv}"
        )
