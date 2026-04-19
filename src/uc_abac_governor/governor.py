from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from databricks.sdk import WorkspaceClient

from uc_abac_governor.configs.consolidator import consolidate_resources
from uc_abac_governor.configs.discovery import discover_yaml_files, load_raw_configs
from uc_abac_governor.configs.models import ResourcesConfig
from uc_abac_governor.configs.resolver import resolve_refs
from uc_abac_governor.governed_tags.compiler import compile_desired_governed_tags
from uc_abac_governor.governed_tags.differ import compute_governed_tag_diff
from uc_abac_governor.governed_tags.executor import execute_governed_tag_diff
from uc_abac_governor.governed_tags.state import GovernedTagDiff
from uc_abac_governor.helpers.workspace import WorkspaceHelper
from uc_abac_governor.helpers.unity_catalog import UnityCatalogHelper
from uc_abac_governor.policies.compiler import compile_desired_policies
from uc_abac_governor.policies.differ import compute_policy_diff
from uc_abac_governor.policies.executor import execute_policy_diff
from uc_abac_governor.policies.state import PolicyDiff
from uc_abac_governor.principals.resolver import PrincipalResolver
from uc_abac_governor.privileges.compiler import compile_desired_privileges
from uc_abac_governor.privileges.differ import compute_privilege_diff
from uc_abac_governor.privileges.executor import execute_privilege_diff
from uc_abac_governor.privileges.state import PrivilegeDiff
from uc_abac_governor.securables.compiler import compile_desired_attributes, compile_desired_securables
from uc_abac_governor.securables.differ import compute_securable_diff
from uc_abac_governor.securables.executor import execute_securable_diff
from uc_abac_governor.securables.state import SecurableAttributes, SecurableDiff
from uc_abac_governor.logger import ChangeLogger
from uc_abac_governor.tags.compiler import compile_desired_tags
from uc_abac_governor.tags.differ import compute_tag_diff
from uc_abac_governor.tags.executor import execute_tag_diff
from uc_abac_governor.tags.state import TagDiff
from uc_abac_governor.types import ExecutionBatchError, SecurableType

_logger = logging.getLogger("uc_abac_governor")


@dataclass(frozen=True)
class GovernorDiffsResult:
    """Computed diffs from one ``governor.run()`` invocation, one per domain."""

    securable_diff: SecurableDiff
    governed_tag_diff: GovernedTagDiff
    tag_diff: TagDiff
    policy_diff: PolicyDiff
    privilege_diff: PrivilegeDiff


def _function_attributes_only(attrs: set[SecurableAttributes]) -> set[SecurableAttributes]:
    """Drop non-function attributes — used when --enable-taggable-management is off,
    so the attribute differ only sees FUNCTION owners (functions are engine-managed
    independently of the taggable-management gate)."""
    return {a for a in attrs if a.securable_type == SecurableType.FUNCTION}


def run(
    config_dir: Path,
    workspace_client: WorkspaceClient,
    warehouse_id: str,
    dry_run: bool = False,
    use_workspace_scim: bool = False,
    enable_tag_management: bool = False,
    enable_taggable_management: bool = False,
    enable_taggable_creation: bool = False,
    enable_privilege_management: bool = False,
    enable_governed_tag_deletion: bool = False,
    force: bool = False,
) -> GovernorDiffsResult:
    """Run the full governance pipeline: discover, resolve, compile, diff, apply.

    Returns the computed diffs for every domain in execution order.
    In dry-run mode, diffs are computed but no SQL is executed.

    The three ``enable_*`` flags gate mutation classes. Each defaults to False;
    when unset the corresponding domain is skipped in both dry-run and real-run
    (no fetch, no diff, no log, no execute). ``enable_privilege_management=True``
    with ``enable_tag_management=False`` makes the privileges compiler match its
    grant policies against the on-disk (``actual``) tag state instead of the
    config's desired tags.
    """
    # 1. Discover + load + resolve YAML
    paths = discover_yaml_files(config_dir)
    raw_defs, raw_resources = load_raw_configs(paths)
    resolved = resolve_refs(raw_defs, raw_resources)
    consolidated = consolidate_resources(resolved)
    config = ResourcesConfig.model_validate(consolidated)
    catalog_names = list(config.catalogs.keys())

    # 2. Parallel initial fetch (securables, tags, privileges, and principals concurrently)
    uc_helper = UnityCatalogHelper(workspace_client, warehouse_id)
    ws_helper = WorkspaceHelper(workspace_client, use_workspace_scim=use_workspace_scim)
    change_logger = ChangeLogger(dry_run=dry_run, logger=_logger)
    change_logger.log_banner()
    _logger.info("  Fetching current state from workspace (this can take several minutes)...")
    # actual_tags is needed by either the tags domain (for the diff) or the privileges
    # domain (for policy matching against on-disk tag state when tag management is off).
    need_actual_tags = enable_tag_management or enable_privilege_management
    with ThreadPoolExecutor() as pool:
        actual_securables_f = pool.submit(uc_helper.fetch_actual_securables, catalog_names)
        actual_policies_f = pool.submit(uc_helper.fetch_actual_policies, config)
        actual_governed_tags_f = pool.submit(ws_helper.fetch_actual_governed_tags)
        principals_f = pool.submit(ws_helper.fetch_principals)
        actual_tags_f = pool.submit(uc_helper.fetch_actual_tags, catalog_names) if need_actual_tags else None
        actual_privs_f = pool.submit(uc_helper.fetch_actual_privileges, catalog_names) if enable_privilege_management else None

        actual_securables, actual_attributes = actual_securables_f.result()
        actual_policies = actual_policies_f.result()
        actual_governed_tags = actual_governed_tags_f.result()
        principals_f.result()
        actual_tags = actual_tags_f.result() if actual_tags_f is not None else set()
        actual_privileges = actual_privs_f.result() if actual_privs_f is not None else set()
    _logger.info("  Successfully fetched current state")

    # 3. Construct the shared PrincipalResolver now that ws_helper cache is populated.
    resolver = PrincipalResolver(ws_helper)

    # 4. Securables workflow (before tags and privileges)
    desired_attributes = compile_desired_attributes(config)
    desired_securables = compile_desired_securables(config)
    if not enable_taggable_management:
        # Drop non-function attribute updates on both sides — the engine must not
        # touch catalog/schema/table/volume owners without the taggable-management
        # opt-in. Function attributes flow through because FUNCTION creation /
        # replacement is always engine-managed.
        desired_attributes = _function_attributes_only(desired_attributes)
        actual_attributes = _function_attributes_only(actual_attributes)
    securable_diff = compute_securable_diff(
        desired_attributes, actual_attributes, desired_securables, actual_securables,
        resolver, change_logger,
        enable_taggable_creation=enable_taggable_creation,
    )

    if securable_diff.securables_to_create or securable_diff.securables_to_replace or securable_diff.attributes_to_update:
        change_logger.log_section_header("Securables")
    execute_securable_diff(uc_helper, securable_diff, change_logger, dry_run=dry_run)

    # 4. Governed tags workflow (account-level tag policies — must run before
    # catalog-scoped tag assignments, so new tag keys exist before SET TAGS).
    desired_governed_tags = compile_desired_governed_tags(config)
    governed_tag_diff = compute_governed_tag_diff(
        desired_governed_tags, actual_governed_tags,
        enable_deletion=enable_governed_tag_deletion,
    )

    # 5. Tags workflow
    if enable_tag_management:
        desired_tags = compile_desired_tags(config)
        tag_diff = compute_tag_diff(desired_tags, actual_tags)
        tags_for_privilege_matching = desired_tags
    else:
        tag_diff = TagDiff()
        # When tag management is off the engine will not reconcile the config's
        # desired tags onto UC this run, so the privileges compiler must match
        # its policies against the on-disk tag state to stay honest.
        tags_for_privilege_matching = actual_tags

    # 6. Policies workflow (mask/filter)
    desired_policies = compile_desired_policies(config)
    policy_diff = compute_policy_diff(
        desired_policies, actual_policies, resolver, change_logger,
    )

    # 7. Privileges workflow
    if enable_privilege_management:
        compiled_privileges = compile_desired_privileges(
            config, tags_for_privilege_matching, run_date=date.today(),
        )
        privilege_diff = compute_privilege_diff(
            compiled_privileges, actual_privileges, resolver, change_logger,
        )
    else:
        privilege_diff = PrivilegeDiff()

    # 8. Log and execute (or dry-run)
    if governed_tag_diff.to_create or governed_tag_diff.to_update or governed_tag_diff.to_delete:
        change_logger.log_section_header("Governed tags")
    execute_governed_tag_diff(
        ws_helper, governed_tag_diff, change_logger, dry_run=dry_run, force=force,
    )

    if tag_diff.to_add or tag_diff.to_update or tag_diff.to_remove:
        change_logger.log_section_header("Tags")
    execute_tag_diff(uc_helper, tag_diff, change_logger, dry_run=dry_run)

    if policy_diff.to_create or policy_diff.to_replace:
        change_logger.log_section_header("Policies")
    execute_policy_diff(uc_helper, policy_diff, change_logger, dry_run=dry_run)

    if privilege_diff.to_grant or privilege_diff.to_revoke:
        change_logger.log_section_header("Privileges")
    execute_privilege_diff(uc_helper, privilege_diff, change_logger, dry_run=dry_run)

    change_logger.log_errors_section()
    change_logger.log_summary()

    if change_logger.has_errors:
        raise ExecutionBatchError(change_logger.errors)

    return GovernorDiffsResult(
        securable_diff=securable_diff,
        governed_tag_diff=governed_tag_diff,
        tag_diff=tag_diff,
        policy_diff=policy_diff,
        privilege_diff=privilege_diff,
    )
