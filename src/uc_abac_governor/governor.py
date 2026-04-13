from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from pathlib import Path

from databricks.sdk import WorkspaceClient

from uc_abac_governor.configs.consolidator import consolidate_resources
from uc_abac_governor.configs.discovery import discover_yaml_files, load_raw_configs
from uc_abac_governor.configs.models import ResourcesConfig
from uc_abac_governor.configs.resolver import resolve_refs
from uc_abac_governor.helpers.workspace import WorkspaceHelper
from uc_abac_governor.helpers.unity_catalog import UnityCatalogHelper
from uc_abac_governor.privileges.compiler import compile_desired_privileges
from uc_abac_governor.privileges.differ import compute_privilege_diff
from uc_abac_governor.privileges.executor import execute_privilege_diff
from uc_abac_governor.privileges.state import PrivilegeDiff, SecurablePrivilege, UnresolvedPrivilege
from uc_abac_governor.logger import ChangeLogger
from uc_abac_governor.tags.compiler import compile_desired_tags
from uc_abac_governor.tags.differ import compute_tag_diff
from uc_abac_governor.tags.executor import execute_tag_diff
from uc_abac_governor.tags.state import TagDiff
from uc_abac_governor.types import (
    ExecutionBatchError,
    ExecutionError,
    PrincipalValidationError,
)

_logger = logging.getLogger("uc_abac_governor")


def _resolve_compiled_privileges(
    compiled: set[UnresolvedPrivilege],
    ws_helper: WorkspaceHelper,
    change_logger: ChangeLogger,
) -> set[SecurablePrivilege]:
    """Resolve compiled privileges to SecurablePrivileges with Principal objects.

    Unknown principals (not in the workspace) are logged as errors and excluded.
    """
    principals = ws_helper.get_principals()
    resolved: set[SecurablePrivilege] = set()
    unknown: set[str] = set()

    for cp in compiled:
        principal = principals.get(cp.principal)
        if principal is None:
            if cp.principal not in unknown:
                unknown.add(cp.principal)
                change_logger.log_error(ExecutionError(
                    context=f"Validate principal '{cp.principal}'",
                    exception=PrincipalValidationError(
                        f"Principal '{cp.principal}' not found in workspace"
                    ),
                ))
            continue
        resolved.add(SecurablePrivilege(
            securable_type=cp.securable_type,
            securable_full_name=cp.securable_full_name,
            principal=principal,
            privilege_type=cp.privilege_type,
        ))

    return resolved


def _resolve_actual_privileges(
    actual_privileges: set[UnresolvedPrivilege],
    ws_helper: WorkspaceHelper,
) -> set[SecurablePrivilege]:
    """Resolve unresolved actual privileges (string principals) to Principal objects.

    Actual privileges with unrecognised principals (e.g. deleted users) are
    logged as errors and excluded.
    """
    resolved: set[SecurablePrivilege] = set()
    for p in actual_privileges:
        try:
            principal = ws_helper.resolve_by_identifier(p.principal)
        except PrincipalValidationError:
            _logger.error(f"Skipping actual privilege: unknown principal '{p.principal}'")
            continue
        resolved.add(SecurablePrivilege(
            securable_type=p.securable_type,
            securable_full_name=p.securable_full_name,
            principal=principal,
            privilege_type=p.privilege_type,
        ))
    return resolved


def run(
    config_dir: Path,
    workspace_client: WorkspaceClient,
    warehouse_id: str,
    dry_run: bool = False,
    use_workspace_scim: bool = False,
) -> tuple[TagDiff, PrivilegeDiff]:
    """Run the full governance pipeline: discover, resolve, compile, diff, apply.

    Returns the computed (TagDiff, PrivilegeDiff) for both domains.
    In dry-run mode, diffs are computed but no SQL is executed.
    """
    # 1. Discover + load + resolve YAML
    paths = discover_yaml_files(config_dir)
    raw_defs, raw_resources = load_raw_configs(paths)
    resolved = resolve_refs(raw_defs, raw_resources)
    consolidated = consolidate_resources(resolved)
    config = ResourcesConfig.model_validate(consolidated)
    catalog_names = list(config.catalogs.keys())

    # 2. Parallel initial fetch (tags, privileges, and principals concurrently)
    uc_helper = UnityCatalogHelper(workspace_client, warehouse_id)
    ws_helper = WorkspaceHelper(workspace_client, use_workspace_scim=use_workspace_scim)
    change_logger = ChangeLogger(dry_run=dry_run, logger=_logger)
    change_logger.log_banner()
    _logger.info("  Fetching current state from workspace (this can take several minutes)...")
    with ThreadPoolExecutor() as pool:
        actual_tags_f = pool.submit(uc_helper.fetch_actual_tags, catalog_names)
        actual_privs_f = pool.submit(uc_helper.fetch_actual_privileges, catalog_names)
        principals_f = pool.submit(ws_helper.fetch_principals)
        actual_tags = actual_tags_f.result()
        actual_privileges = actual_privs_f.result()
        principals_f.result()
    _logger.info("  Successfully fetched current state")
    _logger.info("")

    # 3. Tags workflow
    desired_tags = compile_desired_tags(config)
    tag_diff = compute_tag_diff(desired_tags, actual_tags)

    # 4. Privileges workflow
    compiled_privileges = compile_desired_privileges(config, desired_tags, run_date=date.today())
    resolved_desired = _resolve_compiled_privileges(compiled_privileges, ws_helper, change_logger)
    resolved_actual = _resolve_actual_privileges(actual_privileges, ws_helper)
    privilege_diff = compute_privilege_diff(resolved_desired, resolved_actual)

    # 5. Log and execute (sequential)
    if not dry_run:
        if tag_diff.to_add or tag_diff.to_update or tag_diff.to_remove:
            change_logger.log_section_header("Tags")
        execute_tag_diff(uc_helper, tag_diff, change_logger)
        if privilege_diff.to_grant or privilege_diff.to_revoke:
            change_logger.log_section_header("Privileges")
        execute_privilege_diff(uc_helper, privilege_diff, change_logger)
    else:
        change_logger.log_tag_changes(tag_diff)
        change_logger.log_privilege_changes(privilege_diff)
    change_logger.log_errors_section()
    change_logger.log_summary()

    if change_logger.has_errors:
        raise ExecutionBatchError(change_logger.errors)

    return tag_diff, privilege_diff
