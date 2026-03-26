from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from databricks.sdk import WorkspaceClient

from uc_governor.discovery import discover_yaml_files, load_raw_configs
from uc_governor.helpers.workspace import WorkspaceHelper
from uc_governor.helpers.unity_catalog import UnityCatalogHelper
from uc_governor.models import ConfigFile
from uc_governor.privileges.compiler import compile_desired_privileges
from uc_governor.privileges.differ import compute_privilege_diff
from uc_governor.privileges.executor import execute_privilege_diff
from uc_governor.privileges.state import PrivilegeDiff, SecurablePrivilege
from uc_governor.resolver import resolve_refs
from uc_governor.logger import ChangeLogger
from uc_governor.tags.compiler import compile_desired_tags
from uc_governor.tags.differ import compute_tag_diff
from uc_governor.tags.executor import execute_tag_diff
from uc_governor.tags.state import TagDiff
from uc_governor.types import ExecutionBatchError, ExecutionError, PrincipalValidationError


def _extract_principals(privileges: set[SecurablePrivilege]) -> list[str]:
    """Extract unique principal display names from a set of desired privileges."""
    return list({p.principal.name for p in privileges})


def _try_resolve_identifier(ws_helper: WorkspaceHelper, identifier: str) -> bool:
    """Return True if the identifier can be resolved to a known principal."""
    try:
        ws_helper.resolve_by_identifier(identifier)
        return True
    except PrincipalValidationError:
        return False


def _resolve_privileges(
    ws_helper: WorkspaceHelper,
    desired_privileges: set[SecurablePrivilege],
    actual_privileges: set[SecurablePrivilege],
    change_logger: ChangeLogger,
) -> tuple[set[SecurablePrivilege], set[SecurablePrivilege]]:
    """Resolve string principals to Principal objects for both desired and actual privileges.

    Unknown desired principals are logged as errors and excluded.
    Actual principals that cannot be resolved (e.g. deleted users) are silently excluded.
    Returns (resolved_desired, resolved_actual).
    """
    unknown = set(ws_helper.find_unknown_principals(_extract_principals(desired_privileges)))
    for name in unknown:
        change_logger.log_error(ExecutionError(
            context=f"Validate principal '{name}'",
            exception=PrincipalValidationError(f"Principal '{name}' not found in workspace"),
        ))

    resolved_desired = {
        SecurablePrivilege(
            securable_type=p.securable_type,
            securable_full_name=p.securable_full_name,
            principal=ws_helper.resolve_by_name(p.principal.name),
            privilege_type=p.privilege_type,
        )
        for p in desired_privileges
        if p.principal.name not in unknown
    }

    resolved_actual = {
        SecurablePrivilege(
            securable_type=p.securable_type,
            securable_full_name=p.securable_full_name,
            principal=ws_helper.resolve_by_identifier(p.principal),
            privilege_type=p.privilege_type,
        )
        for p in actual_privileges
        if _try_resolve_identifier(ws_helper, p.principal)
    }

    return resolved_desired, resolved_actual


def run(
    config_dir: Path,
    workspace_client: WorkspaceClient,
    warehouse_id: str,
    dry_run: bool = False,
) -> tuple[TagDiff, PrivilegeDiff]:
    """Run the full governance pipeline: discover, resolve, compile, diff, apply.

    Returns the computed (TagDiff, PrivilegeDiff) for both domains.
    In dry-run mode, diffs are computed but no SQL is executed.
    """
    # 1. Discover + load + resolve YAML
    paths = discover_yaml_files(config_dir)
    raw_defs, raw_resources = load_raw_configs(paths)
    resolved = resolve_refs(raw_defs, raw_resources)
    config = ConfigFile.model_validate(resolved)
    catalog_names = list(config.catalogs.keys())

    # 2. Parallel initial fetch (tags, privileges, and principals concurrently)
    change_logger = ChangeLogger(dry_run=dry_run)
    uc_helper = UnityCatalogHelper(workspace_client, warehouse_id)
    ws_helper = WorkspaceHelper(workspace_client)
    with ThreadPoolExecutor() as pool:
        actual_tags_f = pool.submit(uc_helper.fetch_actual_tags, catalog_names)
        actual_privs_f = pool.submit(uc_helper.fetch_actual_privileges, catalog_names)
        principals_f = pool.submit(ws_helper.fetch_principals)
        actual_tags = actual_tags_f.result()
        actual_privileges = actual_privs_f.result()
        principals_f.result()

    # 3. Tags workflow
    desired_tags = compile_desired_tags(config)
    tag_diff = compute_tag_diff(desired_tags, actual_tags)

    # 4. Privileges workflow — resolve string principals to Principal objects
    desired_privileges = compile_desired_privileges(config, desired_tags)
    resolved_desired, resolved_actual = _resolve_privileges(
        ws_helper, desired_privileges, actual_privileges, change_logger,
    )
    privilege_diff = compute_privilege_diff(resolved_desired, resolved_actual)

    # 5. Log and execute (sequential)
    if not dry_run:
        execute_tag_diff(uc_helper, tag_diff, change_logger)
        execute_privilege_diff(uc_helper, privilege_diff, change_logger)
    else:
        change_logger.log_tag_changes(tag_diff)
        change_logger.log_privilege_changes(privilege_diff)
    change_logger.log_summary()

    if change_logger.has_errors:
        raise ExecutionBatchError(change_logger.errors)

    return tag_diff, privilege_diff
