from __future__ import annotations

from pathlib import Path

from databricks.sdk import AccountClient, WorkspaceClient

from uc_abac_governor.privileges.state import PrivilegeDiff, SecurablePrivilege
from uc_abac_governor.tags.state import TagDiff


def extract_principals(privileges: set[SecurablePrivilege]) -> list[str]:
    """Extract unique principal names from a set of desired privileges."""
    return list({p.principal for p in privileges})


def run(
    config_dir: Path,
    workspace_client: WorkspaceClient,
    account_client: AccountClient,
    warehouse_id: str,
    dry_run: bool = False,
) -> tuple[TagDiff, PrivilegeDiff]:
    """Run the full governance pipeline: discover, resolve, compile, diff, apply.

    Returns the computed (TagDiff, PrivilegeDiff) for both domains.
    In dry-run mode, diffs are computed but no SQL is executed.
    """
    raise NotImplementedError
