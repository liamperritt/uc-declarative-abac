from __future__ import annotations

import argparse
import sys
from pathlib import Path

from databricks.sdk import AccountClient, WorkspaceClient

from uc_governor.governor import run


def main() -> None:
    parser = argparse.ArgumentParser(
        description="UC Governor — declarative ABAC governance for Unity Catalog",
    )
    parser.add_argument(
        "--config-dir",
        type=Path,
        required=True,
        help="Path to the YAML config directory",
    )
    parser.add_argument(
        "--warehouse-id",
        type=str,
        required=True,
        help="SQL warehouse ID for executing queries",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned changes without executing",
    )

    args = parser.parse_args()

    workspace_client = WorkspaceClient()
    account_client = AccountClient()

    tag_diff, privilege_diff = run(
        config_dir=args.config_dir,
        workspace_client=workspace_client,
        account_client=account_client,
        warehouse_id=args.warehouse_id,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
