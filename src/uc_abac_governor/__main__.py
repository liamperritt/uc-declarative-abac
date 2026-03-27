from __future__ import annotations

import argparse
import logging
from pathlib import Path

from databricks.sdk import WorkspaceClient

from uc_abac_governor.governor import run


def main() -> None:
    parser = argparse.ArgumentParser(
        description="UC ABAC Governor — declarative ABAC governance for Unity Catalog",
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
        "--profile",
        type=str,
        default=None,
        help="Databricks CLI profile name (from ~/.databrickscfg)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned changes without executing",
    )
    parser.add_argument(
        "--use-workspace-scim",
        action="store_true",
        help="Fetch principals from the workspace SCIM API instead of the account SCIM proxy (default: account)",
    )

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    workspace_client = WorkspaceClient(profile=args.profile)

    run(
        config_dir=args.config_dir,
        workspace_client=workspace_client,
        warehouse_id=args.warehouse_id,
        dry_run=args.dry_run,
        use_workspace_scim=args.use_workspace_scim,
    )


if __name__ == "__main__":
    main()
