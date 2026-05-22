from __future__ import annotations

import argparse
import logging
from pathlib import Path

from databricks.sdk import WorkspaceClient

from uc_declarative_abac.governor import run


def main() -> None:
    parser = argparse.ArgumentParser(
        description="UC Declarative ABAC  — declarative ABAC governance for Unity Catalog",
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
    parser.add_argument(
        "--enable-tag-management",
        action="store_true",
        default=False,
        help="Permit the engine to create/update/remove tag assignments on securables. Off by default.",
    )
    parser.add_argument(
        "--enable-privilege-management",
        action="store_true",
        default=False,
        help="Permit the engine to GRANT/REVOKE privileges via SQL. Off by default.",
    )
    parser.add_argument(
        "--enable-taggable-management",
        action="store_true",
        default=False,
        help="Permit the engine to update attributes (e.g. owner) on existing catalogs, schemas, tables, and volumes. Off by default.",
    )
    parser.add_argument(
        "--enable-taggable-creation",
        action="store_true",
        default=False,
        help="Permit the engine to create catalogs, schemas, tables, and volumes declared in config but absent from UC. Off by default.",
    )
    parser.add_argument(
        "--enable-governed-tag-deletion",
        action="store_true",
        default=False,
        help="Permit the engine to delete governed tags (account-level tag policies) "
             "that exist in the account but are absent from config. Off by default. "
             "Requires interactive confirmation at the terminal unless --force is set.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Skip every interactive confirmation prompt and auto-confirm destructive "
             "actions. Required in non-interactive CI contexts if any destructive gate "
             "(e.g. --enable-governed-tag-deletion) is set.",
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
        enable_tag_management=args.enable_tag_management,
        enable_taggable_management=args.enable_taggable_management,
        enable_taggable_creation=args.enable_taggable_creation,
        enable_privilege_management=args.enable_privilege_management,
        enable_governed_tag_deletion=args.enable_governed_tag_deletion,
        force=args.force,
    )


if __name__ == "__main__":
    main()
