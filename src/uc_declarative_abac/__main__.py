from __future__ import annotations

import argparse
import logging
from pathlib import Path

from databricks.sdk import WorkspaceClient

from uc_declarative_abac.orchestrator import run


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
        "--manage-tags-for-catalogs",
        type=str,
        default="*",
        help="Comma-separated catalog names to scope tag management to (default '*' = all configured catalogs). No effect unless --enable-tag-management is set.",
    )
    parser.add_argument(
        "--manage-privileges-for-catalogs",
        type=str,
        default="*",
        help="Comma-separated catalog names to scope privilege management to (default '*' = all configured catalogs). No effect unless --enable-privilege-management is set.",
    )
    parser.add_argument(
        "--manage-taggables-for-catalogs",
        type=str,
        default="*",
        help="Comma-separated catalog names to scope taggable attribute updates (e.g. owner) to (default '*' = all configured catalogs). Function attributes always flow through. No effect unless --enable-taggable-management is set.",
    )
    parser.add_argument(
        "--create-taggables-for-catalogs",
        type=str,
        default="*",
        help="Comma-separated catalog names to scope creation of missing catalogs/schemas/tables/volumes to (default '*' = all configured catalogs). Function creation always flows through. No effect unless --enable-taggable-creation is set.",
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
    parser.add_argument(
        "--ref-override-strategy",
        type=str,
        choices=["merge", "replace"],
        default="merge",
        help="How sibling fields on a $ref entry combine with the referenced definition. "
             "'merge' (default) recursively deep-merges maps and lists; 'replace' shallowly "
             "replaces top-level keys (legacy behaviour).",
    )
    parser.add_argument(
        "--max-parallel-changes",
        type=int,
        default=16,
        help="Max worker threads used per (securable_type, change_type) execution batch. "
             "Default 16. Set to 1 to disable parallelism and force sequential execution.",
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
        manage_tags_for_catalogs=args.manage_tags_for_catalogs,
        manage_privileges_for_catalogs=args.manage_privileges_for_catalogs,
        manage_taggables_for_catalogs=args.manage_taggables_for_catalogs,
        create_taggables_for_catalogs=args.create_taggables_for_catalogs,
        force=args.force,
        ref_override_strategy=args.ref_override_strategy,
        max_parallel_changes=args.max_parallel_changes,
    )


if __name__ == "__main__":
    main()
