from __future__ import annotations

import argparse
import logging
from pathlib import Path

from databricks.sdk import WorkspaceClient

from uc_declarative_abac.orchestrator import run

_logger = logging.getLogger("uc_declarative_abac")


def _resolve_namespace_flag(
    parser: argparse.ArgumentParser,
    old_value: str | None,
    new_value: str | None,
    old_flag: str,
    new_flag: str,
) -> str:
    """Resolve a namespace filter from its new flag and its deprecated alias.

    Fails immediately (``parser.error``, exit code 2) if both are given. If only
    the deprecated alias is set, logs a deprecation warning and returns its
    value. Otherwise returns the new value, or ``"*"`` (all configured catalogs)
    when neither is given.
    """
    if old_value is not None and new_value is not None:
        parser.error(
            f"{old_flag} is deprecated and cannot be combined with {new_flag}. "
            f"Use {new_flag} only."
        )
    if old_value is not None:
        _logger.warning(
            "%s is deprecated; use %s instead. Treating it as %s for this run.",
            old_flag, new_flag, new_flag,
        )
        return old_value
    if new_value is not None:
        return new_value
    return "*"


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
        help="Fetch principals from the workspace SCIM API instead of the account SCIM proxy (default: account). The 'account users' and 'account admins' system groups are automatically included, since the workspace SCIM API does not surface them. Incompatible with configuring groups under resources.groups (group management requires the account SCIM proxy).",
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
        "--manage-tags-for-namespaces",
        type=str,
        default=None,
        help="Comma-separated catalog names or qualified schema names (<catalog>.<schema>) to scope tag management to (default = all configured catalogs). No effect unless --enable-tag-management is set.",
    )
    parser.add_argument(
        "--manage-privileges-for-namespaces",
        type=str,
        default=None,
        help="Comma-separated catalog names or qualified schema names (<catalog>.<schema>) to scope privilege management to (default = all configured catalogs). No effect unless --enable-privilege-management is set.",
    )
    parser.add_argument(
        "--manage-taggables-for-namespaces",
        type=str,
        default=None,
        help="Comma-separated catalog names or qualified schema names (<catalog>.<schema>) to scope taggable attribute updates (e.g. owner) to (default = all configured catalogs). Function attributes always flow through. No effect unless --enable-taggable-management is set.",
    )
    parser.add_argument(
        "--create-taggables-for-namespaces",
        type=str,
        default=None,
        help="Comma-separated catalog names or qualified schema names (<catalog>.<schema>) to scope creation of missing catalogs/schemas/tables/volumes to (default = all configured catalogs). Function creation always flows through. No effect unless --enable-taggable-creation is set.",
    )
    # Deprecated aliases (hidden from --help). Passing one logs a deprecation
    # warning and is converted to its --*-for-namespaces equivalent; passing an
    # alias together with its new flag fails immediately. default=None lets us
    # detect explicit use.
    parser.add_argument(
        "--manage-tags-for-catalogs", type=str, default=None, help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--manage-privileges-for-catalogs", type=str, default=None, help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--manage-taggables-for-catalogs", type=str, default=None, help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--create-taggables-for-catalogs", type=str, default=None, help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--retain-tag-prefixes",
        type=str,
        default="class.",
        help="Comma-separated tag-key prefixes that must never be removed from securables, "
             "even when absent from config (the engine may still add/update them). Defaults "
             "to 'class.' to protect UC auto data classification tags. Pass an empty string "
             "to allow removing any unconfigured tag.",
    )
    parser.add_argument(
        "--ignore-unresolvable-principals",
        type=str,
        default="",
        help="Comma-separated list of actual-state principal identifiers — usernames for users, "
             "application_ids for service principals, display names for groups — whose "
             "resolution-failure warning should be suppressed. Primarily for "
             "Databricks-managed system service principals that appear in system tables but aren't "
             "resolvable via SCIM, which otherwise log a warning every run. Empty by default.",
    )
    parser.add_argument(
        "--enable-group-creation",
        action="store_true",
        default=False,
        help="Permit the engine to create account groups declared under "
             "resources.groups that don't yet exist, with their configured members "
             "(the engine automatically gets the MANAGER role on groups it creates). "
             "Off by default. Independent of --enable-group-management: this flag "
             "only creates missing groups; managing the membership of existing "
             "groups requires --enable-group-management.",
    )
    parser.add_argument(
        "--enable-group-management",
        action="store_true",
        default=False,
        help="Permit the engine to reconcile the membership of existing account "
             "groups declared under resources.groups — adding configured members "
             "and removing members absent from config (an empty members list "
             "removes all). Off by default. Requires the engine principal to hold "
             "the MANAGER role on each managed group. Does not create missing "
             "groups (use --enable-group-creation for that).",
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
        default=8,
        help="Max worker threads used per (securable_type, change_type) execution batch. "
             "Default 8. Set to 1 to disable parallelism and force sequential execution.",
    )

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    manage_tags_for_namespaces = _resolve_namespace_flag(
        parser, args.manage_tags_for_catalogs, args.manage_tags_for_namespaces,
        "--manage-tags-for-catalogs", "--manage-tags-for-namespaces",
    )
    manage_privileges_for_namespaces = _resolve_namespace_flag(
        parser, args.manage_privileges_for_catalogs, args.manage_privileges_for_namespaces,
        "--manage-privileges-for-catalogs", "--manage-privileges-for-namespaces",
    )
    manage_taggables_for_namespaces = _resolve_namespace_flag(
        parser, args.manage_taggables_for_catalogs, args.manage_taggables_for_namespaces,
        "--manage-taggables-for-catalogs", "--manage-taggables-for-namespaces",
    )
    create_taggables_for_namespaces = _resolve_namespace_flag(
        parser, args.create_taggables_for_catalogs, args.create_taggables_for_namespaces,
        "--create-taggables-for-catalogs", "--create-taggables-for-namespaces",
    )

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
        enable_group_creation=args.enable_group_creation,
        enable_group_management=args.enable_group_management,
        ignore_unresolvable_principals=args.ignore_unresolvable_principals,
        manage_tags_for_namespaces=manage_tags_for_namespaces,
        manage_privileges_for_namespaces=manage_privileges_for_namespaces,
        manage_taggables_for_namespaces=manage_taggables_for_namespaces,
        create_taggables_for_namespaces=create_taggables_for_namespaces,
        retain_tag_prefixes=args.retain_tag_prefixes,
        force=args.force,
        ref_override_strategy=args.ref_override_strategy,
        max_parallel_changes=args.max_parallel_changes,
    )


if __name__ == "__main__":
    main()
