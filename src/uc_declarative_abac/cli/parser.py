from __future__ import annotations

import argparse
import sys
from pathlib import Path

from uc_declarative_abac.cli import __version__
from uc_declarative_abac.cli.presentation import CliArgumentParser, HelpExample

_SUBCOMMANDS = frozenset({"validate", "deploy"})
_DESCRIPTION = "UC Declarative ABAC — declarative ABAC governance for Unity Catalog"
_VALIDATE_EXAMPLE = "uc-abac validate --config-dir ./configs"
_VALIDATE_PROFILE_EXAMPLE = "uc-abac validate --config-dir ./configs --profile staging"
_DEPLOY_DRY_RUN_EXAMPLE = (
    "uc-abac deploy --config-dir ./configs --warehouse-id <id> --dry-run"
)
_DEPLOY_EXAMPLE = "uc-abac deploy --config-dir ./configs --warehouse-id <id>"


def _add_common_run_arguments(parser: argparse.ArgumentParser) -> None:
    """Register optional run flags shared by validate, deploy, and legacy mode."""
    parser.add_argument(
        "--profile",
        type=str,
        default=argparse.SUPPRESS,
        help="Databricks CLI profile name (from ~/.databrickscfg)",
    )
    parser.add_argument(
        "--system-catalog",
        type=str,
        default=argparse.SUPPRESS,
        help="Catalog containing Unity Catalog system tables [default: system].",
    )
    parser.add_argument(
        "--use-workspace-scim",
        action="store_true",
        default=argparse.SUPPRESS,
        help=(
            "Fetch principals from the workspace SCIM API instead of the account SCIM proxy "
            "(default: account). The 'account users' and 'account admins' system groups are "
            "automatically included, since the workspace SCIM API does not surface them. "
            "Incompatible with configuring groups under resources.groups (group management "
            "requires the account SCIM proxy)."
        ),
    )
    parser.add_argument(
        "--skip-users-fetch",
        action="store_true",
        default=argparse.SUPPRESS,
        help=(
            "Skip listing account/workspace users and treat the user set as empty. "
            "For organisations that govern access only via groups and service principals, "
            "this avoids the slowest SCIM list call and speeds up the initial fetch "
            "significantly in accounts with many users. It is useful when running interactively "
            "for a faster fetch time, but it is not intended for production use."
        ),
    )
    parser.add_argument(
        "--enable-tag-management",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Permit the engine to create/update/remove tag assignments on securables. Off by default.",
    )
    parser.add_argument(
        "--enable-privilege-management",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Permit the engine to GRANT/REVOKE privileges via SQL. Off by default.",
    )
    parser.add_argument(
        "--enable-taggable-management",
        action="store_true",
        default=argparse.SUPPRESS,
        help=(
            "Permit the engine to update attributes (e.g. owner) on existing catalogs, schemas, "
            "tables, and volumes. Off by default."
        ),
    )
    parser.add_argument(
        "--enable-taggable-creation",
        action="store_true",
        default=argparse.SUPPRESS,
        help=(
            "Permit the engine to create catalogs, schemas, tables, and volumes declared in "
            "config but absent from UC. Off by default."
        ),
    )
    parser.add_argument(
        "--manage-tags-for-namespaces",
        type=str,
        metavar="NAMESPACES",
        default=argparse.SUPPRESS,
        help=(
            "Comma-separated catalog names or qualified schema names (<catalog>.<schema>) to "
            "scope tag management to (default = all configured catalogs). No effect unless "
            "--enable-tag-management is set."
        ),
    )
    parser.add_argument(
        "--manage-privileges-for-namespaces",
        type=str,
        metavar="NAMESPACES",
        default=argparse.SUPPRESS,
        help=(
            "Comma-separated catalog names or qualified schema names (<catalog>.<schema>) to "
            "scope privilege management to (default = all configured catalogs). No effect "
            "unless --enable-privilege-management is set."
        ),
    )
    parser.add_argument(
        "--manage-taggables-for-namespaces",
        type=str,
        metavar="NAMESPACES",
        default=argparse.SUPPRESS,
        help=(
            "Comma-separated catalog names or qualified schema names (<catalog>.<schema>) to "
            "scope taggable attribute updates (e.g. owner) to (default = all configured "
            "catalogs). Function attributes always flow through. No effect unless "
            "--enable-taggable-management is set."
        ),
    )
    parser.add_argument(
        "--create-taggables-for-namespaces",
        type=str,
        metavar="NAMESPACES",
        default=argparse.SUPPRESS,
        help=(
            "Comma-separated catalog names or qualified schema names (<catalog>.<schema>) to "
            "scope creation of missing catalogs/schemas/tables/volumes to (default = all "
            "configured catalogs). Function creation always flows through. No effect unless "
            "--enable-taggable-creation is set."
        ),
    )
    parser.add_argument(
        "--delete-policies-for-namespaces",
        type=str,
        metavar="NAMESPACES",
        default=argparse.SUPPRESS,
        help=(
            "Comma-separated catalog names or qualified schema names (<catalog>.<schema>) to "
            "scope policy deletion to (default = all configured catalogs). No effect unless "
            "--enable-policy-deletion is set."
        ),
    )
    parser.add_argument(
        "--manage-tags-for-catalogs",
        type=str,
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--manage-privileges-for-catalogs",
        type=str,
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--manage-taggables-for-catalogs",
        type=str,
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--create-taggables-for-catalogs",
        type=str,
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--retain-tag-prefixes",
        type=str,
        default=argparse.SUPPRESS,
        help=(
            "Comma-separated tag-key prefixes that must never be removed from securables, "
            "even when absent from config (the engine may still add/update them). Defaults "
            "to 'class.' to protect UC auto data classification tags. Pass an empty string "
            "to allow removing any unconfigured tag."
        ),
    )
    parser.add_argument(
        "--ignore-unresolvable-principals",
        type=str,
        metavar="IDENTIFIERS",
        default=argparse.SUPPRESS,
        help=(
            "Comma-separated list of actual-state principal identifiers — usernames for users, "
            "application_ids for service principals, display names for groups — whose "
            "resolution-failure warning should be suppressed. Primarily for "
            "Databricks-managed system service principals that appear in system tables but aren't "
            "resolvable via SCIM, which otherwise log a warning every run. Empty by default."
        ),
    )
    parser.add_argument(
        "--enable-group-creation",
        action="store_true",
        default=argparse.SUPPRESS,
        help=(
            "Permit the engine to create account groups declared under resources.groups that "
            "don't yet exist, with their configured members (the engine automatically gets the "
            "MANAGER role on groups it creates). Off by default. Independent of "
            "--enable-group-management: this flag only creates missing groups; managing the "
            "membership of existing groups requires --enable-group-management."
        ),
    )
    parser.add_argument(
        "--enable-group-management",
        action="store_true",
        default=argparse.SUPPRESS,
        help=(
            "Permit the engine to reconcile the membership of existing account groups declared "
            "under resources.groups — adding configured members and removing members absent "
            "from config (an empty members list removes all). Off by default. Requires the "
            "engine principal to hold the MANAGER role on each managed group. Does not create "
            "missing groups (use --enable-group-creation for that)."
        ),
    )
    parser.add_argument(
        "--enable-group-deletion",
        action="store_true",
        default=argparse.SUPPRESS,
        help=(
            "Make config authoritative over account group existence: delete any "
            "Databricks-managed account group absent from resources.groups. Off by "
            "default. Only operates on Databricks-managed groups — external "
            "(IdP-provisioned) groups and account system groups (account users, account "
            "admins) are never deleted. Requires --enable-group-creation and at least one "
            "group declared under resources.groups. Requires interactive confirmation at "
            "the terminal unless --force is set."
        ),
    )
    parser.add_argument(
        "--enable-governed-tag-deletion",
        action="store_true",
        default=argparse.SUPPRESS,
        help=(
            "Permit the engine to delete governed tags (account-level tag policies) that exist "
            "in the account but are absent from config. Off by default. Requires interactive "
            "confirmation at the terminal unless --force is set."
        ),
    )
    parser.add_argument(
        "--enable-policy-deletion",
        action="store_true",
        default=argparse.SUPPRESS,
        help=(
            "Make config authoritative over mask/filter policies within the in-scope catalogs: "
            "any actual policy discovered on an in-scope securable but not declared in config is "
            "deleted, regardless of whether that securable declares a 'policies' list. Actual "
            "policies are discovered via the abac_policy_definitions system table and scoped by "
            "--delete-policies-for-namespaces. Off by default. Requires interactive confirmation "
            "at the terminal unless --force is set."
        ),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        default=argparse.SUPPRESS,
        help=(
            "Skip every interactive confirmation prompt and auto-confirm destructive actions. "
            "Required in non-interactive CI contexts if any destructive gate "
            "(e.g. --enable-governed-tag-deletion) is set."
        ),
    )
    parser.add_argument(
        "--ref-override-strategy",
        type=str,
        choices=["merge", "replace"],
        default=argparse.SUPPRESS,
        help=(
            "How sibling fields on a $ref entry combine with the referenced definition. "
            "'merge' recursively deep-merges maps and lists; 'replace' shallowly "
            "replaces top-level keys (legacy behaviour) [default: merge]."
        ),
    )
    parser.add_argument(
        "--max-parallel-changes",
        type=int,
        default=argparse.SUPPRESS,
        help=(
            "Worker threads per execution batch [default: 8]. Set to 1 to disable "
            "parallelism and force sequential execution."
        ),
    )


def _build_common_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    _add_common_run_arguments(parser)
    return parser


def _add_global_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--settings-file",
        type=Path,
        default=argparse.SUPPRESS,
        help="Path to a YAML settings file (default: ./uc_abac.yml when present).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Print full tracebacks on failure.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Suppress non-error log output.",
    )


def _add_config_dir(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config-dir",
        type=Path,
        default=argparse.SUPPRESS,
        help="Path to the YAML config directory",
    )


def _add_version(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )


def _cli_parser(**kwargs) -> CliArgumentParser:
    return CliArgumentParser(
        prog="uc-abac",
        description=_DESCRIPTION,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        **kwargs,
    )


def _build_modern_parser() -> argparse.ArgumentParser:
    common = _build_common_parser()
    parser = _cli_parser(
        product_name="UC Declarative ABAC",
        version=__version__,
        examples=(
            HelpExample(_VALIDATE_EXAMPLE, "Validate local YAML configuration."),
            HelpExample(
                _DEPLOY_DRY_RUN_EXAMPLE,
                "Preview changes before deploying to Unity Catalog.",
            ),
        ),
    )
    _add_version(parser)
    _add_global_arguments(parser)

    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser(
        "validate",
        parents=[common],
        help="Parse, resolve, and validate YAML configs without contacting Databricks.",
        description="Validate YAML configs locally (no warehouse or credentials required).",
        options_title="FLAGS:",
        examples=(
            HelpExample(_VALIDATE_EXAMPLE, "Validate the default local configuration."),
            HelpExample(
                _VALIDATE_PROFILE_EXAMPLE,
                "Validate using settings for the staging profile.",
            ),
        ),
    )
    _add_config_dir(validate_parser)
    validate_parser.set_defaults(command="validate")

    deploy_parser = subparsers.add_parser(
        "deploy",
        parents=[common],
        help="Deploy governance changes (use --dry-run to preview).",
        description="Deploy declarative governance to Unity Catalog.",
        options_title="FLAGS:",
        examples=(
            HelpExample(
                _DEPLOY_DRY_RUN_EXAMPLE,
                "Preview the changes without applying them.",
            ),
            HelpExample(_DEPLOY_EXAMPLE, "Apply the configured governance changes."),
        ),
    )
    _add_config_dir(deploy_parser)
    deploy_parser.add_argument(
        "--warehouse-id",
        type=str,
        default=argparse.SUPPRESS,
        help="SQL warehouse ID for executing queries",
    )
    deploy_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Print the planned changes without executing them.",
    )
    deploy_parser.set_defaults(command="deploy")

    return parser


def _build_legacy_parser() -> argparse.ArgumentParser:
    parser = _cli_parser()
    _add_version(parser)
    _add_global_arguments(parser)
    _add_common_run_arguments(parser)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Print planned changes without executing (deprecated: use 'deploy --dry-run').",
    )
    # Not required at the argparse layer: like the modern subcommands, these may
    # be supplied via env vars or the settings file. A genuinely missing value is
    # caught after settings resolution (_require_config_dir / _require_warehouse_id
    # -> OrchestratorError -> exit 3), matching the deploy subcommand's behaviour.
    _add_config_dir(parser)
    parser.add_argument(
        "--warehouse-id",
        type=str,
        default=argparse.SUPPRESS,
        help="SQL warehouse ID for executing queries",
    )
    return parser


# Global flags that may legitimately precede a subcommand in modern mode.
# Store-true globals consume no value; --settings-file consumes one value token
# in its split form ("--settings-file path"). The "=" form ("--settings-file=x")
# is a single token. Any *other* leading option means this is not a modern
# "[globals] <subcommand> ..." invocation, so it is treated as the legacy flat form.
_STORE_TRUE_GLOBAL_FLAGS = frozenset(
    {"--verbose", "--quiet", "--version", "-h", "--help"}
)
_VALUE_TAKING_GLOBAL_FLAGS = frozenset({"--settings-file"})


def _is_legacy_invocation(argv: list[str]) -> bool:
    """A modern invocation is ``[global-flags] <subcommand> [...]``. Scan past any
    leading global flags; if the next token is a known subcommand it is modern,
    otherwise (a non-global option, or a non-subcommand positional) it is legacy.
    An argv of only global flags (e.g. ``--version``) is modern."""
    if not argv:
        return False
    index = 0
    while index < len(argv):
        token = argv[index]
        if token in _STORE_TRUE_GLOBAL_FLAGS:
            index += 1
            continue
        if token in _VALUE_TAKING_GLOBAL_FLAGS:
            index += 2
            continue
        if token.startswith(tuple(f"{flag}=" for flag in _VALUE_TAKING_GLOBAL_FLAGS)):
            index += 1
            continue
        # Positional tokens use the modern command parser so unknown commands get
        # the same actionable diagnostic as misspelled known commands. Legacy
        # invocations are distinguished by their leading flat option flags.
        return token.startswith("-") and token not in _SUBCOMMANDS
    return False


def parse_cli_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse argv into a namespace with ``command`` set to validate/deploy."""
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if _is_legacy_invocation(raw_argv):
        namespace = _build_legacy_parser().parse_args(raw_argv)
        namespace.command = "deploy"
        namespace.legacy = True
        return namespace

    namespace = _build_modern_parser().parse_args(raw_argv)
    namespace.legacy = False
    return namespace
