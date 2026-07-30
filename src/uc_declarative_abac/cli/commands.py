from __future__ import annotations

import argparse
import logging
import sys
import traceback
from pathlib import Path

import yaml
from databricks.sdk import WorkspaceClient
from databricks.sdk.errors.base import DatabricksError
from pydantic import ValidationError

from uc_declarative_abac.cli.parser import parse_cli_args
from uc_declarative_abac.cli.settings import RunSettings, resolve_settings
from uc_declarative_abac.orchestrator import load_config, run
from uc_declarative_abac.utils import ExecutionBatchError, OrchestratorError

_logger = logging.getLogger("uc_declarative_abac")

# Deprecated *-for-catalogs flags are consumed directly off the namespace by
# _namespace_values_from_namespace; they are not RunSettings fields, so they
# must be kept out of the cli_overrides passed to resolve_settings.
_DEPRECATED_CATALOG_FLAGS = frozenset(
    {
        "manage_tags_for_catalogs",
        "manage_privileges_for_catalogs",
        "manage_taggables_for_catalogs",
        "create_taggables_for_catalogs",
    }
)

EXIT_SUCCESS = 0
EXIT_EXECUTION_ERROR = 1
EXIT_CONFIG_ERROR = 3
EXIT_DATABRICKS_ERROR = 4
EXIT_INTERRUPTED = 130


def _resolve_namespace_flag(
    old_value: str | None,
    new_value: str | None,
    old_flag: str,
    new_flag: str,
) -> str:
    if old_value is not None and new_value is not None:
        raise argparse.ArgumentTypeError(
            f"{old_flag} is deprecated and cannot be combined with {new_flag}. "
            f"Use {new_flag} only."
        )
    if old_value is not None:
        _logger.warning(
            "%s is deprecated; use %s instead. Treating it as %s for this run.",
            old_flag,
            new_flag,
            new_flag,
        )
        return old_value
    if new_value is not None:
        return new_value
    return "*"


def _namespace_values_from_namespace(
    namespace: argparse.Namespace,
) -> dict[str, str]:
    return {
        "manage_tags_for_namespaces": _resolve_namespace_flag(
            getattr(namespace, "manage_tags_for_catalogs", None),
            getattr(namespace, "manage_tags_for_namespaces", None),
            "--manage-tags-for-catalogs",
            "--manage-tags-for-namespaces",
        ),
        "manage_privileges_for_namespaces": _resolve_namespace_flag(
            getattr(namespace, "manage_privileges_for_catalogs", None),
            getattr(namespace, "manage_privileges_for_namespaces", None),
            "--manage-privileges-for-catalogs",
            "--manage-privileges-for-namespaces",
        ),
        "manage_taggables_for_namespaces": _resolve_namespace_flag(
            getattr(namespace, "manage_taggables_for_catalogs", None),
            getattr(namespace, "manage_taggables_for_namespaces", None),
            "--manage-taggables-for-catalogs",
            "--manage-taggables-for-namespaces",
        ),
        "create_taggables_for_namespaces": _resolve_namespace_flag(
            getattr(namespace, "create_taggables_for_catalogs", None),
            getattr(namespace, "create_taggables_for_namespaces", None),
            "--create-taggables-for-catalogs",
            "--create-taggables-for-namespaces",
        ),
    }


def _configure_logging(namespace: argparse.Namespace) -> None:
    if getattr(namespace, "quiet", False):
        level = logging.ERROR
    elif getattr(namespace, "verbose", False):
        level = logging.DEBUG
    else:
        level = logging.INFO
    # basicConfig only installs the root handler on the first call (no force=True),
    # so we don't tear down handlers other libraries or pytest's caplog have added.
    # The explicit setLevel keeps the level current across repeated invocations.
    logging.basicConfig(level=level, format="%(message)s")
    logging.getLogger().setLevel(level)


def _require_config_dir(settings: RunSettings) -> Path:
    if settings.config_dir is None:
        raise OrchestratorError("--config-dir is required.")
    return settings.config_dir


def _require_warehouse_id(settings: RunSettings) -> str:
    if settings.warehouse_id is None:
        raise OrchestratorError("--warehouse-id is required.")
    return settings.warehouse_id


def _run_kwargs(settings: RunSettings, namespace: argparse.Namespace, *, dry_run: bool) -> dict:
    namespaces = _namespace_values_from_namespace(namespace)
    delete_policies = settings.delete_policies_for_namespaces or "*"
    return {
        "config_dir": _require_config_dir(settings),
        "warehouse_id": _require_warehouse_id(settings),
        "dry_run": dry_run,
        "use_workspace_scim": settings.use_workspace_scim,
        "skip_users_fetch": settings.skip_users_fetch,
        "enable_tag_management": settings.enable_tag_management,
        "enable_taggable_management": settings.enable_taggable_management,
        "enable_taggable_creation": settings.enable_taggable_creation,
        "enable_privilege_management": settings.enable_privilege_management,
        "enable_governed_tag_deletion": settings.enable_governed_tag_deletion,
        "enable_policy_deletion": settings.enable_policy_deletion,
        "enable_group_creation": settings.enable_group_creation,
        "enable_group_management": settings.enable_group_management,
        "ignore_unresolvable_principals": settings.ignore_unresolvable_principals,
        "manage_tags_for_namespaces": namespaces["manage_tags_for_namespaces"],
        "manage_privileges_for_namespaces": namespaces["manage_privileges_for_namespaces"],
        "manage_taggables_for_namespaces": namespaces["manage_taggables_for_namespaces"],
        "create_taggables_for_namespaces": namespaces["create_taggables_for_namespaces"],
        "delete_policies_for_namespaces": delete_policies,
        "retain_tag_prefixes": settings.retain_tag_prefixes,
        "force": settings.force,
        "ref_override_strategy": settings.ref_override_strategy,
        "max_parallel_changes": settings.max_parallel_changes,
    }


def cmd_validate(settings: RunSettings) -> int:
    config_dir = _require_config_dir(settings)
    load_config(config_dir, settings.ref_override_strategy)
    _logger.info("Config validation successful.")
    return EXIT_SUCCESS


def cmd_plan(settings: RunSettings, namespace: argparse.Namespace) -> int:
    kwargs = _run_kwargs(settings, namespace, dry_run=True)
    workspace_client = WorkspaceClient(profile=settings.profile)
    run(workspace_client=workspace_client, **kwargs)
    return EXIT_SUCCESS


def cmd_apply(settings: RunSettings, namespace: argparse.Namespace) -> int:
    kwargs = _run_kwargs(settings, namespace, dry_run=False)
    workspace_client = WorkspaceClient(profile=settings.profile)
    run(workspace_client=workspace_client, **kwargs)
    return EXIT_SUCCESS


def _print_error(message: str, *, verbose: bool) -> None:
    print(message, file=sys.stderr)
    if verbose:
        traceback.print_exc()


def _handle_cli_error(exc: BaseException, *, verbose: bool) -> int:
    if isinstance(exc, ExecutionBatchError):
        _print_error(str(exc), verbose=verbose)
        return EXIT_EXECUTION_ERROR
    if isinstance(exc, (OrchestratorError, ValidationError, ValueError, yaml.YAMLError)):
        _print_error(str(exc), verbose=verbose)
        return EXIT_CONFIG_ERROR
    if isinstance(exc, DatabricksError):
        _print_error(str(exc), verbose=verbose)
        return EXIT_DATABRICKS_ERROR
    if isinstance(exc, argparse.ArgumentTypeError):
        _print_error(str(exc), verbose=verbose)
        return 2
    raise exc


def run_cli(argv: list[str] | None = None) -> int:
    namespace = parse_cli_args(argv)
    _configure_logging(namespace)

    if getattr(namespace, "legacy", False):
        _logger.warning(
            "Invoking uc-abac without a subcommand is deprecated. "
            "Use 'uc-abac plan' or 'uc-abac apply' instead."
        )

    cli_overrides = {
        key: value
        for key, value in vars(namespace).items()
        if key not in {"command", "legacy", "settings_file", "verbose", "quiet", "dry_run"}
        and key not in _DEPRECATED_CATALOG_FLAGS
    }
    settings_file = getattr(namespace, "settings_file", None)
    settings = resolve_settings(cli_overrides, settings_file=settings_file)

    try:
        if namespace.command == "validate":
            return cmd_validate(settings)
        if namespace.command == "plan":
            return cmd_plan(settings, namespace)
        return cmd_apply(settings, namespace)
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    except BaseException as exc:
        verbose = getattr(namespace, "verbose", False)
        return _handle_cli_error(exc, verbose=verbose)


def main() -> None:
    try:
        exit_code = run_cli()
    except SystemExit:
        raise
    sys.exit(exit_code)


# Re-exported for tests that monkeypatch the CLI boundary.
__all__ = ["WorkspaceClient", "main", "run", "run_cli"]
