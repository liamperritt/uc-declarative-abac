from __future__ import annotations

import argparse
import logging
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path

import yaml
from databricks.sdk import WorkspaceClient
from databricks.sdk.errors.base import DatabricksError
from pydantic import ValidationError

from uc_declarative_abac.cli.parser import parse_cli_args
from uc_declarative_abac.cli.presentation import format_error, format_status
from uc_declarative_abac.cli.settings import RunSettings, resolve_settings
from uc_declarative_abac.orchestrator import load_config, run
from uc_declarative_abac.utils import (
    ExecutionBatchError,
    OrchestratorError,
    parse_flat_scope,
    parse_hierarchical_scope,
)

_logger = logging.getLogger("uc_declarative_abac")


class CliUsageError(Exception):
    """Raised for invalid flag combinations or other CLI usage errors (exit 2)."""


# Deprecated *-for-catalogs flags are consumed directly off the namespace by
# _resolve_namespace_values; they are not RunSettings fields, so they must be
# kept out of the cli_overrides passed to resolve_settings.
_DEPRECATED_CATALOG_FLAGS = frozenset(
    {
        "manage_tags_for_catalogs",
        "manage_privileges_for_catalogs",
        "manage_taggables_for_catalogs",
        "create_taggables_for_catalogs",
    }
)


@dataclass(frozen=True)
class _ScopeFeature:
    """Maps a new ``--*-scopes`` flag to the deprecated flags it supersedes.

    ``namespace_*`` / ``catalog_*`` are ``None`` for the flat domains (groups,
    governed tags), which only ever had an enable gate.
    """

    new_field: str
    new_flag: str
    enable_field: str
    enable_flag: str
    namespace_field: str | None = None
    namespace_flag: str | None = None
    catalog_attr: str | None = None
    catalog_flag: str | None = None
    hierarchical: bool = True


# One entry per new scope flag, listing the deprecated flags it replaces. Used to
# (a) reject a new + deprecated combination for the same feature, and (b) warn
# when a deprecated flag is used on its own.
_SCOPE_FEATURES: tuple[_ScopeFeature, ...] = (
    _ScopeFeature(
        "tag_management_scopes", "--tag-management-scopes",
        "enable_tag_management", "--enable-tag-management",
        "manage_tags_for_namespaces", "--manage-tags-for-namespaces",
        "manage_tags_for_catalogs", "--manage-tags-for-catalogs",
    ),
    _ScopeFeature(
        "privilege_management_scopes", "--privilege-management-scopes",
        "enable_privilege_management", "--enable-privilege-management",
        "manage_privileges_for_namespaces", "--manage-privileges-for-namespaces",
        "manage_privileges_for_catalogs", "--manage-privileges-for-catalogs",
    ),
    _ScopeFeature(
        "taggable_management_scopes", "--taggable-management-scopes",
        "enable_taggable_management", "--enable-taggable-management",
        "manage_taggables_for_namespaces", "--manage-taggables-for-namespaces",
        "manage_taggables_for_catalogs", "--manage-taggables-for-catalogs",
    ),
    _ScopeFeature(
        "taggable_creation_scopes", "--taggable-creation-scopes",
        "enable_taggable_creation", "--enable-taggable-creation",
        "create_taggables_for_namespaces", "--create-taggables-for-namespaces",
        "create_taggables_for_catalogs", "--create-taggables-for-catalogs",
    ),
    _ScopeFeature(
        "policy_deletion_scopes", "--policy-deletion-scopes",
        "enable_policy_deletion", "--enable-policy-deletion",
        "delete_policies_for_namespaces", "--delete-policies-for-namespaces",
    ),
    _ScopeFeature(
        "group_creation_scopes", "--group-creation-scopes",
        "enable_group_creation", "--enable-group-creation",
        hierarchical=False,
    ),
    _ScopeFeature(
        "group_management_scopes", "--group-management-scopes",
        "enable_group_management", "--enable-group-management",
        hierarchical=False,
    ),
    _ScopeFeature(
        "group_deletion_scopes", "--group-deletion-scopes",
        "enable_group_deletion", "--enable-group-deletion",
        hierarchical=False,
    ),
    _ScopeFeature(
        "governed_tag_deletion_scopes", "--governed-tag-deletion-scopes",
        "enable_governed_tag_deletion", "--enable-governed-tag-deletion",
        hierarchical=False,
    ),
)

EXIT_SUCCESS = 0
EXIT_EXECUTION_ERROR = 1
EXIT_USAGE_ERROR = 2
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
        raise CliUsageError(
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


def _resolve_namespace_values(
    settings: RunSettings,
    namespace: argparse.Namespace,
) -> dict[str, str]:
    """Merge deprecated *-for-catalogs flags (namespace-only) with the resolved
    *-for-namespaces settings (which already fold in env vars and the settings
    file). The deprecated flags are read off the raw namespace because they are
    not RunSettings fields; the new-style values come from settings."""
    return {
        "manage_tags_for_namespaces": _resolve_namespace_flag(
            getattr(namespace, "manage_tags_for_catalogs", None),
            settings.manage_tags_for_namespaces,
            "--manage-tags-for-catalogs",
            "--manage-tags-for-namespaces",
        ),
        "manage_privileges_for_namespaces": _resolve_namespace_flag(
            getattr(namespace, "manage_privileges_for_catalogs", None),
            settings.manage_privileges_for_namespaces,
            "--manage-privileges-for-catalogs",
            "--manage-privileges-for-namespaces",
        ),
        "manage_taggables_for_namespaces": _resolve_namespace_flag(
            getattr(namespace, "manage_taggables_for_catalogs", None),
            settings.manage_taggables_for_namespaces,
            "--manage-taggables-for-catalogs",
            "--manage-taggables-for-namespaces",
        ),
        "create_taggables_for_namespaces": _resolve_namespace_flag(
            getattr(namespace, "create_taggables_for_catalogs", None),
            settings.create_taggables_for_namespaces,
            "--create-taggables-for-catalogs",
            "--create-taggables-for-namespaces",
        ),
    }


def _deprecated_flags_for_warning(
    feature: _ScopeFeature, settings: RunSettings
) -> list[str]:
    """Deprecated flags for ``feature`` that are meaningfully set (enable True or
    namespace non-None). Excludes the ``*-for-catalogs`` flags, whose own
    deprecation warning is owned by ``_resolve_namespace_flag``."""
    used: list[str] = []
    if getattr(settings, feature.enable_field):
        used.append(feature.enable_flag)
    if feature.namespace_field and getattr(settings, feature.namespace_field) is not None:
        used.append(feature.namespace_flag)
    return used


def _resolve_scope_flags(
    settings: RunSettings, namespace: argparse.Namespace
) -> None:
    """Validate the new ``--*-scopes`` flags against the deprecated flags they
    supersede.

    For each feature, combining a new scope flag with any deprecated counterpart
    (enable, ``*-for-namespaces``, or ``*-for-catalogs``) is a fast usage error;
    using a deprecated flag on its own logs a one-off migration warning. Purely
    additive — an all-legacy invocation only warns, never fails.
    """
    for feature in _SCOPE_FEATURES:
        new_spec = getattr(settings, feature.new_field)
        new_set = new_spec is not None
        deprecated = _deprecated_flags_for_warning(feature, settings)
        if new_set:
            conflicting = list(deprecated)
            if feature.catalog_attr and (
                getattr(namespace, feature.catalog_attr, None) is not None
            ):
                conflicting.append(feature.catalog_flag)
            if conflicting:
                raise CliUsageError(
                    f"{feature.new_flag} cannot be combined with deprecated "
                    f"flag(s): {', '.join(conflicting)}. Use {feature.new_flag} only."
                )
            # Validate the grammar up front (so `validate` catches it too, and
            # deploy fails before contacting Databricks). ValueError -> exit 2.
            parse = (
                parse_hierarchical_scope
                if feature.hierarchical
                else parse_flat_scope
            )
            try:
                parse(new_spec)
            except ValueError as exc:
                raise CliUsageError(f"{feature.new_flag}: {exc}") from exc
        elif deprecated:
            _logger.warning(
                "%s deprecated; use %s instead.",
                ", ".join(deprecated),
                feature.new_flag,
            )


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


def _run_kwargs(
    settings: RunSettings, namespaces: dict[str, str], *, dry_run: bool
) -> dict:
    delete_policies = settings.delete_policies_for_namespaces or "*"
    return {
        "config_dir": _require_config_dir(settings),
        "warehouse_id": _require_warehouse_id(settings),
        "system_catalog": settings.system_catalog,
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
        "enable_group_deletion": settings.enable_group_deletion,
        "ignore_unresolvable_principals": settings.ignore_unresolvable_principals,
        "manage_tags_for_namespaces": namespaces["manage_tags_for_namespaces"],
        "manage_privileges_for_namespaces": namespaces[
            "manage_privileges_for_namespaces"
        ],
        "manage_taggables_for_namespaces": namespaces[
            "manage_taggables_for_namespaces"
        ],
        "create_taggables_for_namespaces": namespaces[
            "create_taggables_for_namespaces"
        ],
        "delete_policies_for_namespaces": delete_policies,
        "tag_management_scopes": settings.tag_management_scopes,
        "privilege_management_scopes": settings.privilege_management_scopes,
        "taggable_management_scopes": settings.taggable_management_scopes,
        "taggable_creation_scopes": settings.taggable_creation_scopes,
        "policy_deletion_scopes": settings.policy_deletion_scopes,
        "group_creation_scopes": settings.group_creation_scopes,
        "group_management_scopes": settings.group_management_scopes,
        "group_deletion_scopes": settings.group_deletion_scopes,
        "governed_tag_deletion_scopes": settings.governed_tag_deletion_scopes,
        "retain_tag_prefixes": settings.retain_tag_prefixes,
        "force": settings.force,
        "ref_override_strategy": settings.ref_override_strategy,
        "max_parallel_changes": settings.max_parallel_changes,
    }


def cmd_validate(settings: RunSettings) -> int:
    config_dir = _require_config_dir(settings)
    load_config(config_dir, settings.ref_override_strategy)
    _logger.info(format_status("success", "Config validation successful."))
    return EXIT_SUCCESS


def cmd_deploy(
    settings: RunSettings,
    namespace: argparse.Namespace,
    namespaces: dict[str, str],
) -> int:
    dry_run = getattr(namespace, "dry_run", False)
    kwargs = _run_kwargs(settings, namespaces, dry_run=dry_run)
    workspace_client = WorkspaceClient(profile=settings.profile)
    run(workspace_client=workspace_client, **kwargs)
    return EXIT_SUCCESS


def _error_hint(message: str) -> str | None:
    if "--warehouse-id is required" in message:
        return (
            "Pass `--warehouse-id <id>`, set `UC_ABAC_WAREHOUSE_ID`, "
            "or add `warehouse_id` to the settings file."
        )
    return None


def _print_error(message: str, *, verbose: bool) -> None:
    sys.stderr.write(
        format_error(message, hint=_error_hint(message), stream=sys.stderr)
    )
    if verbose:
        traceback.print_exc()


def _handle_cli_error(exc: Exception, *, verbose: bool) -> int:
    if isinstance(exc, ExecutionBatchError):
        _print_error(str(exc), verbose=verbose)
        return EXIT_EXECUTION_ERROR
    if isinstance(
        exc, (OrchestratorError, ValidationError, ValueError, TypeError, yaml.YAMLError)
    ):
        _print_error(str(exc), verbose=verbose)
        return EXIT_CONFIG_ERROR
    if isinstance(exc, DatabricksError):
        _print_error(str(exc), verbose=verbose)
        return EXIT_DATABRICKS_ERROR
    if isinstance(exc, CliUsageError):
        _print_error(str(exc), verbose=verbose)
        return EXIT_USAGE_ERROR
    raise exc


def run_cli(argv: list[str] | None = None) -> int:
    namespace = parse_cli_args(argv)
    _configure_logging(namespace)

    if getattr(namespace, "legacy", False):
        _logger.warning(
            "Invoking uc-abac without a subcommand is deprecated. "
            "Use 'uc-abac deploy' (add --dry-run to preview) instead."
        )

    cli_overrides = {
        key: value
        for key, value in vars(namespace).items()
        if key
        not in {"command", "legacy", "settings_file", "verbose", "quiet", "dry_run"}
        and key not in _DEPRECATED_CATALOG_FLAGS
    }
    settings_file = getattr(namespace, "settings_file", None)
    settings = resolve_settings(cli_overrides, settings_file=settings_file)

    try:
        # Resolve/validate scope flags up front so the deprecated+new conflict
        # check (CliUsageError -> exit 2) fires for every command, not just
        # deploy. New-vs-deprecated conflicts are checked before the legacy
        # namespace resolution so the clearer error wins over a stale warning.
        _resolve_scope_flags(settings, namespace)
        namespaces = _resolve_namespace_values(settings, namespace)
        if namespace.command == "validate":
            return cmd_validate(settings)
        return cmd_deploy(settings, namespace, namespaces)
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    except (
        ExecutionBatchError,
        OrchestratorError,
        ValidationError,
        ValueError,
        TypeError,
        yaml.YAMLError,
        DatabricksError,
        CliUsageError,
    ) as exc:
        verbose = getattr(namespace, "verbose", False)
        return _handle_cli_error(exc, verbose=verbose)


def main() -> None:
    sys.exit(run_cli())


# Re-exported for tests that monkeypatch the CLI boundary.
__all__ = ["WorkspaceClient", "main", "run", "run_cli"]
