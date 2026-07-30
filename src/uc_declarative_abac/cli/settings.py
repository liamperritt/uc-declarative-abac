from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

_ENV_PREFIX = "UC_ABAC_"
_DEFAULT_SETTINGS_FILE = Path("uc-abac.yml")

_BOOL_ENV_VALUES = frozenset({"1", "true", "yes", "on"})

# Fields where an empty string is a meaningful value ("clear the list"), not
# "unset". For every other field an empty env var is treated as absent, so that
# the GitHub Action — which sets every UC_ABAC_* var, often to '' — does not
# clobber defaults or settings-file values with empty strings.
_EMPTY_MEANINGFUL_FIELDS = frozenset(
    {"retain_tag_prefixes", "ignore_unresolvable_principals"}
)

# Maps RunSettings field names to UC_ABAC_* environment variable suffixes.
_ENV_FIELD_MAP: dict[str, str] = {
    "config_dir": "CONFIG_DIR",
    "warehouse_id": "WAREHOUSE_ID",
    "profile": "PROFILE",
    "use_workspace_scim": "USE_WORKSPACE_SCIM",
    "skip_users_fetch": "SKIP_USERS_FETCH",
    "enable_tag_management": "ENABLE_TAG_MANAGEMENT",
    "enable_privilege_management": "ENABLE_PRIVILEGE_MANAGEMENT",
    "enable_taggable_management": "ENABLE_TAGGABLE_MANAGEMENT",
    "enable_taggable_creation": "ENABLE_TAGGABLE_CREATION",
    "manage_tags_for_namespaces": "MANAGE_TAGS_FOR_NAMESPACES",
    "manage_privileges_for_namespaces": "MANAGE_PRIVILEGES_FOR_NAMESPACES",
    "manage_taggables_for_namespaces": "MANAGE_TAGGABLES_FOR_NAMESPACES",
    "create_taggables_for_namespaces": "CREATE_TAGGABLES_FOR_NAMESPACES",
    "delete_policies_for_namespaces": "DELETE_POLICIES_FOR_NAMESPACES",
    "retain_tag_prefixes": "RETAIN_TAG_PREFIXES",
    "ignore_unresolvable_principals": "IGNORE_UNRESOLVABLE_PRINCIPALS",
    "enable_group_creation": "ENABLE_GROUP_CREATION",
    "enable_group_management": "ENABLE_GROUP_MANAGEMENT",
    "enable_governed_tag_deletion": "ENABLE_GOVERNED_TAG_DELETION",
    "enable_policy_deletion": "ENABLE_POLICY_DELETION",
    "force": "FORCE",
    "ref_override_strategy": "REF_OVERRIDE_STRATEGY",
    "max_parallel_changes": "MAX_PARALLEL_CHANGES",
}


class RunSettings(BaseModel):
    """Resolved runtime settings for validate / deploy."""

    model_config = ConfigDict(extra="forbid")

    config_dir: Path | None = None
    warehouse_id: str | None = None
    profile: str | None = None
    use_workspace_scim: bool = False
    skip_users_fetch: bool = False
    enable_tag_management: bool = False
    enable_privilege_management: bool = False
    enable_taggable_management: bool = False
    enable_taggable_creation: bool = False
    manage_tags_for_namespaces: str | None = None
    manage_privileges_for_namespaces: str | None = None
    manage_taggables_for_namespaces: str | None = None
    create_taggables_for_namespaces: str | None = None
    delete_policies_for_namespaces: str | None = None
    retain_tag_prefixes: str = "class."
    ignore_unresolvable_principals: str = ""
    enable_group_creation: bool = False
    enable_group_management: bool = False
    enable_governed_tag_deletion: bool = False
    enable_policy_deletion: bool = False
    force: bool = False
    ref_override_strategy: Literal["merge", "replace"] = "merge"
    max_parallel_changes: int = Field(default=8, ge=1)


def _coerce_env_value(field_name: str, raw: str, field_info: Any) -> Any:
    annotation = getattr(field_info, "annotation", None)
    if annotation is bool:
        return raw.strip().lower() in _BOOL_ENV_VALUES
    if annotation is int:
        return int(raw)
    if field_name == "config_dir":
        return Path(raw)
    return raw


def _load_settings_file(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Settings file {path} must contain a YAML mapping at the top level.")
    return data


def _load_env_settings() -> dict[str, Any]:
    field_lookup = {name: RunSettings.model_fields[name] for name in _ENV_FIELD_MAP}
    loaded: dict[str, Any] = {}
    for field_name, suffix in _ENV_FIELD_MAP.items():
        raw = os.environ.get(f"{_ENV_PREFIX}{suffix}")
        if raw is None:
            continue
        if raw == "" and field_name not in _EMPTY_MEANINGFUL_FIELDS:
            continue
        loaded[field_name] = _coerce_env_value(field_name, raw, field_lookup[field_name])
    return loaded


def _normalize_cli_overrides(overrides: dict[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, value in overrides.items():
        if key == "dry_run":
            continue
        if value is None:
            continue
        normalized[key] = value
    return normalized


def resolve_settings(
    cli_overrides: dict[str, Any],
    settings_file: Path | None = None,
) -> RunSettings:
    """Merge defaults, settings file, env vars, and explicit CLI overrides."""
    merged: dict[str, Any] = RunSettings().model_dump()

    resolved_file = settings_file
    if resolved_file is None and _DEFAULT_SETTINGS_FILE.is_file():
        resolved_file = _DEFAULT_SETTINGS_FILE
    if resolved_file is not None:
        merged.update(_load_settings_file(resolved_file))

    merged.update(_load_env_settings())
    merged.update(_normalize_cli_overrides(cli_overrides))
    return RunSettings.model_validate(merged)
