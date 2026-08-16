from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from uc_declarative_abac.cli.settings import resolve_settings


@pytest.mark.parametrize(
    ("file_value", "env_value", "cli_value", "expected"),
    [
        pytest.param(None, None, None, "system", id="default"),
        pytest.param("from-file", None, None, "from-file", id="settings-file"),
        pytest.param(
            "from-file", "from-env", None, "from-env", id="environment-over-file"
        ),
        pytest.param(
            "from-file", "from-env", "from-cli", "from-cli", id="cli-over-environment"
        ),
    ],
)
def test_given_system_catalog_sources_when_settings_are_resolved_then_normal_precedence_applies(
    file_value: str | None,
    env_value: str | None,
    cli_value: str | None,
    expected: str,
    monkeypatch,
    tmp_path: Path,
):
    # Given
    monkeypatch.chdir(tmp_path)
    if file_value is not None:
        (tmp_path / "uc_abac.yml").write_text(
            yaml.dump({"system_catalog": file_value}), encoding="utf-8"
        )
    if env_value is not None:
        monkeypatch.setenv("UC_ABAC_SYSTEM_CATALOG", env_value)
    cli_overrides = {"system_catalog": cli_value} if cli_value is not None else {}

    # When
    settings = resolve_settings(cli_overrides, settings_file=None)

    # Then
    assert settings.system_catalog == expected


def test_settings_prefers_cli_flag_over_env_var(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("UC_ABAC_WAREHOUSE_ID", "from-env")
    settings = resolve_settings(
        {"warehouse_id": "from-cli"},
        settings_file=None,
    )
    assert settings.warehouse_id == "from-cli"


def test_settings_prefers_env_var_over_settings_file(tmp_path: Path, monkeypatch):
    settings_path = tmp_path / "uc_abac.yml"
    settings_path.write_text(yaml.dump({"warehouse_id": "from-file"}), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("UC_ABAC_WAREHOUSE_ID", "from-env")
    settings = resolve_settings({}, settings_file=None)
    assert settings.warehouse_id == "from-env"


def test_settings_rejects_unknown_key_in_settings_file(tmp_path: Path):
    settings_path = tmp_path / "settings.yml"
    settings_path.write_text(yaml.dump({"not_a_real_field": True}), encoding="utf-8")
    with pytest.raises(ValidationError):
        resolve_settings({}, settings_file=settings_path)


def test_settings_loads_boolean_from_env(monkeypatch):
    monkeypatch.setenv("UC_ABAC_ENABLE_TAG_MANAGEMENT", "true")
    settings = resolve_settings({}, settings_file=None)
    assert settings.enable_tag_management is True


def test_settings_loads_enable_group_deletion_from_env(monkeypatch):
    monkeypatch.setenv("UC_ABAC_ENABLE_GROUP_DELETION", "true")
    settings = resolve_settings({}, settings_file=None)
    assert settings.enable_group_deletion is True


def test_settings_loads_namespace_scope_from_env(monkeypatch):
    monkeypatch.setenv("UC_ABAC_MANAGE_TAGS_FOR_NAMESPACES", "cat_env.sch1")
    settings = resolve_settings({}, settings_file=None)
    assert settings.manage_tags_for_namespaces == "cat_env.sch1"


def test_settings_empty_retain_prefixes_env_clears_default(monkeypatch):
    monkeypatch.setenv("UC_ABAC_RETAIN_TAG_PREFIXES", "")
    settings = resolve_settings({}, settings_file=None)
    assert settings.retain_tag_prefixes == ""


def test_settings_empty_bool_env_does_not_override_default(monkeypatch):
    monkeypatch.setenv("UC_ABAC_ENABLE_TAG_MANAGEMENT", "")
    settings = resolve_settings({}, settings_file=None)
    assert settings.enable_tag_management is False
