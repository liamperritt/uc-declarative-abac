from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from uc_declarative_abac.cli.settings import resolve_settings


def test_settings_prefers_cli_flag_over_env_var(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("UC_ABAC_WAREHOUSE_ID", "from-env")
    settings = resolve_settings(
        {"warehouse_id": "from-cli"},
        settings_file=None,
    )
    assert settings.warehouse_id == "from-cli"


def test_settings_prefers_env_var_over_settings_file(tmp_path: Path, monkeypatch):
    settings_path = tmp_path / "uc-abac.yml"
    settings_path.write_text(yaml.dump({"warehouse_id": "from-file"}), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("UC_ABAC_WAREHOUSE_ID", "from-env")
    settings = resolve_settings({}, settings_file=None)
    assert settings.warehouse_id == "from-env"


def test_settings_rejects_unknown_key_in_settings_file(tmp_path: Path):
    settings_path = tmp_path / "settings.yml"
    settings_path.write_text(yaml.dump({"not_a_real_field": True}), encoding="utf-8")
    with pytest.raises(Exception):
        resolve_settings({}, settings_file=settings_path)


def test_settings_loads_boolean_from_env(monkeypatch):
    monkeypatch.setenv("UC_ABAC_ENABLE_TAG_MANAGEMENT", "true")
    settings = resolve_settings({}, settings_file=None)
    assert settings.enable_tag_management is True
