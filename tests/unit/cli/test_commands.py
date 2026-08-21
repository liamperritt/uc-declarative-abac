from __future__ import annotations

import json
import logging
from pathlib import Path

import uc_declarative_abac.cli.commands as cli
from uc_declarative_abac.cli.settings import RunSettings
from uc_declarative_abac.governed_tags import GovernedTagDiff
from uc_declarative_abac.orchestrator import OrchestratorDiffsResult
from uc_declarative_abac.policies import PolicyDiff
from uc_declarative_abac.principals import GroupDiff
from uc_declarative_abac.privileges import PrivilegeDiff
from uc_declarative_abac.securables import SecurableDiff
from uc_declarative_abac.tags import TagDiff

# ---------------------------------------------------------------------------
# Legacy flat invocation (regression coverage for pre-subcommand CLI)
# ---------------------------------------------------------------------------


def _run_legacy(monkeypatch, argv: list[str]) -> dict:
    captured: dict = {}

    def _fake_run(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(cli, "run", _fake_run)
    monkeypatch.setattr(cli, "WorkspaceClient", lambda **_: object())
    exit_code = cli.run_cli(
        ["--config-dir", "cfg", "--warehouse-id", "wh", *argv],
    )
    assert exit_code == 0
    return captured


def test_main_passes_new_namespace_flag_through_to_run(monkeypatch):
    captured = _run_legacy(
        monkeypatch,
        ["--manage-tags-for-namespaces", "cat_a.sch1"],
    )
    assert captured["manage_tags_for_namespaces"] == "cat_a.sch1"


def test_main_defaults_namespace_flag_to_star_when_unset(monkeypatch):
    captured = _run_legacy(monkeypatch, [])
    assert captured["manage_tags_for_namespaces"] == "*"
    assert captured["create_taggables_for_namespaces"] == "*"


def test_main_converts_deprecated_catalog_flag_and_warns(monkeypatch, caplog):
    with caplog.at_level(logging.WARNING, logger="uc_declarative_abac"):
        captured = _run_legacy(
            monkeypatch,
            ["--manage-tags-for-catalogs", "cat_a"],
        )
    assert captured["manage_tags_for_namespaces"] == "cat_a"
    assert any(
        "manage-tags-for-catalogs" in r.getMessage()
        and "manage-tags-for-namespaces" in r.getMessage()
        for r in caplog.records
    )


def test_main_fails_when_old_and_new_namespace_flags_combined(monkeypatch):
    exit_code = cli.run_cli(
        [
            "--config-dir",
            "cfg",
            "--warehouse-id",
            "wh",
            "--manage-tags-for-catalogs",
            "cat_a",
            "--manage-tags-for-namespaces",
            "cat_a",
        ],
    )
    assert exit_code == 2


def test_main_passes_namespace_scope_from_env_through_to_run(monkeypatch):
    monkeypatch.setenv("UC_ABAC_MANAGE_TAGS_FOR_NAMESPACES", "cat_env.sch1")
    captured = _run_legacy(monkeypatch, [])
    assert captured["manage_tags_for_namespaces"] == "cat_env.sch1"


def test_main_fails_on_conflicting_namespace_flags_for_deploy(monkeypatch):
    exit_code = cli.run_cli(
        [
            "deploy",
            "--config-dir",
            "cfg",
            "--warehouse-id",
            "wh",
            "--manage-tags-for-catalogs",
            "cat_a",
            "--manage-tags-for-namespaces",
            "cat_a",
        ],
    )
    assert exit_code == 2


def test_main_passes_enable_policy_deletion_through_to_run(monkeypatch):
    captured = _run_legacy(monkeypatch, ["--enable-policy-deletion"])
    assert captured["enable_policy_deletion"] is True


def test_main_defaults_enable_policy_deletion_off(monkeypatch):
    captured = _run_legacy(monkeypatch, [])
    assert captured["enable_policy_deletion"] is False


def test_main_passes_enable_group_deletion_through_to_run(monkeypatch):
    captured = _run_legacy(monkeypatch, ["--enable-group-deletion"])
    assert captured["enable_group_deletion"] is True


def test_main_defaults_enable_group_deletion_off(monkeypatch):
    captured = _run_legacy(monkeypatch, [])
    assert captured["enable_group_deletion"] is False


def test_main_passes_delete_policies_namespaces_through_to_run(monkeypatch):
    captured = _run_legacy(
        monkeypatch,
        ["--delete-policies-for-namespaces", "cat_a.sch1"],
    )
    assert captured["delete_policies_for_namespaces"] == "cat_a.sch1"


def test_main_defaults_delete_policies_namespaces_to_star(monkeypatch):
    captured = _run_legacy(monkeypatch, [])
    assert captured["delete_policies_for_namespaces"] == "*"


def test_main_passes_skip_users_fetch_through_to_run(monkeypatch):
    captured = _run_legacy(monkeypatch, ["--skip-users-fetch"])
    assert captured["skip_users_fetch"] is True


def test_main_defaults_skip_users_fetch_off(monkeypatch):
    captured = _run_legacy(monkeypatch, [])
    assert captured["skip_users_fetch"] is False


def test_cli_warns_when_invoked_with_legacy_flat_flags(monkeypatch, caplog):
    monkeypatch.setattr(cli, "run", lambda **_: None)
    monkeypatch.setattr(cli, "WorkspaceClient", lambda **_: object())
    with caplog.at_level(logging.WARNING, logger="uc_declarative_abac"):
        cli.run_cli(["--config-dir", "cfg", "--warehouse-id", "wh"])
    assert any("deprecated" in r.getMessage().lower() for r in caplog.records)


def test_commands_validate_does_not_construct_workspace_client(
    monkeypatch, tmp_path: Path
):
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    (config_dir / "resources.yaml").write_text(
        "resources:\n  catalogs: {}\n",
        encoding="utf-8",
    )
    constructed = False

    def _fail_workspace_client(**_):
        nonlocal constructed
        constructed = True
        raise AssertionError("WorkspaceClient should not be constructed for validate")

    monkeypatch.setattr(cli, "WorkspaceClient", _fail_workspace_client)
    exit_code = cli.run_cli(["validate", "--config-dir", str(config_dir)])
    assert exit_code == 0
    assert constructed is False


def test_commands_reports_success_when_config_is_valid(tmp_path: Path, caplog):
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    (config_dir / "resources.yaml").write_text(
        "resources:\n  catalogs: {}\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.INFO, logger="uc_declarative_abac"):
        exit_code = cli.run_cli(["validate", "--config-dir", str(config_dir)])

    output = caplog.text
    assert exit_code == 0
    assert "✔" in output or "[OK]" in output
    assert "Config validation successful." in output


def test_commands_validate_writes_json_result_when_output_is_json(
    monkeypatch, capsys, tmp_path: Path
):
    config_dir = tmp_path / "configs"
    monkeypatch.setattr(cli, "load_config", lambda *_args, **_kwargs: object())

    exit_code = cli.run_cli(
        ["validate", "--config-dir", str(config_dir), "--output", "json"]
    )

    report = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert report["format_version"] == "1"
    assert report["mode"] == "validate"
    assert report["dry_run"] is False
    assert report["config_dir"] == str(config_dir)
    assert report["status"] == "valid"
    assert report["resources"] == []
    assert report["summary"]["total"] == 0


def test_commands_return_config_error_code_when_yaml_invalid(tmp_path: Path):
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    (config_dir / "bad.yaml").write_text("not: [valid", encoding="utf-8")
    exit_code = cli.run_cli(["validate", "--config-dir", str(config_dir)])
    assert exit_code == 3


def test_commands_deploy_dry_run_passes_dry_run_true(monkeypatch):
    captured: dict = {}

    def _fake_run(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(cli, "run", _fake_run)
    monkeypatch.setattr(cli, "WorkspaceClient", lambda **_: object())
    exit_code = cli.run_cli(
        ["deploy", "--dry-run", "--config-dir", "cfg", "--warehouse-id", "wh"],
    )
    assert exit_code == 0
    assert captured["dry_run"] is True


def test_commands_deploy_passes_dry_run_false(monkeypatch):
    captured: dict = {}

    def _fake_run(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(cli, "run", _fake_run)
    monkeypatch.setattr(cli, "WorkspaceClient", lambda **_: object())
    exit_code = cli.run_cli(
        ["deploy", "--config-dir", "cfg", "--warehouse-id", "wh"],
    )
    assert exit_code == 0
    assert captured["dry_run"] is False


def test_commands_deploy_writes_json_report_when_output_is_json(monkeypatch, capsys):
    result = OrchestratorDiffsResult(
        group_diff=GroupDiff(),
        securable_diff=SecurableDiff(),
        governed_tag_diff=GovernedTagDiff(),
        tag_diff=TagDiff(),
        policy_diff=PolicyDiff(),
        privilege_diff=PrivilegeDiff(),
    )
    monkeypatch.setattr(cli, "run", lambda **_: result)
    monkeypatch.setattr(cli, "WorkspaceClient", lambda **_: object())

    exit_code = cli.run_cli(
        [
            "deploy",
            "--config-dir",
            "cfg",
            "--warehouse-id",
            "wh",
            "--output",
            "json",
        ],
    )

    stdout = capsys.readouterr().out
    report = json.loads(stdout)
    assert exit_code == 0
    assert report["mode"] == "deploy"
    assert "successful" not in stdout.lower()
    assert "changes" not in stdout.lower()


def test_commands_deploy_forwards_system_catalog_from_run_settings_to_orchestrator(
    monkeypatch,
):
    captured: dict = {}
    settings = RunSettings(
        config_dir=Path("cfg"),
        warehouse_id="wh",
        system_catalog="system_catalog_proxy",
    )

    monkeypatch.setattr(cli, "resolve_settings", lambda *_args, **_kwargs: settings)
    monkeypatch.setattr(cli, "run", lambda **kwargs: captured.update(kwargs))
    monkeypatch.setattr(cli, "WorkspaceClient", lambda **_: object())

    exit_code = cli.run_cli(["deploy"])

    assert exit_code == 0
    assert captured["system_catalog"] == "system_catalog_proxy"


def test_commands_deploy_missing_warehouse_returns_config_error(monkeypatch):
    monkeypatch.setattr(cli, "WorkspaceClient", lambda **_: object())
    exit_code = cli.run_cli(["deploy", "--config-dir", "cfg"])
    assert exit_code == 3


def test_commands_reports_actionable_error_when_warehouse_id_is_missing(
    monkeypatch, capsys, tmp_path: Path
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("UC_ABAC_WAREHOUSE_ID", raising=False)

    exit_code = cli.run_cli(["deploy", "--config-dir", "cfg"])

    error = capsys.readouterr().err
    assert exit_code == 3
    assert "[ERROR]" in error or "✖" in error
    assert "--warehouse-id" in error
    assert "HOW TO FIX" in error or (
        "Hint:" in error
        and ("--warehouse-id" in error or "settings" in error.lower())
    )


def test_commands_legacy_missing_warehouse_returns_config_error(monkeypatch):
    monkeypatch.setattr(cli, "WorkspaceClient", lambda **_: object())
    exit_code = cli.run_cli(["--config-dir", "cfg"])
    assert exit_code == 3
