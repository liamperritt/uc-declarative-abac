from __future__ import annotations

import pytest

from uc_declarative_abac.cli.parser import parse_cli_args


def test_parser_routes_deploy_to_execute():
    namespace = parse_cli_args(
        ["deploy", "--config-dir", "cfg", "--warehouse-id", "wh"],
    )
    assert namespace.command == "deploy"
    assert getattr(namespace, "dry_run", False) is False


def test_parser_deploy_dry_run_sets_flag():
    namespace = parse_cli_args(
        ["deploy", "--config-dir", "cfg", "--warehouse-id", "wh", "--dry-run"],
    )
    assert namespace.command == "deploy"
    assert namespace.dry_run is True


def test_parser_legacy_dry_run_maps_to_deploy():
    namespace = parse_cli_args(
        ["--config-dir", "cfg", "--warehouse-id", "wh", "--dry-run"],
    )
    assert namespace.command == "deploy"
    assert namespace.dry_run is True
    assert namespace.legacy is True


def test_parser_legacy_without_dry_run_maps_to_deploy():
    namespace = parse_cli_args(
        ["--config-dir", "cfg", "--warehouse-id", "wh"],
    )
    assert namespace.command == "deploy"
    assert getattr(namespace, "dry_run", False) is False
    assert namespace.legacy is True


@pytest.mark.parametrize(
    "args",
    [
        ["deploy", "--config-dir", "cfg", "--warehouse-id", "wh", "--system-catalog", "system"],
        ["--config-dir", "cfg", "--warehouse-id", "wh", "--system-catalog", "system"],
    ],
    ids=["modern-deploy", "legacy-invocation"],
)
def test_parser_accepts_system_catalog_for_deploy_invocations(args):
    namespace = parse_cli_args(args)

    assert namespace.system_catalog == "system"


def test_parser_global_flag_before_subcommand_is_not_legacy():
    namespace = parse_cli_args(
        ["--verbose", "deploy", "--config-dir", "cfg", "--warehouse-id", "wh"],
    )
    assert namespace.command == "deploy"
    assert namespace.legacy is False


def test_parser_value_taking_global_flag_before_subcommand_is_not_legacy(tmp_path):
    settings_file = tmp_path / "s.yml"
    settings_file.write_text("config_dir: cfg\n", encoding="utf-8")
    namespace = parse_cli_args(
        ["--settings-file", str(settings_file), "validate"],
    )
    assert namespace.command == "validate"
    assert namespace.legacy is False


def test_parser_global_flag_before_legacy_flags_stays_legacy():
    namespace = parse_cli_args(
        ["--verbose", "--config-dir", "cfg", "--warehouse-id", "wh"],
    )
    assert namespace.command == "deploy"
    assert namespace.legacy is True


def test_cli_reports_version(capsys):
    with pytest.raises(SystemExit) as exc_info:
        parse_cli_args(["--version"])
    assert exc_info.value.code == 0
