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


def test_cli_reports_version(capsys):
    with pytest.raises(SystemExit) as exc_info:
        parse_cli_args(["--version"])
    assert exc_info.value.code == 0
