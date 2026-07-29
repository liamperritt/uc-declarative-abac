from __future__ import annotations

import pytest

from uc_declarative_abac.cli.parser import parse_cli_args


def test_parser_routes_plan_to_dry_run():
    namespace = parse_cli_args(
        ["plan", "--config-dir", "cfg", "--warehouse-id", "wh"],
    )
    assert namespace.command == "plan"


def test_parser_routes_apply_to_execute():
    namespace = parse_cli_args(
        ["apply", "--config-dir", "cfg", "--warehouse-id", "wh"],
    )
    assert namespace.command == "apply"


def test_parser_legacy_dry_run_maps_to_plan():
    namespace = parse_cli_args(
        ["--config-dir", "cfg", "--warehouse-id", "wh", "--dry-run"],
    )
    assert namespace.command == "plan"
    assert namespace.legacy is True


def test_parser_legacy_without_dry_run_maps_to_apply():
    namespace = parse_cli_args(
        ["--config-dir", "cfg", "--warehouse-id", "wh"],
    )
    assert namespace.command == "apply"
    assert namespace.legacy is True


def test_cli_reports_version(capsys):
    with pytest.raises(SystemExit) as exc_info:
        parse_cli_args(["--version"])
    assert exc_info.value.code == 0
