from __future__ import annotations

import re

import pytest

from uc_declarative_abac.cli.parser import parse_cli_args

_SHARED_DEFAULT_ANNOTATIONS = (
    r"--system-catalog\b[\s\S]*?\[default: system\]",
    r"--ref-override-strategy\b[\s\S]*?\[default: merge\]",
    r"--max-parallel-changes\b[\s\S]*?\[default: 8\]",
)
_COMMAND_HELP_SECTIONS = ("USAGE:", "FLAGS:", "EXAMPLES:")


def _help_output(argv: list[str], capsys) -> str:
    with pytest.raises(SystemExit) as exc_info:
        parse_cli_args(argv)
    assert exc_info.value.code == 0
    return capsys.readouterr().out


def _assert_contains_patterns(output: str, patterns: tuple[str, ...]) -> None:
    for pattern in patterns:
        assert re.search(pattern, output)


def _example_commands(output: str, prefix: str) -> list[str]:
    return [
        line.strip() for line in output.splitlines() if line.strip().startswith(prefix)
    ]


def test_parser_displays_polished_root_help(capsys):
    output = _help_output(["--help"], capsys)
    nonempty_lines = [line for line in output.splitlines() if line.strip()]
    compact_header = " ".join(nonempty_lines[:3])
    assert "UC Declarative ABAC" in compact_header
    assert re.search(r"\bv?\d+\.\d+\.\d+\b", compact_header)

    for section in ("USAGE:", "COMMANDS:", "GLOBAL OPTIONS:", "EXAMPLES:"):
        assert section in output

    command_lines = [
        line
        for line in output.splitlines()
        if line.lstrip().startswith(("validate ", "deploy "))
    ]
    assert len(command_lines) == 2
    assert all(line.startswith("  ") for line in command_lines)
    description_columns = [
        re.search(r"\s{2,}\S", line[2:]).start() + 4 for line in command_lines
    ]
    assert len(set(description_columns)) == 1
    assert "validate" in output and "YAML" in output
    assert "deploy" in output and "Unity Catalog" in output

    examples = [line for line in output.splitlines() if line.startswith("  uc-abac ")]
    assert 2 <= len(examples) <= 3


def test_parser_displays_polished_validate_help(capsys):
    output = _help_output(["validate", "--help"], capsys)

    assert "Validate YAML configs locally" in output
    for section in _COMMAND_HELP_SECTIONS:
        assert section in output

    for flag in (
        "--config-dir",
        "--profile",
        "--system-catalog",
        "--ref-override-strategy",
        "--max-parallel-changes",
    ):
        assert flag in output

    _assert_contains_patterns(output, _SHARED_DEFAULT_ANNOTATIONS)

    examples = _example_commands(output, "uc-abac validate ")
    assert 2 <= len(examples) <= 3
    assert all("--config-dir" in example for example in examples)
    assert all(len(line) <= 80 for line in output.splitlines())


def test_parser_displays_polished_deploy_help(capsys):
    output = _help_output(["deploy", "--help"], capsys)

    assert "Deploy declarative governance to Unity Catalog" in output
    for section in _COMMAND_HELP_SECTIONS:
        assert section in output

    for flag in (
        "--config-dir",
        "--warehouse-id",
        "--dry-run",
        "--enable-tag-management",
        "--enable-privilege-management",
        "--enable-policy-deletion",
        "--enable-group-deletion",
        "--manage-tags-for-namespaces",
        "--delete-policies-for-namespaces",
    ):
        assert flag in output

    _assert_contains_patterns(output, _SHARED_DEFAULT_ANNOTATIONS)
    assert "Off by default" in output

    examples = _example_commands(output, "uc-abac deploy ")
    assert 2 <= len(examples) <= 3
    assert all("--config-dir" in example for example in examples)
    assert any("--dry-run" in example for example in examples)
    assert any("--dry-run" not in example for example in examples)
    assert all(len(line) <= 80 for line in output.splitlines())


def test_parser_displays_timezone_flag_in_validate_help(capsys):
    output = _help_output(["validate", "--help"], capsys)
    assert "--timezone" in output


def test_parser_displays_timezone_flag_in_deploy_help(capsys):
    output = _help_output(["deploy", "--help"], capsys)
    assert "--timezone" in output


@pytest.mark.parametrize(
    "args",
    [
        [
            "deploy",
            "--config-dir",
            "cfg",
            "--warehouse-id",
            "wh",
            "--timezone",
            "Australia/Melbourne",
        ],
        [
            "--config-dir",
            "cfg",
            "--warehouse-id",
            "wh",
            "--timezone",
            "Australia/Melbourne",
        ],
    ],
    ids=["modern-deploy", "legacy-invocation"],
)
def test_parser_accepts_timezone_for_deploy_invocations(args):
    namespace = parse_cli_args(args)
    assert namespace.timezone == "Australia/Melbourne"


def test_parser_reports_actionable_error_when_command_is_unknown(capsys):
    with pytest.raises(SystemExit) as exc_info:
        parse_cli_args(["unknown"])

    assert exc_info.value.code == 2
    error = capsys.readouterr().err
    assert "✖" in error or "[ERROR]" in error
    assert re.search(r"unknown|invalid command", error, re.IGNORECASE)
    assert "uc-abac --help" in error
    assert "COMMANDS:" not in error
    assert "EXAMPLES:" not in error


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
        [
            "deploy",
            "--config-dir",
            "cfg",
            "--warehouse-id",
            "wh",
            "--system-catalog",
            "system",
        ],
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
