from __future__ import annotations

import logging

import pytest

import uc_declarative_abac.__main__ as cli


# ---------------------------------------------------------------------------
# Namespace filter flags: deprecation + mutual-exclusion (via main())
# ---------------------------------------------------------------------------


def _run_main(monkeypatch, argv: list[str]) -> dict:
    """Invoke ``main()`` with a stubbed ``run`` and ``WorkspaceClient`` and
    return the keyword args ``run`` was called with."""
    captured: dict = {}

    def _fake_run(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(cli, "run", _fake_run)
    monkeypatch.setattr(cli, "WorkspaceClient", lambda **_: object())
    monkeypatch.setattr(
        "sys.argv",
        ["uc_declarative_abac", "--config-dir", "cfg", "--warehouse-id", "wh", *argv],
    )
    cli.main()
    return captured


def test_main_passes_new_namespace_flag_through_to_run(monkeypatch):
    captured = _run_main(
        monkeypatch, ["--manage-tags-for-namespaces", "cat_a.sch1"],
    )
    assert captured["manage_tags_for_namespaces"] == "cat_a.sch1"


def test_main_defaults_namespace_flag_to_star_when_unset(monkeypatch):
    captured = _run_main(monkeypatch, [])
    assert captured["manage_tags_for_namespaces"] == "*"
    assert captured["create_taggables_for_namespaces"] == "*"


def test_main_converts_deprecated_catalog_flag_and_warns(monkeypatch, caplog):
    with caplog.at_level(logging.WARNING, logger="uc_declarative_abac"):
        captured = _run_main(
            monkeypatch, ["--manage-tags-for-catalogs", "cat_a"],
        )
    assert captured["manage_tags_for_namespaces"] == "cat_a"
    assert any(
        "manage-tags-for-catalogs" in r.getMessage()
        and "manage-tags-for-namespaces" in r.getMessage()
        for r in caplog.records
    ), "Expected a deprecation warning naming both the old and new flags"


def test_main_fails_when_old_and_new_namespace_flags_combined(monkeypatch):
    with pytest.raises(SystemExit):
        _run_main(
            monkeypatch,
            ["--manage-tags-for-catalogs", "cat_a", "--manage-tags-for-namespaces", "cat_a"],
        )


# ---------------------------------------------------------------------------
# Policy deletion flags
# ---------------------------------------------------------------------------


def test_main_passes_enable_policy_deletion_through_to_run(monkeypatch):
    captured = _run_main(monkeypatch, ["--enable-policy-deletion"])
    assert captured["enable_policy_deletion"] is True


def test_main_defaults_enable_policy_deletion_off(monkeypatch):
    captured = _run_main(monkeypatch, [])
    assert captured["enable_policy_deletion"] is False


def test_main_passes_delete_policies_namespaces_through_to_run(monkeypatch):
    captured = _run_main(
        monkeypatch, ["--delete-policies-for-namespaces", "cat_a.sch1"],
    )
    assert captured["delete_policies_for_namespaces"] == "cat_a.sch1"


def test_main_defaults_delete_policies_namespaces_to_star(monkeypatch):
    captured = _run_main(monkeypatch, [])
    assert captured["delete_policies_for_namespaces"] == "*"


def test_main_passes_skip_users_fetch_through_to_run(monkeypatch):
    captured = _run_main(monkeypatch, ["--skip-users-fetch"])
    assert captured["skip_users_fetch"] is True


def test_main_defaults_skip_users_fetch_off(monkeypatch):
    captured = _run_main(monkeypatch, [])
    assert captured["skip_users_fetch"] is False
