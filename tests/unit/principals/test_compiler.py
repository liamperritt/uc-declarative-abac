from __future__ import annotations

from datetime import date

from uc_declarative_abac.configs import ResourcesConfig
from uc_declarative_abac.principals import (
    Principal,
    compile_desired_groups,
)
from uc_declarative_abac.types import PrincipalType


def test_groups_compiler_emits_empty_set_when_no_groups():
    """A config without a groups block produces an empty desired-state set."""
    config = ResourcesConfig.model_validate({"catalogs": {"cat": {"name": "cat"}}})

    result = compile_desired_groups(config)

    assert result == set()


def test_groups_compiler_emits_group_from_config():
    """A groups entry compiles into a Group with a matching display_name."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {"cat": {"name": "cat"}},
            "groups": {
                "data_engineers": {"name": "data_engineers"},
            },
        }
    )

    result = compile_desired_groups(config)

    names = {g.display_name for g in result}
    assert "data_engineers" in names


def test_groups_compiler_uses_dict_key_as_name_default():
    """When a groups entry has no explicit 'name', the dict key is used as the name."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {"cat": {"name": "cat"}},
            "groups": {
                "analysts": {"members": ["alice@example.com"]},
            },
        }
    )

    result = compile_desired_groups(config)

    names = {g.display_name for g in result}
    assert "analysts" in names


def test_groups_compiler_emits_unresolved_principal_per_member_entry():
    """Each member name becomes an unresolved Principal carrying that name."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {"cat": {"name": "cat"}},
            "groups": {
                "data_engineers": {
                    "name": "data_engineers",
                    "members": ["alice@example.com", "bob@example.com"],
                },
            },
        }
    )

    result = compile_desired_groups(config)

    grp = next(g for g in result if g.display_name == "data_engineers")
    assert grp.members == frozenset(
        {
            Principal(PrincipalType.UNKNOWN, name="alice@example.com"),
            Principal(PrincipalType.UNKNOWN, name="bob@example.com"),
        }
    )


def test_groups_compiler_emits_empty_members_when_field_missing():
    """A group without members compiles to a Group with an empty members frozenset."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {"cat": {"name": "cat"}},
            "groups": {"data_engineers": {"name": "data_engineers"}},
        }
    )

    result = compile_desired_groups(config)

    grp = next(g for g in result if g.display_name == "data_engineers")
    assert grp.members == frozenset()


def test_groups_compiler_deduplicates_members():
    """Duplicate member names collapse to one frozenset entry."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {"cat": {"name": "cat"}},
            "groups": {
                "data_engineers": {
                    "name": "data_engineers",
                    "members": ["alice@example.com", "alice@example.com"],
                },
            },
        }
    )

    result = compile_desired_groups(config)

    grp = next(g for g in result if g.display_name == "data_engineers")
    assert grp.members == frozenset(
        {
            Principal(PrincipalType.UNKNOWN, name="alice@example.com"),
        }
    )


def test_groups_compiler_leaves_external_id_empty_on_desired_groups():
    """external_id is never set on the desired side — it stays empty on every group."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {"cat": {"name": "cat"}},
            "groups": {
                "data_engineers": {
                    "name": "data_engineers",
                    "members": ["alice@example.com"],
                },
                "analysts": {"name": "analysts"},
            },
        }
    )

    result = compile_desired_groups(config)

    assert all(g.external_id == "" for g in result)


def test_groups_compiler_sets_id_on_group_when_id_in_config():
    """A config group with an 'id' compiles to a Group whose .id equals that value."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {"cat": {"name": "cat"}},
            "groups": {
                "data_engineers": {"name": "data_engineers", "id": "1234567890"},
            },
        }
    )

    result = compile_desired_groups(config)

    grp = next(g for g in result if g.display_name == "data_engineers")
    assert grp.id == "1234567890"


def test_groups_compiler_leaves_id_empty_when_omitted():
    """A config group without 'id' compiles to a Group whose .id == ''."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {"cat": {"name": "cat"}},
            "groups": {"data_engineers": {"name": "data_engineers"}},
        }
    )

    result = compile_desired_groups(config)

    grp = next(g for g in result if g.display_name == "data_engineers")
    assert grp.id == ""


def test_groups_compiler_emits_all_groups_in_config():
    """Every group declared in the config appears in the result."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {"cat": {"name": "cat"}},
            "groups": {
                "data_engineers": {"name": "data_engineers"},
                "analysts": {"name": "analysts"},
                "admins": {"name": "admins"},
            },
        }
    )

    result = compile_desired_groups(config)

    names = {g.display_name for g in result}
    assert names == {"data_engineers", "analysts", "admins"}


# ---------------------------------------------------------------------------
# expiry_date: on/after the date, a group's members are emitted as empty
# ---------------------------------------------------------------------------


def _config_with_expiring_group(expiry_date: str) -> ResourcesConfig:
    return ResourcesConfig.model_validate(
        {
            "catalogs": {"cat": {"name": "cat"}},
            "groups": {
                "temp_access": {
                    "name": "temp_access",
                    "members": ["alice@example.com", "bob@example.com"],
                    "expiry_date": expiry_date,
                },
            },
        }
    )


def test_groups_compiler_emits_empty_members_when_expiry_date_is_past():
    """A group whose expiry_date is before run_date is emitted with empty members
    (the group itself is still present)."""
    config = _config_with_expiring_group("2025-01-01")

    result = compile_desired_groups(config, run_date=date(2025, 6, 1))

    grp = next(g for g in result if g.display_name == "temp_access")
    assert grp.members == frozenset()


def test_groups_compiler_emits_empty_members_when_expiry_date_is_today():
    """expiry is 'on or past' the date: expiry_date == run_date is expired."""
    config = _config_with_expiring_group("2025-06-01")

    result = compile_desired_groups(config, run_date=date(2025, 6, 1))

    grp = next(g for g in result if g.display_name == "temp_access")
    assert grp.members == frozenset()


def test_groups_compiler_keeps_members_when_expiry_date_is_future():
    """A group whose expiry_date is after run_date retains its configured members."""
    config = _config_with_expiring_group("2026-12-31")

    result = compile_desired_groups(config, run_date=date(2025, 6, 1))

    grp = next(g for g in result if g.display_name == "temp_access")
    assert grp.members == frozenset(
        {
            Principal(PrincipalType.UNKNOWN, name="alice@example.com"),
            Principal(PrincipalType.UNKNOWN, name="bob@example.com"),
        }
    )


def test_groups_compiler_keeps_members_when_no_expiry_date():
    """A group without expiry_date retains its members regardless of run_date."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {"cat": {"name": "cat"}},
            "groups": {
                "data_engineers": {
                    "name": "data_engineers",
                    "members": ["alice@example.com"],
                },
            },
        }
    )

    result = compile_desired_groups(config, run_date=date(2099, 12, 31))

    grp = next(g for g in result if g.display_name == "data_engineers")
    assert grp.members == frozenset(
        {Principal(PrincipalType.UNKNOWN, name="alice@example.com")}
    )


def test_groups_compiler_keeps_id_and_name_on_expired_group():
    """An expired group is still emitted (name + id preserved) so it is matchable and
    not dropped from desired — only its members are emptied."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {"cat": {"name": "cat"}},
            "groups": {
                "temp_access": {
                    "name": "temp_access",
                    "id": "g-99",
                    "members": ["alice@example.com"],
                    "expiry_date": "2025-01-01",
                },
            },
        }
    )

    result = compile_desired_groups(config, run_date=date(2025, 6, 1))

    grp = next(g for g in result if g.display_name == "temp_access")
    assert grp.id == "g-99"
    assert grp.members == frozenset()
