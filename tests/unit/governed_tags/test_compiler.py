from __future__ import annotations

from uc_declarative_abac.configs import ResourcesConfig
from uc_declarative_abac.governed_tags import (
    compile_desired_governed_tags,
    GovernedTag,
)
from uc_declarative_abac.principals import Principal
from uc_declarative_abac.types import PrincipalType


def test_governed_tag_compiler_emits_empty_set_when_no_governed_tags():
    """A config without a governed_tags block produces an empty desired-state set."""
    config = ResourcesConfig.model_validate({"catalogs": {"cat": {"name": "cat"}}})

    result = compile_desired_governed_tags(config)

    assert result == set()


def test_governed_tag_compiler_emits_governed_tag_from_config():
    """A governed_tags entry compiles into a GovernedTag with matching name, description, and values."""
    config = ResourcesConfig.model_validate({
        "catalogs": {"cat": {"name": "cat"}},
        "governed_tags": {
            "pii": {
                "name": "pii",
                "description": "PII data",
                "allowed_values": ["name", "email"],
            }
        },
    })

    result = compile_desired_governed_tags(config)

    assert GovernedTag(
        name="pii",
        description="PII data",
        allowed_values=frozenset({"name", "email"}),
    ) in result


def test_governed_tag_compiler_uses_dict_key_as_name_default():
    """When a governed_tags entry has no explicit 'name', the dict key is used as the name."""
    config = ResourcesConfig.model_validate({
        "catalogs": {"cat": {"name": "cat"}},
        "governed_tags": {
            "classification": {"allowed_values": ["public", "internal"]},
        },
    })

    result = compile_desired_governed_tags(config)

    names = {gt.name for gt in result}
    assert "classification" in names


def test_governed_tag_compiler_preserves_description_when_provided():
    """The description field on a governed_tags entry is preserved on the compiled GovernedTag."""
    config = ResourcesConfig.model_validate({
        "catalogs": {"cat": {"name": "cat"}},
        "governed_tags": {
            "pii": {"name": "pii", "description": "Personally identifiable information"},
        },
    })

    result = compile_desired_governed_tags(config)

    pii = next(gt for gt in result if gt.name == "pii")
    assert pii.description == "Personally identifiable information"


def test_governed_tag_compiler_deduplicates_allowed_values_via_frozenset():
    """allowed_values is stored as a frozenset — duplicates in the YAML list collapse to one."""
    config = ResourcesConfig.model_validate({
        "catalogs": {"cat": {"name": "cat"}},
        "governed_tags": {
            "pii": {"name": "pii", "allowed_values": ["name", "email", "name"]},
        },
    })

    result = compile_desired_governed_tags(config)

    pii = next(gt for gt in result if gt.name == "pii")
    assert pii.allowed_values == frozenset({"name", "email"})


# ---------------------------------------------------------------------------
# assigners
# ---------------------------------------------------------------------------


def test_governed_tag_compiler_emits_empty_assigners_when_field_missing():
    """A governed tag without assigners compiles to an empty frozenset."""
    config = ResourcesConfig.model_validate({
        "catalogs": {"cat": {"name": "cat"}},
        "governed_tags": {"pii": {"name": "pii"}},
    })

    result = compile_desired_governed_tags(config)

    pii = next(gt for gt in result if gt.name == "pii")
    assert pii.assigners == frozenset()


def test_governed_tag_compiler_emits_unresolved_principal_per_assigner_entry():
    """Each name in assigners becomes an unresolved Principal carrying that name."""
    config = ResourcesConfig.model_validate({
        "catalogs": {"cat": {"name": "cat"}},
        "governed_tags": {
            "pii": {
                "name": "pii",
                "assigners": ["data_engineers", "alice@example.com"],
            },
        },
    })

    result = compile_desired_governed_tags(config)

    pii = next(gt for gt in result if gt.name == "pii")
    assert pii.assigners == frozenset({
        Principal(PrincipalType.UNKNOWN, name="data_engineers"),
        Principal(PrincipalType.UNKNOWN, name="alice@example.com"),
    })


def test_governed_tag_compiler_deduplicates_assigners():
    """Duplicate assigner names collapse to one frozenset entry."""
    config = ResourcesConfig.model_validate({
        "catalogs": {"cat": {"name": "cat"}},
        "governed_tags": {
            "pii": {
                "name": "pii",
                "assigners": ["data_engineers", "data_engineers"],
            },
        },
    })

    result = compile_desired_governed_tags(config)

    pii = next(gt for gt in result if gt.name == "pii")
    assert pii.assigners == frozenset({
        Principal(PrincipalType.UNKNOWN, name="data_engineers"),
    })
