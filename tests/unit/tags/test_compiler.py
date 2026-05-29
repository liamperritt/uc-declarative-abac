from __future__ import annotations

from uc_declarative_abac.configs import ResourcesConfig
from uc_declarative_abac.governed_tags import GovernedTag
from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.tags import (
    compile_desired_tags,
    SecurableTag,
)
from uc_declarative_abac.types import SecurableType
from uc_declarative_abac.utils import DisallowedTagValueError


def _change_logger() -> ChangeLogger:
    return ChangeLogger()


def _compile(
    config: ResourcesConfig,
    governed_tags: set[GovernedTag] | None = None,
    change_logger: ChangeLogger | None = None,
) -> set[SecurableTag]:
    return compile_desired_tags(
        config,
        governed_tags if governed_tags is not None else set(),
        change_logger if change_logger is not None else _change_logger(),
    )


# ---------------------------------------------------------------------------
# Config to securable tag resolution
# ---------------------------------------------------------------------------


def test_tag_compiler_emits_catalog_tags():
    """A catalog with tags produces a SecurableTag for each tag."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "tags": {"env": "prod"},
                }
            }
        }
    )

    result = _compile(config)

    assert result == {
        SecurableTag(
            securable_type=SecurableType.CATALOG,
            securable_full_name="my_catalog",
            tag_name="env",
            tag_value="prod",
        )
    }


def test_tag_compiler_emits_schema_tags():
    """A schema with tags produces a SecurableTag with a two-part full name."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "schemas": [
                        {
                            "name": "sales",
                            "tags": {"team": "revenue"},
                        }
                    ],
                }
            }
        }
    )

    result = _compile(config)

    assert result == {
        SecurableTag(
            securable_type=SecurableType.SCHEMA,
            securable_full_name="my_catalog.sales",
            tag_name="team",
            tag_value="revenue",
        )
    }


def test_tag_compiler_emits_table_tags():
    """A table with tags produces a SecurableTag with a three-part full name."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "schemas": [
                        {
                            "name": "sales",
                            "tables": [
                                {
                                    "name": "orders",
                                    "tags": {"pii": "true"},
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = _compile(config)

    assert result == {
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_catalog.sales.orders",
            tag_name="pii",
            tag_value="true",
        )
    }


def test_tag_compiler_emits_volume_tags():
    """A volume with tags produces a SecurableTag with a three-part full name."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "schemas": [
                        {
                            "name": "landing",
                            "volumes": [
                                {
                                    "name": "files",
                                    "tags": {"classification": "raw"},
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = _compile(config)

    assert result == {
        SecurableTag(
            securable_type=SecurableType.VOLUME,
            securable_full_name="my_catalog.landing.files",
            tag_name="classification",
            tag_value="raw",
        )
    }


def test_tag_compiler_emits_valueless_tags():
    """A tag with None as its value produces a SecurableTag with tag_value="" (empty string)."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "tags": {"operations": None},
                }
            }
        }
    )

    result = _compile(config)

    assert result == {
        SecurableTag(
            securable_type=SecurableType.CATALOG,
            securable_full_name="my_catalog",
            tag_name="operations",
            tag_value="",
        )
    }


def test_tag_compiler_emits_no_tags_when_none_defined():
    """Objects with no tags field produce an empty set."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "schemas": [
                        {
                            "name": "sales",
                            "tables": [{"name": "orders"}],
                            "volumes": [{"name": "files"}],
                        }
                    ],
                }
            }
        }
    )

    result = _compile(config)

    assert result == set()


# ---------------------------------------------------------------------------
# Column tags
# ---------------------------------------------------------------------------


def test_tag_compiler_emits_column_tags():
    """A column with tags produces a SecurableTag with a four-part full name."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "schemas": [
                        {
                            "name": "sales",
                            "tables": [
                                {
                                    "name": "orders",
                                    "columns": [
                                        {
                                            "name": "email",
                                            "tags": {"pii": "true"},
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = _compile(config)

    assert SecurableTag(
        securable_type=SecurableType.COLUMN,
        securable_full_name="my_catalog.sales.orders.email",
        tag_name="pii",
        tag_value="true",
    ) in result


def test_tag_compiler_emits_no_column_tags_when_columns_have_no_tags():
    """A table with columns that have no tags produces no COLUMN-type tags."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "schemas": [
                        {
                            "name": "sales",
                            "tables": [
                                {
                                    "name": "orders",
                                    "columns": [
                                        {
                                            "name": "email",
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = _compile(config)

    column_tags = {t for t in result if t.securable_type == SecurableType.COLUMN}
    assert column_tags == set()


# ---------------------------------------------------------------------------
# Catalog dict key vs name field
# ---------------------------------------------------------------------------


def test_tag_compiler_uses_catalog_name_for_full_names_when_name_differs_from_key():
    """When a catalog's name differs from its dict key, the explicit name is
    used as the catalog segment in full names for the catalog and nested schemas."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "ops_prod": {
                    "name": "operations_production",
                    "tags": {"env": "prod"},
                    "schemas": [
                        {
                            "name": "sales",
                            "tags": {"team": "data"},
                        }
                    ],
                }
            }
        }
    )

    result = _compile(config)

    full_names = {tag.securable_full_name for tag in result}
    assert "operations_production" in full_names, (
        "Catalog full name should use the explicit name"
    )
    assert "operations_production.sales" in full_names, (
        "Schema full name should use the catalog's explicit name"
    )


def test_tag_compiler_defaults_to_dict_key_when_catalog_name_omitted():
    """When no explicit name is set, the catalog dict key is used as the
    catalog segment in securable_full_name for all nested objects."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat_key": {
                    "tags": {"env": "prod"},
                    "schemas": [
                        {
                            "name": "sales",
                            "tags": {"team": "revenue"},
                            "tables": [
                                {
                                    "name": "orders",
                                    "tags": {"pii": "true"},
                                }
                            ],
                            "volumes": [
                                {
                                    "name": "files",
                                    "tags": {"zone": "raw"},
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = _compile(config)

    expected = {
        SecurableTag(
            securable_type=SecurableType.CATALOG,
            securable_full_name="cat_key",
            tag_name="env",
            tag_value="prod",
        ),
        SecurableTag(
            securable_type=SecurableType.SCHEMA,
            securable_full_name="cat_key.sales",
            tag_name="team",
            tag_value="revenue",
        ),
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="cat_key.sales.orders",
            tag_name="pii",
            tag_value="true",
        ),
        SecurableTag(
            securable_type=SecurableType.VOLUME,
            securable_full_name="cat_key.sales.files",
            tag_name="zone",
            tag_value="raw",
        ),
    }
    assert result == expected


# ---------------------------------------------------------------------------
# Governed-tag value validation
# ---------------------------------------------------------------------------


def test_tag_compiler_keeps_tag_when_value_in_allowed_values():
    """A tag whose value is in the governed tag's allowed_values is emitted."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "tags": {"uc_gov_env": "prod"},
                }
            }
        }
    )
    governed_tags = {
        GovernedTag(
            name="uc_gov_env",
            allowed_values=frozenset({"dev", "test", "prod"}),
        )
    }
    change_logger = _change_logger()

    result = _compile(config, governed_tags=governed_tags, change_logger=change_logger)

    assert result == {
        SecurableTag(
            securable_type=SecurableType.CATALOG,
            securable_full_name="my_catalog",
            tag_name="uc_gov_env",
            tag_value="prod",
        )
    }
    assert not change_logger.has_errors


def test_tag_compiler_drops_tag_when_value_not_in_allowed_values():
    """A tag whose value is not in the governed tag's allowed_values is
    dropped from the result and a DisallowedTagValueError is logged."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "tags": {"uc_gov_env": "bogus"},
                }
            }
        }
    )
    governed_tags = {
        GovernedTag(
            name="uc_gov_env",
            allowed_values=frozenset({"dev", "test", "prod"}),
        )
    }
    change_logger = _change_logger()

    result = _compile(config, governed_tags=governed_tags, change_logger=change_logger)

    assert result == set()
    assert change_logger.has_errors
    exceptions = [e.exception for e in change_logger.errors]
    assert any(isinstance(e, DisallowedTagValueError) for e in exceptions)
    combined = " ".join(str(e) for e in exceptions) + " ".join(
        e.context for e in change_logger.errors
    )
    assert "uc_gov_env" in combined
    assert "bogus" in combined
    assert "my_catalog" in combined


def test_tag_compiler_keeps_tag_when_governed_tag_has_empty_allowed_values():
    """A governed tag with empty allowed_values accepts any value — no error."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "tags": {"free_form": "anything goes"},
                }
            }
        }
    )
    governed_tags = {
        GovernedTag(name="free_form", allowed_values=frozenset()),
    }
    change_logger = _change_logger()

    result = _compile(config, governed_tags=governed_tags, change_logger=change_logger)

    assert result == {
        SecurableTag(
            securable_type=SecurableType.CATALOG,
            securable_full_name="my_catalog",
            tag_name="free_form",
            tag_value="anything goes",
        )
    }
    assert not change_logger.has_errors


def test_tag_compiler_keeps_tag_when_tag_name_is_not_governed():
    """A tag whose name doesn't match any governed tag is unconstrained — no error."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "tags": {"ungoverned": "anything"},
                }
            }
        }
    )
    governed_tags = {
        GovernedTag(
            name="uc_gov_env",
            allowed_values=frozenset({"dev", "test", "prod"}),
        )
    }
    change_logger = _change_logger()

    result = _compile(config, governed_tags=governed_tags, change_logger=change_logger)

    assert result == {
        SecurableTag(
            securable_type=SecurableType.CATALOG,
            securable_full_name="my_catalog",
            tag_name="ungoverned",
            tag_value="anything",
        )
    }
    assert not change_logger.has_errors


def test_tag_compiler_logs_one_error_per_offending_tag():
    """Multiple invalid tags each produce a separate logged error."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat_a": {
                    "tags": {"uc_gov_env": "bogus_a"},
                },
                "cat_b": {
                    "tags": {"uc_gov_env": "bogus_b"},
                },
            }
        }
    )
    governed_tags = {
        GovernedTag(
            name="uc_gov_env",
            allowed_values=frozenset({"dev", "test", "prod"}),
        )
    }
    change_logger = _change_logger()

    result = _compile(config, governed_tags=governed_tags, change_logger=change_logger)

    assert result == set()
    disallowed = [
        e for e in change_logger.errors
        if isinstance(e.exception, DisallowedTagValueError)
    ]
    assert len(disallowed) == 2
    combined = " ".join(e.context + " " + str(e.exception) for e in disallowed)
    assert "cat_a" in combined and "bogus_a" in combined
    assert "cat_b" in combined and "bogus_b" in combined


def test_tag_compiler_validates_against_union_of_desired_and_actual_governed_tags():
    """The validation set is the union of desired + actual governed tags —
    a governed tag declared only on UC (not in config) still constrains values."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "tags": {"uc_gov_env": "bogus"},
                }
            }
        }
    )
    # Simulating: uc_gov_env is on UC (actual) but not redeclared in this run's
    # config. The orchestrator passes the union, so validation still fires.
    governed_tags = {
        GovernedTag(
            name="uc_gov_env",
            allowed_values=frozenset({"dev", "test", "prod"}),
        )
    }
    change_logger = _change_logger()

    result = _compile(config, governed_tags=governed_tags, change_logger=change_logger)

    assert result == set()
    assert any(
        isinstance(e.exception, DisallowedTagValueError)
        for e in change_logger.errors
    )
