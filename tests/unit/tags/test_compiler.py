from __future__ import annotations

from uc_declarative_abac.configs import ResourcesConfig
from uc_declarative_abac.tags import (
    compile_desired_tags,
    SecurableTag,
)
from uc_declarative_abac.types import SecurableType


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

    result = compile_desired_tags(config)

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

    result = compile_desired_tags(config)

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

    result = compile_desired_tags(config)

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

    result = compile_desired_tags(config)

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

    result = compile_desired_tags(config)

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

    result = compile_desired_tags(config)

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

    result = compile_desired_tags(config)

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

    result = compile_desired_tags(config)

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

    result = compile_desired_tags(config)

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

    result = compile_desired_tags(config)

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
