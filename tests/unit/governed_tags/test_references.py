from __future__ import annotations

from uc_declarative_abac.configs import ResourcesConfig
from uc_declarative_abac.governed_tags import collect_referenced_tag_keys


def test_references_collects_governed_tag_names():
    """Governed tag names are collected from the resources.governed_tags dict keys."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {"cat": {"name": "cat"}},
            "governed_tags": {
                "pii": {"description": "PII data"},
                "classification": {"description": "Data classification"},
                "domain": {"description": "Domain tag"},
            },
        }
    )

    result = collect_referenced_tag_keys(config)

    assert {"pii", "classification", "domain"} <= result


def test_references_collects_domain_governed_tags():
    """Domain governed_tag references are collected."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {"cat": {"name": "cat"}},
            "governed_tags": {
                "finance": {"description": "Finance domain"},
                "sales": {"description": "Sales domain"},
                "engineering": {"description": "Engineering domain"},
            },
            "domains": {
                "finance_domain": {"governed_tag": "finance"},
                "sales_domain": {"governed_tag": "sales"},
            },
        }
    )

    result = collect_referenced_tag_keys(config)

    assert {"finance", "sales"} <= result


def test_references_collects_securable_tag_keys_across_the_catalog_hierarchy():
    """Tags from catalog, schema, table, column, and volume securables are collected."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "name": "cat",
                    "tags": {"catalog_tag": "value1"},
                    "schemas": [
                        {
                            "name": "s1",
                            "tags": {"schema_tag": "value2"},
                            "tables": [
                                {
                                    "name": "t1",
                                    "tags": {"table_tag": "value3"},
                                    "columns": [
                                        {
                                            "name": "col1",
                                            "tags": {"column_tag": "value4"},
                                        }
                                    ],
                                }
                            ],
                            "volumes": [
                                {
                                    "name": "v1",
                                    "tags": {"volume_tag": "value5"},
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = collect_referenced_tag_keys(config)

    assert {
        "catalog_tag",
        "schema_tag",
        "table_tag",
        "column_tag",
        "volume_tag",
    } <= result


def test_references_collects_policy_tag_condition_keys():
    """has_tags, has_any_of_tags, has_none_of_tags keys from policies are collected."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "name": "cat",
                    "policies": [
                        {
                            "name": "catalog_mask",
                            "type": "mask",
                            "function": "cat.default.mask_fn",
                            "has_tags": {"pii": "email"},
                            "columns": [
                                {
                                    "alias": "col1",
                                    "has_tags": {"col_tag": "value"},
                                }
                            ],
                        }
                    ],
                    "schemas": [
                        {
                            "name": "s",
                            "policies": [
                                {
                                    "name": "schema_filter",
                                    "type": "filter",
                                    "function": "cat.default.filter_fn",
                                    "has_any_of_tags": {"domain": "sales"},
                                    "columns": [
                                        {
                                            "alias": "col2",
                                            "has_tags": {"tag1": "v1"},
                                        }
                                    ],
                                }
                            ],
                            "tables": [
                                {
                                    "name": "t",
                                    "policies": [
                                        {
                                            "name": "table_grant",
                                            "type": "grant",
                                            "privileges": ["select"],
                                            "to": ["analysts"],
                                            "has_tags": {"grant_tag": "yes"},
                                        },
                                        {
                                            "name": "table_mask",
                                            "type": "mask",
                                            "function": "cat.default.mask_fn",
                                            "has_none_of_tags": {"restricted": "yes"},
                                            "columns": [
                                                {
                                                    "alias": "col3",
                                                    "has_any_of_tags": {"tag2": "v2"},
                                                }
                                            ],
                                        },
                                    ],
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = collect_referenced_tag_keys(config)

    assert {
        "pii",
        "col_tag",
        "domain",
        "tag1",
        "tag2",
        "restricted",
        "grant_tag",
    } <= result


def test_references_collects_policy_column_tag_condition_keys():
    """Tag keys in policy column alias has_tags/has_any_of_tags/has_none_of_tags are collected."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "name": "cat",
                    "schemas": [
                        {
                            "name": "s",
                            "tables": [
                                {
                                    "name": "t",
                                    "policies": [
                                        {
                                            "name": "multi_column_policy",
                                            "type": "mask",
                                            "function": "cat.default.mask_fn",
                                            "columns": [
                                                {
                                                    "alias": "email_col",
                                                    "has_tags": {"pii": "email"},
                                                },
                                                {
                                                    "alias": "ssn_col",
                                                    "has_any_of_tags": {
                                                        "sensitive": "ssn"
                                                    },
                                                },
                                                {
                                                    "alias": "public_col",
                                                    "has_none_of_tags": {
                                                        "confidential": "yes"
                                                    },
                                                },
                                            ],
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

    result = collect_referenced_tag_keys(config)

    assert {"pii", "sensitive", "confidential"} <= result


def test_references_collects_tag_introspection_expression_tags():
    """Tag keys from get_column_tag_value and get_tag_value expression columns are collected."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "name": "cat",
                    "schemas": [
                        {
                            "name": "s",
                            "tables": [
                                {
                                    "name": "t",
                                    "policies": [
                                        {
                                            "name": "filter_with_expressions",
                                            "type": "filter",
                                            "function": "cat.default.filter_fn",
                                            "columns": [
                                                {
                                                    "alias": "col1",
                                                    "has_tags": {"col_level": "yes"},
                                                },
                                                {
                                                    "expression": "get_column_tag_value",
                                                    "arguments": {
                                                        "alias": "col1",
                                                        "tag": "pii_type",
                                                    },
                                                },
                                                {
                                                    "expression": "get_tag_value",
                                                    "arguments": {
                                                        "tag": "domain",
                                                    },
                                                },
                                            ],
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

    result = collect_referenced_tag_keys(config)

    assert {"col_level", "pii_type", "domain"} <= result


def test_references_returns_empty_set_for_config_without_tag_references():
    """A minimal catalog with no tags, governed_tags, domains, or policies returns an empty set."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "name": "cat",
                    "schemas": [
                        {
                            "name": "s",
                            "tables": [
                                {
                                    "name": "t",
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = collect_referenced_tag_keys(config)

    assert result == set()
