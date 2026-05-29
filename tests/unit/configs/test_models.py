from __future__ import annotations

import pytest
from pydantic import ValidationError

from uc_declarative_abac.configs.models import FunctionConfig, ParameterConfig, ResourcesConfig
from uc_declarative_abac.types import DuplicateResourceError


def _minimal_catalog(**overrides):
    """Return a minimal valid catalog dict, with optional overrides."""
    base = {"name": "test_catalog"}
    base.update(overrides)
    return base


def _full_config():
    """Return a fully-populated, well-formed config dict."""
    return {
        "catalogs": {
            "analytics": {
                "name": "analytics",
                "tags": {"domain": "analytics", "env": "prod"},
                "policies": [
                    {
                        "name": "analyst_read",
                        "type": "grant",
                        "privileges": ["select", "use_schema"],
                        "to": ["analysts"],
                        "has_tags": {"domain": "analytics"},
                    }
                ],
                "schemas": [
                    {
                        "name": "sales",
                        "tags": {"team": "sales"},
                        "tables": [
                            {
                                "name": "orders",
                                "tags": {"pii": "true"},
                                "columns": [
                                    {"name": "email", "tags": {"pii_type": "email"}},
                                    {"name": "amount"},
                                ],
                            }
                        ],
                        "volumes": [
                            {"name": "raw_events", "tags": {"classification": "raw"}}
                        ],
                    }
                ],
            }
        }
    }


# ---------------------------------------------------------------------------
# ResourcesConfig
# ---------------------------------------------------------------------------


def test_config_file_validates_valid_config():
    """A well-formed resolved dict passes ResourcesConfig.model_validate() without errors."""
    config = ResourcesConfig.model_validate(_full_config())

    catalog = config.catalogs["analytics"]
    assert catalog.name == "analytics"
    assert catalog.tags == {"domain": "analytics", "env": "prod"}
    assert len(catalog.policies) == 1
    assert catalog.policies[0].privileges == ["select", "use_schema"]
    assert len(catalog.schemas) == 1
    schema = catalog.schemas[0]
    assert schema.name == "sales"
    assert len(schema.tables) == 1
    assert len(schema.volumes) == 1
    assert len(schema.tables[0].columns) == 2


def test_config_file_rejects_missing_catalogs():
    """A dict with no 'catalogs' key raises a validation error."""
    with pytest.raises(ValidationError) as exc_info:
        ResourcesConfig.model_validate({})

    errors = exc_info.value.errors()
    assert any(e["loc"] == ("catalogs",) for e in errors)


# ---------------------------------------------------------------------------
# GrantPolicyConfig
# ---------------------------------------------------------------------------


def test_grant_policy_config_rejects_missing_privileges():
    """A grant policy without 'privileges' raises a validation error."""
    data = {
        "catalogs": {
            "cat": {
                "name": "cat",
                "policies": [
                    {
                        "type": "grant",
                        "to": ["analysts"],
                        "has_tags": {"domain": "analytics"},
                    }
                ],
            }
        }
    }
    with pytest.raises(ValidationError) as exc_info:
        ResourcesConfig.model_validate(data)

    errors = exc_info.value.errors()
    assert any("privileges" in str(e["loc"]) for e in errors)


def test_grant_policy_config_rejects_missing_to():
    """A grant policy without 'to' raises a validation error."""
    data = {
        "catalogs": {
            "cat": {
                "name": "cat",
                "policies": [
                    {
                        "type": "grant",
                        "privileges": ["select"],
                        "tags": {"domain": "analytics"},
                    }
                ],
            }
        }
    }
    with pytest.raises(ValidationError) as exc_info:
        ResourcesConfig.model_validate(data)

    errors = exc_info.value.errors()
    assert any("to" in str(e["loc"]) for e in errors)


# ---------------------------------------------------------------------------
# CatalogConfig
# ---------------------------------------------------------------------------


def test_catalog_config_allows_optional_fields():
    """A catalog with only 'name' and no tags, schemas, or policies validates successfully."""
    data = {
        "catalogs": {
            "bare": {"name": "bare"}
        }
    }
    config = ResourcesConfig.model_validate(data)

    catalog = config.catalogs["bare"]
    assert catalog.name == "bare"
    assert catalog.tags is None
    assert catalog.schemas is None
    assert catalog.policies is None


def test_config_file_injects_name_from_catalog_dict_key():
    """When a catalog has no 'name' field, the dict key is used as the name."""
    data = {
        "catalogs": {
            "operations_prod": {
                "tags": {"env": "prod"},
            },
            "operations_test": {
                "tags": {"env": "test"},
            },
        },
    }
    config = ResourcesConfig.model_validate(data)

    assert config.catalogs["operations_prod"].name == "operations_prod"
    assert config.catalogs["operations_test"].name == "operations_test"


def test_config_file_preserves_explicit_catalog_name():
    """When a catalog has an explicit 'name' field, it is preserved."""
    data = {
        "catalogs": {
            "ops_prod": {
                "name": "operations_production",
                "tags": {"env": "prod"},
            },
        },
    }
    config = ResourcesConfig.model_validate(data)

    assert config.catalogs["ops_prod"].name == "operations_production"


# ---------------------------------------------------------------------------
# Schema and table policies
# ---------------------------------------------------------------------------


def test_schema_config_accepts_policies():
    """A schema with a policies list containing one grant policy parses successfully."""
    data = {
        "catalogs": {
            "cat": {
                "schemas": [
                    {
                        "name": "sales",
                        "policies": [
                            {
                                "type": "grant",
                                "privileges": ["select"],
                                "to": ["analysts"],
                                "has_tags": {"team": "data"},
                            }
                        ],
                    }
                ],
            }
        }
    }
    config = ResourcesConfig.model_validate(data)

    schema = config.catalogs["cat"].schemas[0]
    assert len(schema.policies) == 1


def test_table_config_accepts_policies():
    """A table with a policies list containing one grant policy parses successfully."""
    data = {
        "catalogs": {
            "cat": {
                "schemas": [
                    {
                        "name": "default",
                        "tables": [
                            {
                                "name": "orders",
                                "policies": [
                                    {
                                        "type": "grant",
                                        "privileges": ["modify"],
                                        "to": ["writers"],
                                        "has_tags": {"sales": None},
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        }
    }
    config = ResourcesConfig.model_validate(data)

    table = config.catalogs["cat"].schemas[0].tables[0]
    assert len(table.policies) == 1


# ---------------------------------------------------------------------------
# Null tag value coercion
# ---------------------------------------------------------------------------


def test_securable_config_converts_null_tag_values_to_empty_string():
    """Tags with None values (from YAML ~) are coerced to empty strings."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "tags": {"env": "prod", "operations": None},
                }
            }
        }
    )
    tags = config.catalogs["my_catalog"].tags
    assert tags["env"] == "prod"
    assert tags["operations"] == ""


def test_grant_policy_config_converts_null_tag_values_to_empty_string():
    """Grant policy tags with None values are coerced to empty strings."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["team"],
                            "has_tags": {"env": "prod", "operations": None},
                        }
                    ],
                }
            }
        }
    )
    policy = config.catalogs["my_catalog"].policies[0]
    assert policy.has_tags["env"] == "prod"
    assert policy.has_tags["operations"] == ""


# ---------------------------------------------------------------------------
# Expiry date
# ---------------------------------------------------------------------------


def test_grant_policy_config_accepts_expiry_date():
    """A grant policy with an expiry_date parses successfully."""
    from datetime import date

    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["team"],
                            "has_tags": {"env": "prod"},
                            "expiry_date": date(2026, 5, 1),
                        }
                    ],
                }
            }
        }
    )
    policy = config.catalogs["cat"].policies[0]
    assert policy.expiry_date == date(2026, 5, 1)


def test_grant_policy_config_defaults_expiry_date_to_none():
    """A grant policy without expiry_date defaults to None."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["team"],
                            "has_tags": {"env": "prod"},
                        }
                    ],
                }
            }
        }
    )
    policy = config.catalogs["cat"].policies[0]
    assert policy.expiry_date is None


# ---------------------------------------------------------------------------
# Parent context and full_name
# ---------------------------------------------------------------------------


def test_catalog_config_injects_catalog_name_into_schemas():
    """Schemas inherit catalog_name from their parent catalog."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_catalog": {
                "schemas": [{"name": "sales"}]
            }
        }
    })
    assert config.catalogs["my_catalog"].schemas[0].catalog_name == "my_catalog"


def test_schema_config_injects_names_into_tables():
    """Tables inherit catalog_name and schema_name from their parent schema."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_catalog": {
                "schemas": [
                    {
                        "name": "sales",
                        "tables": [{"name": "orders"}],
                    }
                ]
            }
        }
    })
    table = config.catalogs["my_catalog"].schemas[0].tables[0]
    assert table.catalog_name == "my_catalog"
    assert table.schema_name == "sales"


def test_table_config_injects_names_into_columns():
    """Columns inherit catalog_name, schema_name, and table_name from their parent table."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_catalog": {
                "schemas": [
                    {
                        "name": "sales",
                        "tables": [
                            {
                                "name": "orders",
                                "columns": [{"name": "email"}],
                            }
                        ],
                    }
                ]
            }
        }
    })
    column = config.catalogs["my_catalog"].schemas[0].tables[0].columns[0]
    assert column.catalog_name == "my_catalog"
    assert column.schema_name == "sales"
    assert column.table_name == "orders"


def test_catalog_config_injects_catalog_name_into_policies():
    """Catalog-level grant policies inherit catalog_name from their parent catalog."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_catalog": {
                "policies": [
                    {"type": "grant", "privileges": ["select"], "to": ["team"], "tags": {"env": "prod"}}
                ]
            }
        }
    })
    policy = config.catalogs["my_catalog"].policies[0]
    assert policy.catalog_name == "my_catalog"


def test_schema_config_injects_names_into_policies():
    """Schema-level grant policies inherit catalog_name and schema_name from their parents."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_catalog": {
                "schemas": [
                    {
                        "name": "sales",
                        "policies": [
                            {"type": "grant", "privileges": ["select"], "to": ["team"], "tags": {"env": "prod"}}
                        ],
                    }
                ]
            }
        }
    })
    policy = config.catalogs["my_catalog"].schemas[0].policies[0]
    assert policy.catalog_name == "my_catalog"
    assert policy.schema_name == "sales"


def test_catalog_config_has_full_name():
    """CatalogConfig.full_name returns the catalog name."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_catalog": {}
        }
    })
    assert config.catalogs["my_catalog"].full_name == "my_catalog"


def test_schema_config_has_full_name():
    """SchemaConfig.full_name returns catalog.schema."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_catalog": {
                "schemas": [{"name": "sales"}]
            }
        }
    })
    assert config.catalogs["my_catalog"].schemas[0].full_name == "my_catalog.sales"


def test_table_config_has_full_name():
    """TableConfig.full_name returns catalog.schema.table."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_catalog": {
                "schemas": [
                    {
                        "name": "sales",
                        "tables": [{"name": "orders"}],
                    }
                ]
            }
        }
    })
    assert config.catalogs["my_catalog"].schemas[0].tables[0].full_name == "my_catalog.sales.orders"


def test_volume_config_has_full_name():
    """VolumeConfig.full_name returns catalog.schema.volume."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_catalog": {
                "schemas": [
                    {
                        "name": "landing",
                        "volumes": [{"name": "files"}],
                    }
                ]
            }
        }
    })
    assert config.catalogs["my_catalog"].schemas[0].volumes[0].full_name == "my_catalog.landing.files"


def test_column_config_has_full_name():
    """ColumnConfig.full_name returns catalog.schema.table.column."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_catalog": {
                "schemas": [
                    {
                        "name": "sales",
                        "tables": [
                            {
                                "name": "orders",
                                "columns": [{"name": "email"}],
                            }
                        ],
                    }
                ]
            }
        }
    })
    assert config.catalogs["my_catalog"].schemas[0].tables[0].columns[0].full_name == "my_catalog.sales.orders.email"


# ---------------------------------------------------------------------------
# Duplicate resource detection
# ---------------------------------------------------------------------------


def test_resources_config_rejects_duplicate_catalog_names():
    """Two catalog entries keyed under different dict keys but sharing the same
    explicit ``name`` raise DuplicateResourceError."""
    with pytest.raises(DuplicateResourceError):
        ResourcesConfig.model_validate({
            "catalogs": {
                "entry_one": {"name": "same_catalog"},
                "entry_two": {"name": "same_catalog"},
            }
        })


def test_resources_config_rejects_duplicate_governed_tag_names():
    """Two governed tag entries sharing the same explicit ``name`` raise
    DuplicateResourceError."""
    with pytest.raises(DuplicateResourceError):
        ResourcesConfig.model_validate({
            "catalogs": {"cat": {}},
            "governed_tags": {
                "entry_one": {"name": "shared_tag"},
                "entry_two": {"name": "shared_tag"},
            },
        })


def test_catalog_config_rejects_duplicate_schema_names():
    """Two schemas with the same name under one catalog raise DuplicateResourceError."""
    with pytest.raises(DuplicateResourceError):
        ResourcesConfig.model_validate({
            "catalogs": {
                "my_cat": {
                    "schemas": [
                        {"name": "sales"},
                        {"name": "sales"},
                    ],
                }
            }
        })


def test_schema_config_rejects_duplicate_table_names():
    """Two tables with the same name under one schema raise DuplicateResourceError."""
    with pytest.raises(DuplicateResourceError):
        ResourcesConfig.model_validate({
            "catalogs": {
                "my_cat": {
                    "schemas": [
                        {
                            "name": "sales",
                            "tables": [
                                {"name": "orders"},
                                {"name": "orders"},
                            ],
                        }
                    ],
                }
            }
        })


def test_schema_config_rejects_duplicate_volume_names():
    """Two volumes with the same name under one schema raise DuplicateResourceError."""
    with pytest.raises(DuplicateResourceError):
        ResourcesConfig.model_validate({
            "catalogs": {
                "my_cat": {
                    "schemas": [
                        {
                            "name": "landing",
                            "volumes": [
                                {"name": "files"},
                                {"name": "files"},
                            ],
                        }
                    ],
                }
            }
        })


def test_table_config_rejects_duplicate_column_names():
    """Two columns with the same name under one table raise DuplicateResourceError."""
    with pytest.raises(DuplicateResourceError):
        ResourcesConfig.model_validate({
            "catalogs": {
                "my_cat": {
                    "schemas": [
                        {
                            "name": "sales",
                            "tables": [
                                {
                                    "name": "orders",
                                    "columns": [
                                        {"name": "email"},
                                        {"name": "email"},
                                    ],
                                }
                            ],
                        }
                    ],
                }
            }
        })


def test_catalog_config_allows_same_name_in_different_parents():
    """Two tables named 'orders' in different schemas should NOT raise an error."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "schemas": [
                    {
                        "name": "sales",
                        "tables": [{"name": "orders"}],
                    },
                    {
                        "name": "marketing",
                        "tables": [{"name": "orders"}],
                    },
                ],
            }
        }
    })
    assert len(config.catalogs["my_cat"].schemas) == 2


# ---------------------------------------------------------------------------
# ColumnConfig.owner validation
# ---------------------------------------------------------------------------


def test_column_config_rejects_explicit_owner():
    """A column with an explicit 'owner' field raises a ValidationError."""
    data = {
        "catalogs": {
            "my_catalog": {
                "schemas": [
                    {
                        "name": "sales",
                        "tables": [
                            {
                                "name": "orders",
                                "columns": [
                                    {"name": "email", "owner": "someone"},
                                ],
                            }
                        ],
                    }
                ]
            }
        }
    }
    with pytest.raises(ValidationError) as exc_info:
        ResourcesConfig.model_validate(data)

    assert "inherited" in str(exc_info.value).lower() or "table" in str(exc_info.value).lower()


def test_column_config_allows_omitted_owner():
    """A column without an 'owner' field validates successfully with owner as None."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_catalog": {
                "schemas": [
                    {
                        "name": "sales",
                        "tables": [
                            {
                                "name": "orders",
                                "columns": [{"name": "email"}],
                            }
                        ],
                    }
                ]
            }
        }
    })
    column = config.catalogs["my_catalog"].schemas[0].tables[0].columns[0]
    assert column.owner is None


def test_column_config_accepts_optional_data_type():
    """ColumnConfig carries a 'data_type' string when declared (used for table creation)."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_catalog": {
                "schemas": [
                    {
                        "name": "sales",
                        "tables": [
                            {
                                "name": "orders",
                                "columns": [{"name": "email", "data_type": "STRING"}],
                            }
                        ],
                    }
                ]
            }
        }
    })
    column = config.catalogs["my_catalog"].schemas[0].tables[0].columns[0]
    assert column.data_type == "STRING"


def test_column_config_accepts_type_as_alias_for_data_type():
    """'type' is accepted on input as a backward-compatible alias of 'data_type'."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_catalog": {
                "schemas": [
                    {
                        "name": "sales",
                        "tables": [
                            {
                                "name": "orders",
                                "columns": [{"name": "email", "type": "STRING"}],
                            }
                        ],
                    }
                ]
            }
        }
    })
    column = config.catalogs["my_catalog"].schemas[0].tables[0].columns[0]
    assert column.data_type == "STRING"


def test_column_config_data_type_defaults_to_none():
    """ColumnConfig.data_type is None when not declared."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_catalog": {
                "schemas": [
                    {
                        "name": "sales",
                        "tables": [
                            {
                                "name": "orders",
                                "columns": [{"name": "email"}],
                            }
                        ],
                    }
                ]
            }
        }
    })
    column = config.catalogs["my_catalog"].schemas[0].tables[0].columns[0]
    assert column.data_type is None


# ---------------------------------------------------------------------------
# Catalog/Schema/Table/Volume comment + location fields
# ---------------------------------------------------------------------------


def test_catalog_config_accepts_comment_and_location():
    """Catalog configs round-trip 'comment' and 'location' (managed location, CREATE-only)."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "comment": "Prod analytics catalog",
                "location": "s3://prod-bucket/my_cat",
            },
        },
    })
    cat = config.catalogs["my_cat"]
    assert cat.comment == "Prod analytics catalog"
    assert cat.location == "s3://prod-bucket/my_cat"


def test_schema_config_accepts_comment_and_location():
    """Schema configs round-trip 'comment' and 'location' (managed location, CREATE-only)."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "schemas": [
                    {
                        "name": "sales",
                        "comment": "Sales data",
                        "location": "s3://prod-bucket/my_cat/sales",
                    },
                ],
            },
        },
    })
    schema = config.catalogs["my_cat"].schemas[0]
    assert schema.comment == "Sales data"
    assert schema.location == "s3://prod-bucket/my_cat/sales"


def test_table_config_accepts_comment_and_location():
    """Table configs round-trip 'comment' and 'location' (external location)."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "schemas": [
                    {
                        "name": "sales",
                        "tables": [
                            {
                                "name": "orders",
                                "comment": "Orders fact table",
                                "location": "s3://external/orders",
                            },
                        ],
                    },
                ],
            },
        },
    })
    table = config.catalogs["my_cat"].schemas[0].tables[0]
    assert table.comment == "Orders fact table"
    assert table.location == "s3://external/orders"


def test_volume_config_accepts_comment_and_location():
    """Volume configs round-trip 'comment' and 'location' (external location)."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "schemas": [
                    {
                        "name": "landing",
                        "volumes": [
                            {
                                "name": "raw",
                                "comment": "Raw landing volume",
                                "location": "s3://external/raw_volumes/raw",
                            },
                        ],
                    },
                ],
            },
        },
    })
    volume = config.catalogs["my_cat"].schemas[0].volumes[0]
    assert volume.comment == "Raw landing volume"
    assert volume.location == "s3://external/raw_volumes/raw"


def test_taggable_configs_default_comment_and_location_to_none():
    """When 'comment'/'location' are omitted, they default to None."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "schemas": [
                    {
                        "name": "sales",
                        "tables": [{"name": "orders"}],
                        "volumes": [{"name": "raw"}],
                    },
                ],
            },
        },
    })
    cat = config.catalogs["my_cat"]
    schema = cat.schemas[0]
    assert cat.comment is None and cat.location is None
    assert schema.comment is None and schema.location is None
    assert schema.tables[0].comment is None and schema.tables[0].location is None
    assert schema.volumes[0].comment is None and schema.volumes[0].location is None


# ---------------------------------------------------------------------------
# comment double-quote rejection
# ---------------------------------------------------------------------------
#
# Comments are emitted into SQL as ``COMMENT "<value>"`` (see
# ``_build_comment_clause`` in ``src/uc_declarative_abac/securables/executor.py``).
# A ``"`` inside the value would break the quoting; reject at config-load
# instead of trying to escape it. Single quotes must still be permitted —
# they round-trip cleanly through the existing escaping logic exercised by
# ``test_securable_executor_escapes_single_quotes_in_comment_update``.


def test_catalog_config_accepts_comment_without_double_quote():
    """A catalog comment containing no '\"' character validates successfully."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "comment": "Hello world",
            },
        },
    })
    assert config.catalogs["my_cat"].comment == "Hello world"


def test_catalog_config_accepts_comment_with_single_quote():
    """Regression guard: single quotes (') in comments must still validate —
    only double quotes are rejected."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "comment": "It's fine",
            },
        },
    })
    assert config.catalogs["my_cat"].comment == "It's fine"


def test_catalog_config_rejects_comment_containing_double_quote():
    """A catalog comment containing a '\"' character raises ValidationError."""
    with pytest.raises(ValidationError):
        ResourcesConfig.model_validate({
            "catalogs": {
                "my_cat": {
                    "comment": 'A "quoted" word',
                },
            },
        })


def test_schema_config_rejects_comment_containing_double_quote():
    """A schema comment containing a '\"' character raises ValidationError."""
    with pytest.raises(ValidationError):
        ResourcesConfig.model_validate({
            "catalogs": {
                "my_cat": {
                    "schemas": [
                        {
                            "name": "sales",
                            "comment": 'A "quoted" word',
                        },
                    ],
                },
            },
        })


def test_table_config_rejects_comment_containing_double_quote():
    """A table comment containing a '\"' character raises ValidationError."""
    with pytest.raises(ValidationError):
        ResourcesConfig.model_validate({
            "catalogs": {
                "my_cat": {
                    "schemas": [
                        {
                            "name": "sales",
                            "tables": [
                                {
                                    "name": "orders",
                                    "comment": 'A "quoted" word',
                                },
                            ],
                        },
                    ],
                },
            },
        })


def test_volume_config_rejects_comment_containing_double_quote():
    """A volume comment containing a '\"' character raises ValidationError."""
    with pytest.raises(ValidationError):
        ResourcesConfig.model_validate({
            "catalogs": {
                "my_cat": {
                    "schemas": [
                        {
                            "name": "landing",
                            "volumes": [
                                {
                                    "name": "raw",
                                    "comment": 'A "quoted" word',
                                },
                            ],
                        },
                    ],
                },
            },
        })


def test_function_config_rejects_comment_containing_double_quote():
    """A function comment containing a '\"' character raises ValidationError."""
    with pytest.raises(ValidationError):
        FunctionConfig.model_validate({
            "name": "mask_pii_email",
            "owner": None,
            "catalog_name": "my_catalog",
            "schema_name": "shared",
            "parameters": [{"name": "col", "type": "STRING"}],
            "return": "CASE WHEN is_member('admins') THEN col ELSE '***' END",
            "comment": 'A "quoted" word',
        })


def test_catalog_config_comment_validation_message_mentions_double_quote():
    """The ValidationError message for a comment containing a '\"' should be
    operator-friendly — it must mention the double-quote character, the
    phrase 'double-quote', or 'comment' so the cause is obvious."""
    with pytest.raises(ValidationError) as exc_info:
        ResourcesConfig.model_validate({
            "catalogs": {
                "my_cat": {
                    "comment": 'Says "hi" inside',
                },
            },
        })
    rendered = str(exc_info.value).lower()
    assert '"' in rendered or "double-quote" in rendered or "comment" in rendered


# ---------------------------------------------------------------------------
# ParameterConfig.data_type coercion + alias
# ---------------------------------------------------------------------------


def test_parameter_config_coerces_lowercase_data_type():
    """A lowercase value supplied via the legacy 'type' YAML key is coerced to upper case
    and stored on the canonical `data_type` attribute."""
    param = ParameterConfig.model_validate({"name": "col", "type": "string"})
    assert param.data_type == "STRING"


def test_parameter_config_accepts_data_type_alias():
    """The canonical 'data_type' YAML key is accepted (alongside the legacy 'type' alias)."""
    param = ParameterConfig.model_validate({"name": "col", "data_type": "INT"})
    assert param.data_type == "INT"


# ---------------------------------------------------------------------------
# FunctionConfig.tags validation
# ---------------------------------------------------------------------------


def test_function_config_rejects_tags():
    """A FunctionConfig with an explicit 'tags' field raises a ValidationError."""
    with pytest.raises(ValidationError):
        FunctionConfig.model_validate({
            "name": "mask_pii_email",
            "owner": None,
            "catalog_name": "my_catalog",
            "schema_name": "shared",
            "parameters": [{"name": "col", "type": "STRING"}],
            "return": "CASE WHEN is_member('admins') THEN col ELSE '***' END",
            "tags": {"env": "prod"},
        })


def test_function_config_allows_omitted_tags():
    """A FunctionConfig without 'tags' validates successfully with tags as None."""
    function = FunctionConfig.model_validate({
        "name": "mask_pii_email",
        "owner": None,
        "catalog_name": "my_catalog",
        "schema_name": "shared",
        "parameters": [{"name": "col", "type": "STRING"}],
        "return": "CASE WHEN is_member('admins') THEN col ELSE '***' END",
    })
    assert function.tags is None


# ---------------------------------------------------------------------------
# MaskPolicyConfig / FilterPolicyConfig
# ---------------------------------------------------------------------------


def _mask_or_filter_policy_catalog(policy_type: str, **policy_overrides) -> dict:
    """Return a catalogs dict holding one mask or filter policy on a table."""
    policy = {
        "name": "p1",
        "type": policy_type,
        "function": "cat.default.fn",
        "to": ["analysts"],
        "except": ["admins"],
        "columns": [{"alias": "c", "has_tags": {"pii": "email"}}],
    }
    policy.update(policy_overrides)
    return {
        "catalogs": {
            "cat": {
                "schemas": [
                    {
                        "name": "s",
                        "tables": [
                            {"name": "t", "policies": [policy]}
                        ],
                    }
                ],
            }
        }
    }


def test_filter_policy_config_allows_missing_columns():
    """A FilterPolicyConfig without a 'columns' field parses successfully with columns=None."""
    data = _mask_or_filter_policy_catalog("filter")
    # Remove columns entirely
    data["catalogs"]["cat"]["schemas"][0]["tables"][0]["policies"][0].pop("columns")
    config = ResourcesConfig.model_validate(data)

    policy = config.catalogs["cat"].schemas[0].tables[0].policies[0]
    assert policy.columns is None


def test_filter_policy_config_allows_empty_columns():
    """A FilterPolicyConfig with an empty 'columns' list parses successfully."""
    data = _mask_or_filter_policy_catalog("filter", columns=[])
    config = ResourcesConfig.model_validate(data)

    policy = config.catalogs["cat"].schemas[0].tables[0].policies[0]
    assert policy.columns == []


def test_mask_policy_config_rejects_missing_columns():
    """A MaskPolicyConfig without a 'columns' field raises a validation error."""
    data = _mask_or_filter_policy_catalog("mask")
    data["catalogs"]["cat"]["schemas"][0]["tables"][0]["policies"][0].pop("columns")
    with pytest.raises(ValidationError):
        ResourcesConfig.model_validate(data)


def test_mask_policy_config_rejects_empty_columns():
    """A MaskPolicyConfig with an empty 'columns' list raises a validation error."""
    data = _mask_or_filter_policy_catalog("mask", columns=[])
    with pytest.raises(ValidationError) as exc_info:
        ResourcesConfig.model_validate(data)

    assert "at least one column" in str(exc_info.value)


def test_mask_policy_config_accepts_single_column():
    """A MaskPolicyConfig with exactly one column entry parses successfully."""
    data = _mask_or_filter_policy_catalog("mask")
    config = ResourcesConfig.model_validate(data)

    policy = config.catalogs["cat"].schemas[0].tables[0].policies[0]
    assert len(policy.columns) == 1
    assert policy.columns[0].alias == "c"


def test_mask_policy_config_accepts_multiple_columns():
    """A MaskPolicyConfig with multiple column entries parses successfully."""
    data = _mask_or_filter_policy_catalog(
        "mask",
        columns=[
            {"alias": "c1", "has_tags": {"pii": "email"}},
            {"alias": "c2", "has_tags": {"pii": "phone"}},
        ],
    )
    config = ResourcesConfig.model_validate(data)

    policy = config.catalogs["cat"].schemas[0].tables[0].policies[0]
    assert [c.alias for c in policy.columns] == ["c1", "c2"]


def test_fgac_policy_rejects_duplicate_column_aliases():
    """Two column entries sharing the same 'alias' in the same policy raise DuplicateResourceError."""
    data = _mask_or_filter_policy_catalog(
        "mask",
        columns=[
            {"alias": "shared", "has_tags": {"pii": "email"}},
            {"alias": "shared", "has_tags": {"pii": "phone"}},
        ],
    )
    with pytest.raises(DuplicateResourceError, match="shared"):
        ResourcesConfig.model_validate(data)


def test_fgac_policy_allows_distinct_column_aliases():
    """Distinct aliases (already covered) — sanity check that the duplicate guard is specific."""
    data = _mask_or_filter_policy_catalog(
        "mask",
        columns=[
            {"alias": "a", "has_tags": {"pii": "email"}},
            {"alias": "b", "has_tags": {"pii": "phone"}},
            {"alias": "c", "has_tags": {"pii": "ssn"}},
        ],
    )
    config = ResourcesConfig.model_validate(data)
    policy = config.catalogs["cat"].schemas[0].tables[0].policies[0]
    assert [c.alias for c in policy.columns] == ["a", "b", "c"]


def test_filter_policy_rejects_duplicate_column_aliases():
    """Duplicate check applies to FILTER policies too."""
    data = _mask_or_filter_policy_catalog(
        "filter",
        columns=[
            {"alias": "region", "has_tags": {"geo": "*"}},
            {"alias": "region", "has_tags": {"area": "*"}},
        ],
    )
    with pytest.raises(DuplicateResourceError):
        ResourcesConfig.model_validate(data)


def test_mask_policy_config_accepts_none_except():
    """A MaskPolicyConfig with 'except' explicitly set to None parses successfully
    with exceptions=None."""
    data = _mask_or_filter_policy_catalog("mask")
    data["catalogs"]["cat"]["schemas"][0]["tables"][0]["policies"][0]["except"] = None
    config = ResourcesConfig.model_validate(data)

    policy = config.catalogs["cat"].schemas[0].tables[0].policies[0]
    assert policy.exceptions is None


def test_mask_policy_config_allows_missing_except():
    """A MaskPolicyConfig without an 'except' key parses successfully with
    exceptions=None — 'except' is optional, not required."""
    data = _mask_or_filter_policy_catalog("mask")
    data["catalogs"]["cat"]["schemas"][0]["tables"][0]["policies"][0].pop("except")
    config = ResourcesConfig.model_validate(data)

    policy = config.catalogs["cat"].schemas[0].tables[0].policies[0]
    assert policy.exceptions is None


# ---------------------------------------------------------------------------
# GovernedTagConfig
# ---------------------------------------------------------------------------


def test_resources_config_parses_governed_tags():
    """A ResourcesConfig with a governed_tags block parses each entry into a GovernedTagConfig."""
    data = {
        "catalogs": {"cat": {"name": "cat"}},
        "governed_tags": {
            "pii": {
                "name": "pii",
                "description": "Personally identifiable information",
                "allowed_values": ["name", "email", "phone"],
            }
        },
    }
    config = ResourcesConfig.model_validate(data)

    assert config.governed_tags is not None
    gt = config.governed_tags["pii"]
    assert gt.name == "pii"
    assert gt.description == "Personally identifiable information"
    assert gt.allowed_values == ["name", "email", "phone"]


def test_governed_tag_config_accepts_comment_as_alias_for_description():
    """`comment` is accepted on input as a backward-compatible alias of `description`."""
    data = {
        "catalogs": {"cat": {"name": "cat"}},
        "governed_tags": {
            "pii": {
                "name": "pii",
                "comment": "Legacy field name",
                "allowed_values": ["name"],
            }
        },
    }
    config = ResourcesConfig.model_validate(data)

    assert config.governed_tags["pii"].description == "Legacy field name"


def test_resources_config_injects_governed_tag_name_from_key():
    """When a governed_tags entry has no explicit 'name', the dict key is used."""
    data = {
        "catalogs": {"cat": {"name": "cat"}},
        "governed_tags": {
            "classification": {
                "allowed_values": ["public", "internal"],
            }
        },
    }
    config = ResourcesConfig.model_validate(data)

    assert config.governed_tags["classification"].name == "classification"


def test_resources_config_allows_missing_governed_tags():
    """A config without a governed_tags block is valid; governed_tags defaults to None."""
    data = {"catalogs": {"cat": {"name": "cat"}}}
    config = ResourcesConfig.model_validate(data)

    assert config.governed_tags is None


def test_governed_tag_config_defaults_empty_allowed_values():
    """A governed_tags entry without allowed_values parses with an empty list default."""
    data = {
        "catalogs": {"cat": {"name": "cat"}},
        "governed_tags": {
            "bare": {"name": "bare", "description": "Nothing but a name"},
        },
    }
    config = ResourcesConfig.model_validate(data)

    assert config.governed_tags["bare"].allowed_values == []


def test_governed_tag_config_accepts_assigners():
    """assigners is parsed as a list of principal display names."""
    data = {
        "catalogs": {"cat": {"name": "cat"}},
        "governed_tags": {
            "pii": {
                "name": "pii",
                "allowed_values": ["name"],
                "assigners": ["data_governance_team", "user@company.com"],
            }
        },
    }
    config = ResourcesConfig.model_validate(data)

    gt = config.governed_tags["pii"]
    assert gt.assigners == ["data_governance_team", "user@company.com"]


# ---------------------------------------------------------------------------
# rfa_destinations validation
# ---------------------------------------------------------------------------


_VALID_RFA_DESTINATIONS = [
    "data-gov@example.com",
    "https://hooks.example.com/incoming/abc123",
    "550e8400-e29b-41d4-a716-446655440000",
]


def test_catalog_config_accepts_rfa_destinations_list():
    """A CatalogConfig with rfa_destinations: [email, url, uuid] validates."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "rfa_destinations": list(_VALID_RFA_DESTINATIONS),
            },
        },
    })
    cat = config.catalogs["my_cat"]
    assert list(cat.rfa_destinations) == list(_VALID_RFA_DESTINATIONS)


def test_schema_config_accepts_rfa_destinations_list():
    """A SchemaConfig with rfa_destinations: [email, url, uuid] validates."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "schemas": [
                    {
                        "name": "sales",
                        "rfa_destinations": list(_VALID_RFA_DESTINATIONS),
                    },
                ],
            },
        },
    })
    schema = config.catalogs["my_cat"].schemas[0]
    assert list(schema.rfa_destinations) == list(_VALID_RFA_DESTINATIONS)


def test_table_config_accepts_rfa_destinations_list():
    """A TableConfig with rfa_destinations: [email, url, uuid] validates."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "schemas": [
                    {
                        "name": "sales",
                        "tables": [
                            {
                                "name": "orders",
                                "rfa_destinations": list(_VALID_RFA_DESTINATIONS),
                            },
                        ],
                    },
                ],
            },
        },
    })
    table = config.catalogs["my_cat"].schemas[0].tables[0]
    assert list(table.rfa_destinations) == list(_VALID_RFA_DESTINATIONS)


def test_volume_config_accepts_rfa_destinations_list():
    """A VolumeConfig with rfa_destinations: [email, url, uuid] validates."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "schemas": [
                    {
                        "name": "landing",
                        "volumes": [
                            {
                                "name": "raw",
                                "rfa_destinations": list(_VALID_RFA_DESTINATIONS),
                            },
                        ],
                    },
                ],
            },
        },
    })
    volume = config.catalogs["my_cat"].schemas[0].volumes[0]
    assert list(volume.rfa_destinations) == list(_VALID_RFA_DESTINATIONS)


def test_function_config_accepts_rfa_destinations_list():
    """A FunctionConfig with rfa_destinations: [email, url, uuid] validates."""
    function = FunctionConfig.model_validate({
        "name": "mask_pii_email",
        "owner": None,
        "catalog_name": "my_catalog",
        "schema_name": "shared",
        "parameters": [{"name": "col", "type": "STRING"}],
        "return": "CASE WHEN is_member('admins') THEN col ELSE '***' END",
        "rfa_destinations": list(_VALID_RFA_DESTINATIONS),
    })
    assert list(function.rfa_destinations) == list(_VALID_RFA_DESTINATIONS)


def test_catalog_config_rejects_unrecognised_rfa_destination():
    """A single unrecognised RFA destination string raises ValidationError; the
    error message mentions the offending value."""
    bogus = "not-a-real-destination"
    with pytest.raises(ValidationError) as exc_info:
        ResourcesConfig.model_validate({
            "catalogs": {
                "my_cat": {
                    "rfa_destinations": [bogus],
                },
            },
        })
    assert bogus in str(exc_info.value)


def test_catalog_config_lists_every_offender_when_multiple_invalid():
    """Two unrecognised RFA destinations surface together in a single
    ValidationError that names both offenders."""
    bogus_one = "garbage-one"
    bogus_two = "garbage-two"
    with pytest.raises(ValidationError) as exc_info:
        ResourcesConfig.model_validate({
            "catalogs": {
                "my_cat": {
                    "rfa_destinations": [
                        "valid@example.com",
                        bogus_one,
                        bogus_two,
                    ],
                },
            },
        })
    rendered = str(exc_info.value)
    assert bogus_one in rendered
    assert bogus_two in rendered


def test_catalog_config_rfa_destinations_defaults_to_none():
    """When 'rfa_destinations' is omitted, the model attribute defaults to None."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {},
        },
    })
    assert config.catalogs["my_cat"].rfa_destinations is None


def test_column_config_rejects_rfa_destinations_entirely():
    """Any rfa_destinations value on a ColumnConfig — even a syntactically
    valid one — raises ValidationError with a message that mentions
    rfa_destinations / not being supported on columns."""
    with pytest.raises(ValidationError) as exc_info:
        ResourcesConfig.model_validate({
            "catalogs": {
                "my_cat": {
                    "schemas": [
                        {
                            "name": "sales",
                            "tables": [
                                {
                                    "name": "orders",
                                    "columns": [
                                        {
                                            "name": "email",
                                            "rfa_destinations": ["data-gov@example.com"],
                                        },
                                    ],
                                },
                            ],
                        },
                    ],
                },
            },
        })
    rendered = str(exc_info.value).lower()
    assert "rfa_destinations" in rendered or "not supported on columns" in rendered
