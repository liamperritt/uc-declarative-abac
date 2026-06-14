from __future__ import annotations

import pytest
from pydantic import ValidationError

from uc_declarative_abac.configs import (
    FunctionConfig,
    ParameterConfig,
    ResourcesConfig,
)
from uc_declarative_abac.types import SecurableType
from uc_declarative_abac.utils import DuplicateResourceError



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


def test_grant_policy_config_rejects_unknown_abstraction():
    """A grant policy with an unknown abstraction string ('delete') in
    'privileges' raises a validation error — only known concrete privileges
    and known abstractions are accepted."""
    data = {
        "catalogs": {
            "cat": {
                "name": "cat",
                "policies": [
                    {
                        "type": "grant",
                        "privileges": ["delete"],
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


def test_grant_policy_config_rejects_missing_name():
    """A grant policy without 'name' raises a validation error — name is
    required on every policy type."""
    data = {
        "catalogs": {
            "cat": {
                "name": "cat",
                "policies": [
                    {
                        "type": "grant",
                        "privileges": ["select"],
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
    assert any("name" in str(e["loc"]) for e in errors)


# ---------------------------------------------------------------------------
# FGAC policy 'to' default
# ---------------------------------------------------------------------------


def _fgac_policy_in_table(policy: dict) -> dict:
    """Wrap a single FGAC policy dict in a minimal resources config (table-attached)."""
    return {
        "catalogs": {
            "cat": {
                "name": "cat",
                "schemas": [
                    {
                        "name": "s",
                        "tables": [{"name": "t", "policies": [policy]}],
                    }
                ],
            }
        }
    }


def test_mask_policy_config_defaults_to_account_users_when_to_omitted():
    """A mask policy that omits 'to' defaults it to ['account users']."""
    config = ResourcesConfig.model_validate(
        _fgac_policy_in_table(
            {
                "name": "p",
                "type": "mask",
                "function": "cat.s.fn",
                "columns": [{"alias": "c", "has_tags": {"pii": "email"}}],
            }
        )
    )
    policy = config.catalogs["cat"].schemas[0].tables[0].policies[0]
    assert policy.to == ["account users"]


def test_filter_policy_config_defaults_to_account_users_when_to_omitted():
    """A filter policy that omits 'to' defaults it to ['account users']."""
    config = ResourcesConfig.model_validate(
        _fgac_policy_in_table(
            {
                "name": "p",
                "type": "filter",
                "function": "cat.s.fn",
            }
        )
    )
    policy = config.catalogs["cat"].schemas[0].tables[0].policies[0]
    assert policy.to == ["account users"]


def test_fgac_policy_config_defaults_to_account_users_when_to_is_null():
    """A mask policy with an explicit null 'to' falls back to ['account users']."""
    config = ResourcesConfig.model_validate(
        _fgac_policy_in_table(
            {
                "name": "p",
                "type": "mask",
                "function": "cat.s.fn",
                "to": None,
                "columns": [{"alias": "c", "has_tags": {"pii": "email"}}],
            }
        )
    )
    policy = config.catalogs["cat"].schemas[0].tables[0].policies[0]
    assert policy.to == ["account users"]


def test_fgac_policy_config_preserves_explicit_to():
    """An explicitly provided 'to' is preserved, not overwritten by the default."""
    config = ResourcesConfig.model_validate(
        _fgac_policy_in_table(
            {
                "name": "p",
                "type": "mask",
                "function": "cat.s.fn",
                "to": ["analysts"],
                "columns": [{"alias": "c", "has_tags": {"pii": "email"}}],
            }
        )
    )
    policy = config.catalogs["cat"].schemas[0].tables[0].policies[0]
    assert policy.to == ["analysts"]


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
                                "name": "g1",
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
                                        "name": "g1",
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
                            "name": "g1",
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
# has_any_of_tags (OR semantics)
# ---------------------------------------------------------------------------


def test_grant_policy_config_accepts_has_any_of_tags():
    """A grant policy may specify has_any_of_tags alongside (or instead of) has_tags."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "policies": [
                        {
                            "name": "g1",
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["team"],
                            "has_any_of_tags": {"zone": "landing", "env": "prod"},
                        }
                    ],
                }
            }
        }
    )
    policy = config.catalogs["my_catalog"].policies[0]
    assert policy.has_any_of_tags == {"zone": "landing", "env": "prod"}


def test_grant_policy_config_converts_null_has_any_of_tags_values_to_empty_string():
    """has_any_of_tags entries with None values are coerced to empty strings."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "policies": [
                        {
                            "name": "g1",
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["team"],
                            "has_any_of_tags": {"env": "prod", "operations": None},
                        }
                    ],
                }
            }
        }
    )
    policy = config.catalogs["my_catalog"].policies[0]
    assert policy.has_any_of_tags["env"] == "prod"
    assert policy.has_any_of_tags["operations"] == ""


def test_grant_policy_config_defaults_has_any_of_tags_to_none():
    """A grant policy without has_any_of_tags defaults the field to None."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "name": "g1",
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
    assert config.catalogs["cat"].policies[0].has_any_of_tags is None


def test_mask_policy_column_accepts_has_any_of_tags_without_has_tags():
    """A mask policy column may match with has_any_of_tags alone (has_tags omitted)."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "schemas": [
                        {
                            "name": "s",
                            "tables": [
                                {
                                    "name": "t",
                                    "policies": [
                                        {
                                            "name": "p",
                                            "type": "mask",
                                            "function": "cat.s.fn",
                                            "to": ["team"],
                                            "columns": [
                                                {
                                                    "alias": "c",
                                                    "has_any_of_tags": {
                                                        "pii": "email",
                                                        "pii_alt": "ssn",
                                                    },
                                                }
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
    column = config.catalogs["cat"].schemas[0].tables[0].policies[0].columns[0]
    assert column.has_tags is None
    assert column.has_any_of_tags == {"pii": "email", "pii_alt": "ssn"}


def test_mask_policy_column_rejects_neither_tag_field():
    """A policy column with neither has_tags nor has_any_of_tags is rejected."""
    with pytest.raises(ValidationError):
        ResourcesConfig.model_validate(
            {
                "catalogs": {
                    "cat": {
                        "schemas": [
                            {
                                "name": "s",
                                "tables": [
                                    {
                                        "name": "t",
                                        "policies": [
                                            {
                                                "name": "p",
                                                "type": "mask",
                                                "function": "cat.s.fn",
                                                "to": ["team"],
                                                "columns": [{"alias": "c"}],
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
                            "name": "g1",
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
                            "name": "g1",
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
                    {"name": "g1", "type": "grant", "privileges": ["select"], "to": ["team"], "tags": {"env": "prod"}}
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
                            {"name": "g1", "type": "grant", "privileges": ["select"], "to": ["team"], "tags": {"env": "prod"}}
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


def test_resources_config_derives_group_name_from_dict_key():
    """A groups entry without an explicit ``name`` takes the dict key as its name."""
    config = ResourcesConfig.model_validate({
        "catalogs": {"cat": {}},
        "groups": {"data_engineers": {"members": ["alice@example.com"]}},
    })

    assert config.groups is not None
    assert config.groups["data_engineers"].name == "data_engineers"
    assert config.groups["data_engineers"].members == ["alice@example.com"]


def test_resources_config_defaults_group_members_to_empty():
    """A groups entry without a ``members`` field defaults to an empty member list."""
    config = ResourcesConfig.model_validate({
        "catalogs": {"cat": {}},
        "groups": {"data_engineers": {}},
    })

    assert config.groups is not None
    assert config.groups["data_engineers"].members == []


def test_resources_config_rejects_duplicate_group_names():
    """Two group entries sharing the same explicit ``name`` raise DuplicateResourceError."""
    with pytest.raises(DuplicateResourceError):
        ResourcesConfig.model_validate({
            "catalogs": {"cat": {}},
            "groups": {
                "entry_one": {"name": "shared_group"},
                "entry_two": {"name": "shared_group"},
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


def test_table_config_rejects_duplicate_policy_names():
    """Two policies sharing a name on one table raise DuplicateResourceError —
    the namespace spans all policy types (a grant and a mask cannot share a name)."""
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
                                    "policies": [
                                        {
                                            "name": "dup",
                                            "type": "grant",
                                            "privileges": ["select"],
                                            "to": ["analysts"],
                                            "has_tags": {"domain": "analytics"},
                                        },
                                        {
                                            "name": "dup",
                                            "type": "mask",
                                            "function": "my_cat.sales.fn",
                                            "columns": [
                                                {"alias": "c", "has_tags": {"pii": "email"}}
                                            ],
                                        },
                                    ],
                                }
                            ],
                        }
                    ],
                }
            }
        })


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


def test_parameter_config_accepts_parameterised_data_type():
    """ParameterConfig accepts a data_type with trailing parameters/arguments
    (e.g. DECIMAL(10,2)) as long as the prefix is a known column type."""
    param = ParameterConfig.model_validate({"name": "col", "data_type": "decimal(10,2)"})
    assert param.data_type.startswith("DECIMAL")


def test_parameter_config_rejects_unknown_data_type():
    """ParameterConfig raises a ValidationError when data_type does not start
    with a value from databricks.sdk.service.catalog.ColumnTypeName."""
    with pytest.raises(ValidationError) as exc_info:
        ParameterConfig.model_validate({"name": "col", "data_type": "FOO"})
    assert "data_type" in str(exc_info.value).lower()


def test_parameter_config_rejects_data_type_that_only_shares_a_prefix():
    """A data_type like 'STRINGISH' must not be accepted just because it
    happens to start with 'STRING' — the prefix must end on a token boundary."""
    with pytest.raises(ValidationError):
        ParameterConfig.model_validate({"name": "col", "data_type": "STRINGISH"})


# ---------------------------------------------------------------------------
# ColumnConfig.data_type validation
# ---------------------------------------------------------------------------


def _column_config_data(data_type):
    return {
        "catalogs": {
            "my_catalog": {
                "schemas": [
                    {
                        "name": "sales",
                        "tables": [
                            {
                                "name": "orders",
                                "columns": [{"name": "email", "data_type": data_type}],
                            }
                        ],
                    }
                ]
            }
        }
    }


def test_column_config_accepts_data_type_case_insensitively():
    """ColumnConfig accepts a known data_type regardless of letter case."""
    config = ResourcesConfig.model_validate(_column_config_data("string"))
    column = config.catalogs["my_catalog"].schemas[0].tables[0].columns[0]
    assert column.data_type is not None


def test_column_config_accepts_parameterised_data_type():
    """ColumnConfig accepts a data_type with trailing parameters/arguments
    (e.g. ARRAY<STRING>) as long as the prefix is a known column type."""
    config = ResourcesConfig.model_validate(_column_config_data("ARRAY<STRING>"))
    column = config.catalogs["my_catalog"].schemas[0].tables[0].columns[0]
    assert column.data_type == "ARRAY<STRING>"


def test_column_config_rejects_unknown_data_type():
    """ColumnConfig raises a ValidationError when data_type does not start
    with a value from databricks.sdk.service.catalog.ColumnTypeName."""
    with pytest.raises(ValidationError) as exc_info:
        ResourcesConfig.model_validate(_column_config_data("FOO"))
    assert "data_type" in str(exc_info.value).lower()


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


# ---------------------------------------------------------------------------
# Constant columns
# ---------------------------------------------------------------------------


def test_mask_policy_config_accepts_trailing_constant_column():
    """A mask policy may have a constant column after the first alias column."""
    data = _mask_or_filter_policy_catalog(
        "mask",
        columns=[
            {"alias": "email", "has_tags": {"pii": "email"}},
            {"constant": "REDACTED"},
        ],
    )
    config = ResourcesConfig.model_validate(data)

    columns = config.catalogs["cat"].schemas[0].tables[0].policies[0].columns
    assert columns[0].alias == "email"
    assert columns[1].constant == "REDACTED"


def test_filter_policy_config_accepts_constant_column():
    """A filter policy may include a constant column."""
    data = _mask_or_filter_policy_catalog(
        "filter",
        columns=[
            {"alias": "region", "has_tags": {"geo": "*"}},
            {"constant": "EU"},
        ],
    )
    config = ResourcesConfig.model_validate(data)

    columns = config.catalogs["cat"].schemas[0].tables[0].policies[0].columns
    assert columns[1].constant == "EU"


def test_mask_policy_config_rejects_leading_constant_column():
    """A mask policy whose first column is a constant is rejected — the masked
    column must be an alias."""
    data = _mask_or_filter_policy_catalog(
        "mask",
        columns=[
            {"constant": "REDACTED"},
            {"alias": "email", "has_tags": {"pii": "email"}},
        ],
    )
    with pytest.raises(ValidationError, match="alias"):
        ResourcesConfig.model_validate(data)


def test_fgac_policy_allows_multiple_constant_columns():
    """Multiple constant columns do not trigger a false duplicate-alias error."""
    data = _mask_or_filter_policy_catalog(
        "mask",
        columns=[
            {"alias": "email", "has_tags": {"pii": "email"}},
            {"constant": "REDACTED"},
            {"constant": "REDACTED"},
        ],
    )
    config = ResourcesConfig.model_validate(data)

    columns = config.catalogs["cat"].schemas[0].tables[0].policies[0].columns
    assert [getattr(c, "constant", None) for c in columns[1:]] == ["REDACTED", "REDACTED"]


def test_policy_column_constant_preserves_native_types():
    """Non-string constant values keep their native Python type (not coerced to str)."""
    from datetime import date

    data = _mask_or_filter_policy_catalog(
        "mask",
        columns=[
            {"alias": "email", "has_tags": {"pii": "email"}},
            {"constant": 42},
            {"constant": True},
            {"constant": date(2026, 6, 5)},
            {"constant": "42"},
        ],
    )
    config = ResourcesConfig.model_validate(data)

    columns = config.catalogs["cat"].schemas[0].tables[0].policies[0].columns
    assert columns[1].constant == 42 and not isinstance(columns[1].constant, bool)
    assert columns[2].constant is True
    assert columns[3].constant == date(2026, 6, 5)
    assert columns[4].constant == "42" and isinstance(columns[4].constant, str)


def test_policy_column_constant_rejects_null():
    """A bare null constant is a config error (no concrete value provided)."""
    data = _mask_or_filter_policy_catalog(
        "mask",
        columns=[
            {"alias": "email", "has_tags": {"pii": "email"}},
            {"constant": None},
        ],
    )
    with pytest.raises(ValidationError):
        ResourcesConfig.model_validate(data)


def test_mask_policy_config_accepts_singular_constant_column():
    """A singular 'column' shorthand also normalises a constant column."""
    data = _mask_or_filter_policy_catalog("filter")
    policy = data["catalogs"]["cat"]["schemas"][0]["tables"][0]["policies"][0]
    policy.pop("columns")
    policy["column"] = {"constant": "EU"}

    config = ResourcesConfig.model_validate(data)

    resolved = config.catalogs["cat"].schemas[0].tables[0].policies[0]
    assert len(resolved.columns) == 1
    assert resolved.columns[0].constant == "EU"


# ---------------------------------------------------------------------------
# Partial function-name qualification
# ---------------------------------------------------------------------------


def _catalog_level_fgac_policy(function: str) -> dict:
    """A filter policy attached directly at the catalog level (no schema)."""
    return {
        "catalogs": {
            "cat": {
                "name": "cat",
                "policies": [{"name": "p", "type": "filter", "function": function}],
            }
        }
    }


@pytest.mark.parametrize("policy_type", ["mask", "filter"])
@pytest.mark.parametrize(
    "given, expected",
    [
        ("fn", "cat.s.fn"),           # bare → catalog.schema.fn
        ("myschema.fn", "cat.myschema.fn"),  # schema.fn → catalog.schema.fn
        ("cat.s.fn", "cat.s.fn"),     # already qualified → unchanged
    ],
)
def test_fgac_policy_config_qualifies_partial_function_name(policy_type, given, expected):
    """A partially-qualified function is completed from the policy's own
    catalog/schema; a fully-qualified name is preserved."""
    data = _mask_or_filter_policy_catalog(policy_type, function=given)
    config = ResourcesConfig.model_validate(data)

    policy = config.catalogs["cat"].schemas[0].tables[0].policies[0]
    assert policy.function == expected


def test_fgac_policy_config_qualifies_schema_dotted_function_at_catalog_level():
    """A catalog-level policy with a 'schema.fn' function qualifies against its catalog."""
    config = ResourcesConfig.model_validate(_catalog_level_fgac_policy("s.fn"))

    assert config.catalogs["cat"].policies[0].function == "cat.s.fn"


def test_fgac_policy_config_qualifies_bare_function_at_catalog_level_to_default_schema():
    """A catalog-level policy has no schema to prepend, so a bare function name
    falls back to the catalog's 'default' schema."""
    config = ResourcesConfig.model_validate(_catalog_level_fgac_policy("fn"))

    assert config.catalogs["cat"].policies[0].function == "cat.default.fn"


def test_mask_policy_config_accepts_single_column_via_column_alias():
    """A MaskPolicyConfig given a singular 'column' dict is normalised to columns=[<dict>]."""
    data = _mask_or_filter_policy_catalog("mask")
    policy = data["catalogs"]["cat"]["schemas"][0]["tables"][0]["policies"][0]
    policy.pop("columns")
    policy["column"] = {"alias": "email", "has_tags": {"pii": "email"}}

    config = ResourcesConfig.model_validate(data)

    resolved = config.catalogs["cat"].schemas[0].tables[0].policies[0]
    assert len(resolved.columns) == 1
    assert resolved.columns[0].alias == "email"
    assert resolved.columns[0].has_tags == {"pii": "email"}


def test_filter_policy_config_accepts_single_column_via_column_alias():
    """A FilterPolicyConfig given a singular 'column' dict is normalised to columns=[<dict>]."""
    data = _mask_or_filter_policy_catalog("filter")
    policy = data["catalogs"]["cat"]["schemas"][0]["tables"][0]["policies"][0]
    policy.pop("columns")
    policy["column"] = {"alias": "region", "has_tags": {"geo": "eu"}}

    config = ResourcesConfig.model_validate(data)

    resolved = config.catalogs["cat"].schemas[0].tables[0].policies[0]
    assert len(resolved.columns) == 1
    assert resolved.columns[0].alias == "region"
    assert resolved.columns[0].has_tags == {"geo": "eu"}


@pytest.mark.parametrize("bad_value", ["email", ["email"], 42, None])
def test_fgac_policy_config_rejects_column_when_not_a_dict(bad_value):
    """If 'column' is supplied but is not a mapping, a validation error is raised."""
    data = _mask_or_filter_policy_catalog("mask")
    policy = data["catalogs"]["cat"]["schemas"][0]["tables"][0]["policies"][0]
    policy.pop("columns")
    policy["column"] = bad_value

    with pytest.raises(ValidationError):
        ResourcesConfig.model_validate(data)


def test_fgac_policy_config_rejects_both_column_and_columns_provided():
    """Supplying both 'column' and 'columns' on the same policy raises a validation error."""
    data = _mask_or_filter_policy_catalog("mask")
    policy = data["catalogs"]["cat"]["schemas"][0]["tables"][0]["policies"][0]
    policy["column"] = {"alias": "email", "has_tags": {"pii": "email"}}
    # 'columns' is already set by the helper

    with pytest.raises(ValidationError):
        ResourcesConfig.model_validate(data)


def test_fgac_policy_config_omits_column_attribute_after_normalisation():
    """After parsing, the resulting model exposes only 'columns' — no leftover 'column' attribute."""
    data = _mask_or_filter_policy_catalog("mask")
    policy = data["catalogs"]["cat"]["schemas"][0]["tables"][0]["policies"][0]
    policy.pop("columns")
    policy["column"] = {"alias": "email", "has_tags": {"pii": "email"}}

    config = ResourcesConfig.model_validate(data)

    resolved = config.catalogs["cat"].schemas[0].tables[0].policies[0]
    assert not hasattr(resolved, "column")
    assert hasattr(resolved, "columns")


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


# ---------------------------------------------------------------------------
# Securable name '__' prefix rejection (reserved for hidden system securables)
# ---------------------------------------------------------------------------


def test_resources_config_rejects_catalog_name_with_double_underscore():
    """A catalog whose name starts with '__' is rejected."""
    with pytest.raises(ValidationError, match="__"):
        ResourcesConfig.model_validate({"catalogs": {"__hidden": {}}})


def test_resources_config_rejects_schema_name_with_double_underscore():
    """A schema whose name starts with '__' is rejected."""
    with pytest.raises(ValidationError, match="__"):
        ResourcesConfig.model_validate(
            {"catalogs": {"cat": {"schemas": [{"name": "__hidden"}]}}}
        )


def test_resources_config_rejects_table_name_with_double_underscore():
    """A table whose name starts with '__' is rejected."""
    with pytest.raises(ValidationError, match="__"):
        ResourcesConfig.model_validate(
            {"catalogs": {"cat": {"schemas": [{"name": "s", "tables": [{"name": "__t"}]}]}}}
        )


def test_resources_config_rejects_volume_name_with_double_underscore():
    """A volume whose name starts with '__' is rejected."""
    with pytest.raises(ValidationError, match="__"):
        ResourcesConfig.model_validate(
            {"catalogs": {"cat": {"schemas": [{"name": "s", "volumes": [{"name": "__v"}]}]}}}
        )


def test_resources_config_rejects_function_name_with_double_underscore():
    """A function whose name starts with '__' is rejected."""
    with pytest.raises(ValidationError, match="__"):
        ResourcesConfig.model_validate(
            {"catalogs": {"cat": {"schemas": [
                {"name": "s", "functions": [{"name": "__fn", "return": "1"}]}
            ]}}}
        )


def test_resources_config_allows_column_name_with_double_underscore():
    """Columns are exempt from the '__' securable-name restriction."""
    config = ResourcesConfig.model_validate(
        {"catalogs": {"cat": {"schemas": [
            {"name": "s", "tables": [{"name": "t", "columns": [{"name": "__c"}]}]}
        ]}}}
    )
    assert config.catalogs["cat"].schemas[0].tables[0].columns[0].name == "__c"


def test_resources_config_allows_single_underscore_securable_name():
    """A single leading underscore is allowed — only '__' is reserved."""
    config = ResourcesConfig.model_validate(
        {"catalogs": {"cat": {"schemas": [{"name": "_staging"}]}}}
    )
    assert config.catalogs["cat"].schemas[0].name == "_staging"


# ---------------------------------------------------------------------------
# Policy 'for' (for_securable_type)
# ---------------------------------------------------------------------------


def _grant_policy_in_catalog(policy: dict) -> dict:
    """Wrap a single grant policy dict in a minimal catalog-attached config."""
    return {"catalogs": {"cat": {"name": "cat", "policies": [policy]}}}


def test_policy_config_normalises_for_securable_type_case():
    """'for' accepts any case and resolves to the canonical SecurableType."""
    config = ResourcesConfig.model_validate(
        _grant_policy_in_catalog({
            "name": "g", "type": "grant", "privileges": ["use_schema"],
            "to": ["analysts"], "for": "Schema",
        })
    )
    assert config.catalogs["cat"].policies[0].for_securable_type == SecurableType.SCHEMA


@pytest.mark.parametrize(
    "plural,expected",
    [
        ("tables", SecurableType.TABLE),
        ("schemas", SecurableType.SCHEMA),
        ("catalogs", SecurableType.CATALOG),
        ("volumes", SecurableType.VOLUME),
    ],
)
def test_policy_config_normalises_for_securable_type_plural(plural, expected):
    """'for' accepts trailing-'s' plurals and resolves them to the singular type.

    Uses 'manage' as the privilege since it is valid for every securable type."""
    config = ResourcesConfig.model_validate(
        _grant_policy_in_catalog({
            "name": "g", "type": "grant", "privileges": ["manage"],
            "to": ["analysts"], "for": plural,
        })
    )
    assert config.catalogs["cat"].policies[0].for_securable_type == expected


def test_grant_policy_config_allows_all_privileges_when_for_omitted():
    """With 'for' omitted, any privilege list is accepted (no type constraint)."""
    config = ResourcesConfig.model_validate(
        _grant_policy_in_catalog({
            "name": "g", "type": "grant",
            "privileges": ["select", "read_volume", "use_catalog"],
            "to": ["analysts"],
        })
    )
    assert config.catalogs["cat"].policies[0].for_securable_type is None


def test_grant_policy_config_accepts_privileges_matching_for_securable_type():
    """Privileges applicable to the 'for' type validate successfully."""
    config = ResourcesConfig.model_validate(
        _grant_policy_in_catalog({
            "name": "g", "type": "grant",
            "privileges": ["read_volume", "write_volume"],
            "to": ["analysts"], "for": "volume",
        })
    )
    assert config.catalogs["cat"].policies[0].for_securable_type == SecurableType.VOLUME


def test_grant_policy_config_rejects_privileges_mismatching_for_securable_type():
    """A privilege not applicable to the 'for' type raises a validation error."""
    with pytest.raises(ValidationError) as exc_info:
        ResourcesConfig.model_validate(
            _grant_policy_in_catalog({
                "name": "g", "type": "grant", "privileges": ["select"],
                "to": ["analysts"], "for": "volume",
            })
        )
    assert "volume" in str(exc_info.value).lower()


def test_grant_policy_config_accepts_abstraction_with_partial_overlap():
    """An abstraction validates when at least one expanded privilege applies
    (read -> read_volume is applicable to volume)."""
    config = ResourcesConfig.model_validate(
        _grant_policy_in_catalog({
            "name": "g", "type": "grant", "privileges": ["read"],
            "to": ["analysts"], "for": "volume",
        })
    )
    assert config.catalogs["cat"].policies[0].for_securable_type == SecurableType.VOLUME


def test_grant_policy_config_rejects_abstraction_with_no_overlap():
    """An abstraction fails when none of its expanded privileges apply
    (use -> use_catalog/use_schema, neither applicable to table)."""
    with pytest.raises(ValidationError):
        ResourcesConfig.model_validate(
            _grant_policy_in_catalog({
                "name": "g", "type": "grant", "privileges": ["use"],
                "to": ["analysts"], "for": "table",
            })
        )


def test_grant_policy_config_rejects_unsupported_for_securable_type():
    """A securable type with no grantable privileges (e.g. function) is rejected
    cleanly rather than crashing."""
    with pytest.raises(ValidationError):
        ResourcesConfig.model_validate(
            _grant_policy_in_catalog({
                "name": "g", "type": "grant", "privileges": ["execute"],
                "to": ["analysts"], "for": "function",
            })
        )


def test_mask_policy_config_accepts_for_table_aliases():
    """A mask policy accepts 'for' written as a case-variant or plural of table."""
    for value in ("Table", "tables", "TABLE"):
        config = ResourcesConfig.model_validate(
            _fgac_policy_in_table({
                "name": "p", "type": "mask", "function": "cat.s.fn",
                "columns": [{"alias": "c", "has_tags": {"pii": "email"}}],
                "for": value,
            })
        )
        policy = config.catalogs["cat"].schemas[0].tables[0].policies[0]
        assert policy.for_securable_type == SecurableType.TABLE


def test_mask_policy_config_rejects_non_table_for():
    """A mask policy may only target TABLE; any other 'for' is rejected."""
    with pytest.raises(ValidationError):
        ResourcesConfig.model_validate(
            _fgac_policy_in_table({
                "name": "p", "type": "mask", "function": "cat.s.fn",
                "columns": [{"alias": "c", "has_tags": {"pii": "email"}}],
                "for": "schema",
            })
        )


def test_fgac_policy_config_allows_null_for():
    """An explicit 'for: null' is accepted on an FGAC policy (coalesced to TABLE
    downstream by the compiler)."""
    config = ResourcesConfig.model_validate(
        _fgac_policy_in_table({
            "name": "p", "type": "mask", "function": "cat.s.fn",
            "columns": [{"alias": "c", "has_tags": {"pii": "email"}}],
            "for": None,
        })
    )
    assert config.catalogs["cat"].schemas[0].tables[0].policies[0].for_securable_type is None
