from __future__ import annotations

from uc_declarative_abac.configs.models import ResourcesConfig
from uc_declarative_abac.principals.state import Principal
from uc_declarative_abac.securables.compiler import compile_desired_attributes, compile_desired_securables
from uc_declarative_abac.securables.state import Column, Function, Securable, SecurableAttributes, Table
from uc_declarative_abac.types import PrincipalType, SecurableType


def _unknown_owner(name: str) -> Principal:
    return Principal(principal_type=PrincipalType.UNKNOWN, name=name)


# ---------------------------------------------------------------------------
# compile_desired_attributes
# ---------------------------------------------------------------------------


def test_securable_compiler_emits_catalog_owner():
    """A catalog with owner produces a SecurableAttributes for the catalog."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "owner": "admin_user",
                }
            }
        }
    )

    result = compile_desired_attributes(config)

    assert result == {
        SecurableAttributes(
            securable_type=SecurableType.CATALOG,
            full_name="my_catalog",
            owner=_unknown_owner("admin_user"),
        )
    }


def test_securable_compiler_emits_schema_owner():
    """A schema with owner produces a SecurableAttributes with a two-part full name."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "schemas": [
                        {
                            "name": "sales",
                            "owner": "schema_owner",
                        }
                    ],
                }
            }
        }
    )

    result = compile_desired_attributes(config)

    assert SecurableAttributes(
        securable_type=SecurableType.SCHEMA,
        full_name="my_catalog.sales",
        owner=_unknown_owner("schema_owner"),
    ) in result


def test_securable_compiler_emits_table_owner():
    """A table with owner produces a SecurableAttributes with a three-part full name."""
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
                                    "owner": "table_owner",
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = compile_desired_attributes(config)

    assert SecurableAttributes(
        securable_type=SecurableType.TABLE,
        full_name="my_catalog.sales.orders",
        owner=_unknown_owner("table_owner"),
    ) in result


def test_securable_compiler_emits_volume_owner():
    """A volume with owner produces a SecurableAttributes with a three-part full name."""
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
                                    "owner": "vol_owner",
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = compile_desired_attributes(config)

    assert SecurableAttributes(
        securable_type=SecurableType.VOLUME,
        full_name="my_catalog.landing.files",
        owner=_unknown_owner("vol_owner"),
    ) in result


def test_securable_compiler_emits_function_owner():
    """A function with owner produces a SecurableAttributes with a three-part full name."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "schemas": [
                        {
                            "name": "shared",
                            "functions": [
                                {
                                    "name": "mask_email",
                                    "owner": "func_owner",
                                    "parameters": [{"name": "col", "type": "STRING"}],
                                    "return": "CASE WHEN is_member('admins') THEN col ELSE '***' END",
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = compile_desired_attributes(config)

    assert SecurableAttributes(
        securable_type=SecurableType.FUNCTION,
        full_name="my_catalog.shared.mask_email",
        owner=_unknown_owner("func_owner"),
    ) in result


def test_securable_compiler_skips_securables_without_managed_attributes():
    """A catalog with no owner/comment/location is not emitted in the attributes set."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {}
            }
        }
    )

    result = compile_desired_attributes(config)

    assert result == set()


# ---------------------------------------------------------------------------
# compile_desired_attributes — comment + location
# ---------------------------------------------------------------------------


def test_securable_compiler_emits_catalog_comment_in_attributes():
    """A catalog with a comment produces a SecurableAttributes carrying it. Catalogs
    do not currently support ``location`` (managed location)."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "comment": "Prod catalog",
            },
        },
    })

    result = compile_desired_attributes(config)

    assert SecurableAttributes(
        securable_type=SecurableType.CATALOG,
        full_name="my_cat",
        owner=None,
        comment="Prod catalog",
    ) in result


def test_securable_compiler_emits_schema_comment_in_attributes():
    """A schema with a comment produces a SecurableAttributes carrying it. Schemas
    do not currently support ``location`` (managed location)."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "schemas": [
                    {
                        "name": "sales",
                        "comment": "Sales data",
                    },
                ],
            },
        },
    })

    result = compile_desired_attributes(config)

    assert SecurableAttributes(
        securable_type=SecurableType.SCHEMA,
        full_name="my_cat.sales",
        comment="Sales data",
    ) in result


def test_securable_compiler_emits_table_comment_in_attributes():
    """A table with a comment produces a SecurableAttributes carrying it.

    ``location`` is creation-only (not part of SecurableAttributes); see
    ``test_securables_compiler_plumbs_*_onto_*_securable`` for CREATE-time plumbing.
    """
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "schemas": [
                    {
                        "name": "sales",
                        "tables": [
                            {
                                "name": "orders",
                                "comment": "Orders fact",
                                "location": "s3://ext/orders",
                            },
                        ],
                    },
                ],
            },
        },
    })

    result = compile_desired_attributes(config)

    assert SecurableAttributes(
        securable_type=SecurableType.TABLE,
        full_name="my_cat.sales.orders",
        comment="Orders fact",
    ) in result


def test_securable_compiler_emits_volume_comment_in_attributes():
    """A volume with a comment produces a SecurableAttributes carrying it.

    ``location`` is creation-only (not part of SecurableAttributes).
    """
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "schemas": [
                    {
                        "name": "landing",
                        "volumes": [
                            {
                                "name": "raw",
                                "comment": "Raw landing",
                                "location": "s3://ext/raw",
                            },
                        ],
                    },
                ],
            },
        },
    })

    result = compile_desired_attributes(config)

    assert SecurableAttributes(
        securable_type=SecurableType.VOLUME,
        full_name="my_cat.landing.raw",
        comment="Raw landing",
    ) in result


def test_securable_compiler_emits_attributes_when_only_comment_is_set():
    """A catalog with only a comment (no owner) still produces a SecurableAttributes."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {"comment": "Just a comment"},
        },
    })

    result = compile_desired_attributes(config)

    assert SecurableAttributes(
        securable_type=SecurableType.CATALOG,
        full_name="my_cat",
        comment="Just a comment",
    ) in result


def test_securable_compiler_emits_no_attributes_when_only_location_is_set():
    """A volume with only a location (no owner, no comment) does NOT produce a
    SecurableAttributes — ``location`` is creation-only and isn't tracked as a
    managed attribute."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "schemas": [
                    {
                        "name": "landing",
                        "volumes": [
                            {"name": "raw", "location": "s3://ext/raw"},
                        ],
                    },
                ],
            },
        },
    })

    result = compile_desired_attributes(config)

    assert not any(a.securable_type == SecurableType.VOLUME for a in result)


def test_securable_compiler_does_not_emit_function_comment_into_attributes():
    """Function comments live on the Function securable itself, not on SecurableAttributes."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "schemas": [
                    {
                        "name": "shared",
                        "functions": [
                            {
                                "name": "mask_pii",
                                "parameters": [{"name": "x", "type": "STRING"}],
                                "return": "x",
                                "comment": "Mask helper",
                            },
                        ],
                    },
                ],
            },
        },
    })

    result = compile_desired_attributes(config)

    # No SecurableAttributes is emitted for the function (no owner, and we don't
    # promote function comments into the attribute path).
    assert not any(a.securable_type == SecurableType.FUNCTION for a in result)


# ---------------------------------------------------------------------------
# compile_desired_attributes — rfa_destinations
# ---------------------------------------------------------------------------


# A representative mix exercising every regex-recognised RFA destination form:
# an email, an HTTPS URL, and a canonical 8-4-4-4-12 UUID.
_RFA_DESTINATIONS = [
    "data-gov@example.com",
    "https://hooks.example.com/rfa",
    "12345678-1234-1234-1234-123456789abc",
]


def test_securable_compiler_emits_catalog_rfa_destinations():
    """A catalog with rfa_destinations produces a SecurableAttributes carrying the
    destinations as a frozenset (order-insensitive)."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "rfa_destinations": list(_RFA_DESTINATIONS),
            },
        },
    })

    result = compile_desired_attributes(config)

    assert SecurableAttributes(
        securable_type=SecurableType.CATALOG,
        full_name="my_cat",
        rfa_destinations=frozenset(_RFA_DESTINATIONS),
    ) in result


def test_securable_compiler_emits_schema_rfa_destinations():
    """A schema with rfa_destinations produces a SecurableAttributes carrying them."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "schemas": [
                    {
                        "name": "sales",
                        "rfa_destinations": list(_RFA_DESTINATIONS),
                    },
                ],
            },
        },
    })

    result = compile_desired_attributes(config)

    assert SecurableAttributes(
        securable_type=SecurableType.SCHEMA,
        full_name="my_cat.sales",
        rfa_destinations=frozenset(_RFA_DESTINATIONS),
    ) in result


def test_securable_compiler_emits_table_rfa_destinations():
    """A table with rfa_destinations produces a SecurableAttributes carrying them."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "schemas": [
                    {
                        "name": "sales",
                        "tables": [
                            {
                                "name": "orders",
                                "rfa_destinations": list(_RFA_DESTINATIONS),
                            },
                        ],
                    },
                ],
            },
        },
    })

    result = compile_desired_attributes(config)

    assert SecurableAttributes(
        securable_type=SecurableType.TABLE,
        full_name="my_cat.sales.orders",
        rfa_destinations=frozenset(_RFA_DESTINATIONS),
    ) in result


def test_securable_compiler_emits_volume_rfa_destinations():
    """A volume with rfa_destinations produces a SecurableAttributes carrying them."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "schemas": [
                    {
                        "name": "landing",
                        "volumes": [
                            {
                                "name": "raw",
                                "rfa_destinations": list(_RFA_DESTINATIONS),
                            },
                        ],
                    },
                ],
            },
        },
    })

    result = compile_desired_attributes(config)

    assert SecurableAttributes(
        securable_type=SecurableType.VOLUME,
        full_name="my_cat.landing.raw",
        rfa_destinations=frozenset(_RFA_DESTINATIONS),
    ) in result


def test_securable_compiler_emits_function_rfa_destinations():
    """A function with rfa_destinations produces a SecurableAttributes carrying them."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "schemas": [
                    {
                        "name": "shared",
                        "functions": [
                            {
                                "name": "mask_email",
                                "parameters": [{"name": "col", "type": "STRING"}],
                                "return": "col",
                                "rfa_destinations": list(_RFA_DESTINATIONS),
                            },
                        ],
                    },
                ],
            },
        },
    })

    result = compile_desired_attributes(config)

    assert SecurableAttributes(
        securable_type=SecurableType.FUNCTION,
        full_name="my_cat.shared.mask_email",
        rfa_destinations=frozenset(_RFA_DESTINATIONS),
    ) in result


def test_securable_compiler_rfa_destinations_is_none_when_absent():
    """A catalog with an owner but no rfa_destinations leaves
    SecurableAttributes.rfa_destinations as None (not an empty frozenset)."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {"owner": "admin_user"},
        },
    })

    result = compile_desired_attributes(config)

    catalog_attrs = next(
        a for a in result
        if a.securable_type == SecurableType.CATALOG and a.full_name == "my_cat"
    )
    assert catalog_attrs.rfa_destinations is None


def test_securable_compiler_emits_attributes_when_only_rfa_destinations_set():
    """A catalog with only rfa_destinations (no owner, no comment) still produces
    a SecurableAttributes — and a sibling catalog with no managed attributes at
    all does not."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "with_rfa": {
                "rfa_destinations": list(_RFA_DESTINATIONS),
            },
            "without_anything": {},
        },
    })

    result = compile_desired_attributes(config)

    assert SecurableAttributes(
        securable_type=SecurableType.CATALOG,
        full_name="with_rfa",
        rfa_destinations=frozenset(_RFA_DESTINATIONS),
    ) in result
    assert not any(a.full_name == "without_anything" for a in result)


# ---------------------------------------------------------------------------
# compile_desired_securables
# ---------------------------------------------------------------------------


def test_securable_compiler_emits_function_info():
    """A function config produces a Function with parameters and definition."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "schemas": [
                        {
                            "name": "shared",
                            "functions": [
                                {
                                    "name": "mask_email",
                                    "owner": "func_owner",
                                    "parameters": [{"name": "col", "type": "STRING"}],
                                    "return": "CASE WHEN is_member('admins') THEN col ELSE '***' END",
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = compile_desired_securables(config)

    assert Function(
        securable_type=SecurableType.FUNCTION,
        full_name="my_catalog.shared.mask_email",
        parameters=(("col", "STRING"),),
        definition="CASE WHEN is_member('admins') THEN col ELSE '***' END",
    ) in result


def test_securable_compiler_emits_function_info_without_parameters():
    """A function with no parameters produces a Function with parameters=()."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "schemas": [
                        {
                            "name": "shared",
                            "functions": [
                                {
                                    "name": "get_greeting",
                                    "return": "'Hello, World!'",
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = compile_desired_securables(config)

    assert Function(
        securable_type=SecurableType.FUNCTION,
        full_name="my_catalog.shared.get_greeting",
        parameters=(),
        definition="'Hello, World!'",
    ) in result


def test_securable_compiler_emits_function_comment_when_provided():
    """FunctionConfig.comment is propagated onto the emitted Function."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "schemas": [
                        {
                            "name": "shared",
                            "functions": [
                                {
                                    "name": "greet",
                                    "return": "'hi'",
                                    "comment": "Returns a greeting",
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = compile_desired_securables(config)
    func = next(s for s in result if isinstance(s, Function))
    assert func.comment == "Returns a greeting"


def test_securable_compiler_function_comment_defaults_to_none():
    """A function without a comment emits Function.comment == None."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "schemas": [
                        {
                            "name": "shared",
                            "functions": [
                                {"name": "greet", "return": "'hi'"}
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = compile_desired_securables(config)
    func = next(s for s in result if isinstance(s, Function))
    assert func.comment is None


# ---------------------------------------------------------------------------
# compile_desired_securables — base Securable emissions for catalog/schema/table/volume
# ---------------------------------------------------------------------------


def test_securables_compiler_emits_securable_for_each_declared_catalog():
    """Every declared catalog appears in the desired-securables set as a base Securable."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat_a": {},
                "cat_b": {},
            }
        }
    )

    result = compile_desired_securables(config)

    assert Securable(securable_type=SecurableType.CATALOG, full_name="cat_a") in result
    assert Securable(securable_type=SecurableType.CATALOG, full_name="cat_b") in result


def test_securables_compiler_emits_securable_for_each_declared_schema():
    """Every declared schema appears in the desired-securables set as a base Securable."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "schemas": [
                        {"name": "sales"},
                        {"name": "hr"},
                    ],
                }
            }
        }
    )

    result = compile_desired_securables(config)

    assert Securable(securable_type=SecurableType.SCHEMA, full_name="cat.sales") in result
    assert Securable(securable_type=SecurableType.SCHEMA, full_name="cat.hr") in result


def test_securables_compiler_emits_table_subclass_for_each_declared_table():
    """Every declared table appears in the desired-securables set as a Table instance
    (not a base Securable) so the executor can reach columns for CREATE TABLE SQL."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "schemas": [
                        {
                            "name": "sales",
                            "tables": [
                                {"name": "orders"},
                                {"name": "customers"},
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = compile_desired_securables(config)

    assert Table(securable_type=SecurableType.TABLE, full_name="cat.sales.orders", columns=()) in result
    assert Table(securable_type=SecurableType.TABLE, full_name="cat.sales.customers", columns=()) in result


def test_securables_compiler_emits_column_with_data_type_when_specified():
    """A declared column with a 'data_type' produces a Column with that data_type string."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "schemas": [
                        {
                            "name": "sales",
                            "tables": [
                                {
                                    "name": "orders",
                                    "columns": [
                                        {"name": "email", "data_type": "STRING"},
                                        {"name": "amount", "data_type": "DECIMAL(18,2)"},
                                    ],
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = compile_desired_securables(config)

    orders = next(s for s in result if isinstance(s, Table) and s.full_name == "cat.sales.orders")
    assert Column(
        securable_type=SecurableType.COLUMN,
        full_name="cat.sales.orders.email",
        data_type="STRING",
    ) in orders.columns
    assert Column(
        securable_type=SecurableType.COLUMN,
        full_name="cat.sales.orders.amount",
        data_type="DECIMAL(18,2)",
    ) in orders.columns


def test_securables_compiler_emits_column_with_data_type_none_when_unspecified():
    """A declared column without a 'data_type' produces Column(data_type=None)."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
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
                    ],
                }
            }
        }
    )

    result = compile_desired_securables(config)

    orders = next(s for s in result if isinstance(s, Table) and s.full_name == "cat.sales.orders")
    (email_col,) = orders.columns
    assert email_col.data_type is None


def test_securables_compiler_preserves_column_declaration_order():
    """The order of columns in the YAML list is preserved in Table.columns (tuple)."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "schemas": [
                        {
                            "name": "sales",
                            "tables": [
                                {
                                    "name": "orders",
                                    "columns": [
                                        {"name": "c_zebra", "type": "STRING"},
                                        {"name": "a_apple", "type": "INT"},
                                        {"name": "m_mango", "type": "DATE"},
                                    ],
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = compile_desired_securables(config)

    orders = next(s for s in result if isinstance(s, Table) and s.full_name == "cat.sales.orders")
    assert [c.full_name.rsplit(".", 1)[-1] for c in orders.columns] == ["c_zebra", "a_apple", "m_mango"]


def test_securables_compiler_emits_securable_for_each_declared_volume():
    """Every declared volume appears in the desired-securables set as a base Securable."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "schemas": [
                        {
                            "name": "raw",
                            "volumes": [
                                {"name": "events"},
                                {"name": "files"},
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = compile_desired_securables(config)

    assert Securable(securable_type=SecurableType.VOLUME, full_name="cat.raw.events") in result
    assert Securable(securable_type=SecurableType.VOLUME, full_name="cat.raw.files") in result


def test_securables_compiler_emits_function_subclass_for_each_declared_function():
    """Functions continue to be emitted as Function instances, not base Securables."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "schemas": [
                        {
                            "name": "shared",
                            "functions": [
                                {"name": "greet", "return": "'hi'"},
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = compile_desired_securables(config)

    func = next(s for s in result if s.full_name == "cat.shared.greet")
    assert isinstance(func, Function)


def test_securables_compiler_emits_nothing_for_empty_config():
    """A config with no catalogs produces an empty desired-securables set."""
    config = ResourcesConfig.model_validate({"catalogs": {}})

    assert compile_desired_securables(config) == set()


# ---------------------------------------------------------------------------
# compile_desired_securables — CREATE-time comment + location plumbing
# ---------------------------------------------------------------------------


def test_securables_compiler_plumbs_comment_and_location_onto_catalog_securable():
    """Catalog Securable carries comment and managed location for CREATE-time SQL embedding."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "comment": "Prod",
                "location": "s3://managed/my_cat",
            },
        },
    })

    result = compile_desired_securables(config)

    catalog = next(s for s in result if s.full_name == "my_cat" and s.securable_type == SecurableType.CATALOG)
    assert catalog.comment == "Prod"
    assert catalog.location == "s3://managed/my_cat"


def test_securables_compiler_plumbs_comment_and_location_onto_schema_securable():
    """Schema Securable carries comment and managed location for CREATE-time SQL embedding."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "schemas": [
                    {
                        "name": "sales",
                        "comment": "Sales",
                        "location": "s3://managed/sales",
                    },
                ],
            },
        },
    })

    result = compile_desired_securables(config)

    schema = next(s for s in result if s.full_name == "my_cat.sales")
    assert schema.comment == "Sales"
    assert schema.location == "s3://managed/sales"


def test_securables_compiler_plumbs_comment_and_location_onto_table_securable():
    """Table securable carries comment and external location for CREATE-time SQL embedding."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "schemas": [
                    {
                        "name": "sales",
                        "tables": [
                            {
                                "name": "orders",
                                "comment": "Orders",
                                "location": "s3://ext/orders",
                                "columns": [{"name": "id", "type": "BIGINT"}],
                            },
                        ],
                    },
                ],
            },
        },
    })

    result = compile_desired_securables(config)

    table = next(s for s in result if s.full_name == "my_cat.sales.orders")
    assert isinstance(table, Table)
    assert table.comment == "Orders"
    assert table.location == "s3://ext/orders"


def test_securables_compiler_plumbs_comment_and_location_onto_volume_securable():
    """Volume Securable carries comment and external location for CREATE-time SQL embedding."""
    config = ResourcesConfig.model_validate({
        "catalogs": {
            "my_cat": {
                "schemas": [
                    {
                        "name": "landing",
                        "volumes": [
                            {
                                "name": "raw",
                                "comment": "Raw",
                                "location": "s3://ext/raw",
                            },
                        ],
                    },
                ],
            },
        },
    })

    result = compile_desired_securables(config)

    volume = next(s for s in result if s.full_name == "my_cat.landing.raw")
    assert volume.comment == "Raw"
    assert volume.location == "s3://ext/raw"
