from __future__ import annotations

from uc_abac_governor.configs.models import ResourcesConfig
from uc_abac_governor.principals.state import Principal
from uc_abac_governor.securables.compiler import compile_desired_attributes, compile_desired_securables
from uc_abac_governor.securables.state import Function, Securable, SecurableAttributes
from uc_abac_governor.types import PrincipalType, SecurableType


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


def test_securable_compiler_skips_securables_without_owner():
    """A catalog with no owner is not emitted in the result set."""
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


def test_securables_compiler_emits_securable_for_each_declared_table():
    """Every declared table appears in the desired-securables set as a base Securable."""
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

    assert Securable(securable_type=SecurableType.TABLE, full_name="cat.sales.orders") in result
    assert Securable(securable_type=SecurableType.TABLE, full_name="cat.sales.customers") in result


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
