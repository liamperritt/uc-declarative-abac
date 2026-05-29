import pytest

from uc_declarative_abac.configs.consolidator import consolidate_resources
from uc_declarative_abac.utils import DuplicateResourceError, OrchestratorError
from uc_declarative_abac.configs.models import ResourcesConfig
from uc_declarative_abac.configs.resolver import resolve_refs



def _inline_fn_dict(name: str, return_expr: str = "col") -> dict:
    return {
        "name": name,
        "parameters": [{"name": "col", "type": "STRING"}],
        "return": return_expr,
    }


def _fgac_policy(name: str = "p1", function=None) -> dict:
    policy = {
        "name": name,
        "type": "mask",
        "to": ["analysts"],
        "columns": [{"alias": "c", "has_tags": {"pii": "email"}}],
    }
    if function is not None:
        policy["function"] = function
    return policy


# --- consolidate_resources: standalone schemas ---


def test_consolidator_moves_standalone_schema_into_catalog():
    data = {
        "catalogs": {
            "my_cat": {"name": "my_cat"}
        },
        "schemas": {
            "my_schema": {
                "catalog_name": "my_cat",
                "name": "sales",
                "tags": {"team": "data"},
            }
        },
    }
    result = consolidate_resources(data)

    assert "schemas" not in result
    assert len(result["catalogs"]["my_cat"]["schemas"]) == 1
    schema = result["catalogs"]["my_cat"]["schemas"][0]
    assert schema["name"] == "sales"
    assert schema["tags"] == {"team": "data"}


def test_consolidator_auto_creates_parent_catalog():
    data = {
        "catalogs": {},
        "schemas": {
            "my_schema": {
                "catalog_name": "new_cat",
                "name": "sales",
            }
        },
    }
    result = consolidate_resources(data)

    assert "new_cat" in result["catalogs"]
    assert result["catalogs"]["new_cat"]["name"] == "new_cat"
    assert len(result["catalogs"]["new_cat"]["schemas"]) == 1
    assert result["catalogs"]["new_cat"]["schemas"][0]["name"] == "sales"


def test_consolidator_preserves_existing_nested_children():
    data = {
        "catalogs": {
            "my_cat": {
                "name": "my_cat",
                "schemas": [{"name": "sales"}],
            }
        },
        "schemas": {
            "my_schema": {
                "catalog_name": "my_cat",
                "name": "hr",
            }
        },
    }
    result = consolidate_resources(data)

    schemas = result["catalogs"]["my_cat"]["schemas"]
    assert len(schemas) == 2
    names = {s["name"] for s in schemas}
    assert names == {"sales", "hr"}


# --- consolidate_resources: standalone tables ---


def test_consolidator_moves_standalone_table_into_schema():
    data = {
        "catalogs": {
            "my_cat": {
                "name": "my_cat",
                "schemas": [{"name": "sales"}],
            }
        },
        "tables": {
            "my_table": {
                "catalog_name": "my_cat",
                "schema_name": "sales",
                "name": "orders",
            }
        },
    }
    result = consolidate_resources(data)

    assert "tables" not in result
    schema = result["catalogs"]["my_cat"]["schemas"][0]
    assert schema["name"] == "sales"
    assert len(schema["tables"]) == 1
    assert schema["tables"][0]["name"] == "orders"


# --- consolidate_resources: standalone volumes ---


def test_consolidator_moves_standalone_volume_into_schema():
    data = {
        "catalogs": {
            "my_cat": {
                "name": "my_cat",
                "schemas": [{"name": "landing"}],
            }
        },
        "volumes": {
            "my_vol": {
                "catalog_name": "my_cat",
                "schema_name": "landing",
                "name": "files",
            }
        },
    }
    result = consolidate_resources(data)

    assert "volumes" not in result
    schema = result["catalogs"]["my_cat"]["schemas"][0]
    assert schema["name"] == "landing"
    assert len(schema["volumes"]) == 1
    assert schema["volumes"][0]["name"] == "files"


# --- consolidate_resources: no-op passthrough ---


def test_consolidator_passes_through_when_no_standalone_resources():
    data = {
        "catalogs": {
            "my_cat": {
                "name": "my_cat",
                "schemas": [{"name": "sales"}],
            }
        }
    }
    result = consolidate_resources(data)

    assert result == data


# --- Validation errors ---


def test_consolidator_rejects_schema_without_catalog_name():
    data = {
        "catalogs": {},
        "schemas": {
            "my_schema": {"name": "sales"}
        },
    }
    with pytest.raises(OrchestratorError):
        consolidate_resources(data)


def test_consolidator_rejects_table_without_catalog_name():
    data = {
        "catalogs": {
            "my_cat": {
                "name": "my_cat",
                "schemas": [{"name": "sales"}],
            }
        },
        "tables": {
            "my_table": {
                "schema_name": "sales",
                "name": "orders",
            }
        },
    }
    with pytest.raises(OrchestratorError):
        consolidate_resources(data)


def test_consolidator_rejects_table_without_schema_name():
    data = {
        "catalogs": {
            "my_cat": {
                "name": "my_cat",
                "schemas": [{"name": "sales"}],
            }
        },
        "tables": {
            "my_table": {
                "catalog_name": "my_cat",
                "name": "orders",
            }
        },
    }
    with pytest.raises(OrchestratorError):
        consolidate_resources(data)


def test_consolidator_rejects_volume_without_schema_name():
    data = {
        "catalogs": {
            "my_cat": {
                "name": "my_cat",
                "schemas": [{"name": "landing"}],
            }
        },
        "volumes": {
            "my_vol": {
                "catalog_name": "my_cat",
                "name": "files",
            }
        },
    }
    with pytest.raises(OrchestratorError):
        consolidate_resources(data)


# --- consolidate_resources: inline function extraction ---


def test_consolidator_extracts_inline_function_from_table_level_policy():
    """An inline function dict on a table-level policy moves into the table's
    enclosing schema's functions list; policy.function becomes the full name."""
    data = {
        "catalogs": {
            "c1": {
                "name": "c1",
                "schemas": [
                    {
                        "name": "s1",
                        "tables": [
                            {
                                "name": "t1",
                                "policies": [_fgac_policy(function=_inline_fn_dict("mask_pii"))],
                            }
                        ],
                    }
                ],
            }
        }
    }
    result = consolidate_resources(data)

    schema = result["catalogs"]["c1"]["schemas"][0]
    assert schema["name"] == "s1"
    assert len(schema.get("functions", [])) == 1
    fn = schema["functions"][0]
    assert fn["name"] == "mask_pii"
    assert fn["return"] == "col"

    policy = schema["tables"][0]["policies"][0]
    assert policy["function"] == "c1.s1.mask_pii"


def test_consolidator_extracts_inline_function_from_schema_level_policy():
    """Schema-level policy with inline function → enclosing schema's functions list."""
    data = {
        "catalogs": {
            "c1": {
                "name": "c1",
                "schemas": [
                    {
                        "name": "s1",
                        "policies": [_fgac_policy(function=_inline_fn_dict("mask_pii"))],
                    }
                ],
            }
        }
    }
    result = consolidate_resources(data)

    schema = result["catalogs"]["c1"]["schemas"][0]
    assert [f["name"] for f in schema.get("functions", [])] == ["mask_pii"]
    (policy,) = schema["policies"]
    assert policy["function"] == "c1.s1.mask_pii"


def test_consolidator_extracts_inline_function_from_catalog_level_policy_to_default_schema():
    """Catalog-level policy with inline function → 'default' schema (created if missing)."""
    data = {
        "catalogs": {
            "c1": {
                "name": "c1",
                "policies": [_fgac_policy(function=_inline_fn_dict("mask_pii"))],
            }
        }
    }
    result = consolidate_resources(data)

    schemas = result["catalogs"]["c1"]["schemas"]
    default_schemas = [s for s in schemas if s["name"] == "default"]
    assert len(default_schemas) == 1
    assert [f["name"] for f in default_schemas[0].get("functions", [])] == ["mask_pii"]

    (policy,) = result["catalogs"]["c1"]["policies"]
    assert policy["function"] == "c1.default.mask_pii"


def test_consolidator_appends_inline_function_to_existing_default_schema():
    """If the catalog already has a 'default' schema, the function is appended to it
    rather than creating a duplicate schema entry."""
    data = {
        "catalogs": {
            "c1": {
                "name": "c1",
                "schemas": [
                    {"name": "default", "owner": "someone"},
                ],
                "policies": [_fgac_policy(function=_inline_fn_dict("mask_pii"))],
            }
        }
    }
    result = consolidate_resources(data)

    schemas = result["catalogs"]["c1"]["schemas"]
    assert len(schemas) == 1
    assert schemas[0]["name"] == "default"
    assert schemas[0]["owner"] == "someone"
    assert [f["name"] for f in schemas[0].get("functions", [])] == ["mask_pii"]


def test_consolidator_extracts_inline_function_from_standalone_policy():
    """A standalone policy (in resources.policies) with inline function — after
    the existing consolidator nests it, the function lands in the target schema."""
    data = {
        "catalogs": {
            "c1": {"name": "c1"},
        },
        "policies": {
            "pol": {
                "catalog_name": "c1",
                "schema_name": "s1",
                "name": "p1",
                "type": "mask",
                "to": ["analysts"],
                "columns": [{"alias": "c", "has_tags": {"pii": "email"}}],
                "function": _inline_fn_dict("mask_pii"),
            }
        },
    }
    result = consolidate_resources(data)

    schema = result["catalogs"]["c1"]["schemas"][0]
    assert schema["name"] == "s1"
    assert [f["name"] for f in schema.get("functions", [])] == ["mask_pii"]
    (policy,) = schema["policies"]
    assert policy["function"] == "c1.s1.mask_pii"


def test_consolidator_extracts_inline_function_from_defs_string_after_resolution():
    """Full pipeline: resolver replaces a $defs/... string with the function dict,
    consolidator then extracts it."""
    definitions = {
        "functions": {
            "shared|mask_pii": _inline_fn_dict("mask_pii"),
        },
    }
    resources = {
        "catalogs": {
            "c1": {
                "name": "c1",
                "schemas": [
                    {
                        "name": "s1",
                        "tables": [
                            {
                                "name": "t1",
                                "policies": [_fgac_policy(function="$defs/functions/shared|mask_pii")],
                            }
                        ],
                    }
                ],
            }
        }
    }
    resolved = resolve_refs(definitions, resources)
    result = consolidate_resources(resolved)

    schema = result["catalogs"]["c1"]["schemas"][0]
    assert [f["name"] for f in schema.get("functions", [])] == ["mask_pii"]
    (policy,) = schema["tables"][0]["policies"]
    assert policy["function"] == "c1.s1.mask_pii"


def test_consolidator_extracts_inline_function_from_ref_dict_after_resolution():
    """Same as above but using a $ref dict form."""
    definitions = {
        "functions": {
            "shared|mask_pii": _inline_fn_dict("mask_pii"),
        },
    }
    resources = {
        "catalogs": {
            "c1": {
                "name": "c1",
                "schemas": [
                    {
                        "name": "s1",
                        "tables": [
                            {
                                "name": "t1",
                                "policies": [
                                    _fgac_policy(function={"$ref": "$defs/functions/shared|mask_pii"})
                                ],
                            }
                        ],
                    }
                ],
            }
        }
    }
    resolved = resolve_refs(definitions, resources)
    result = consolidate_resources(resolved)

    schema = result["catalogs"]["c1"]["schemas"][0]
    assert [f["name"] for f in schema.get("functions", [])] == ["mask_pii"]
    (policy,) = schema["tables"][0]["policies"]
    assert policy["function"] == "c1.s1.mask_pii"


def test_consolidator_uses_overridden_name_from_ref_function():
    """$ref with a name override → function lands under the new name, policy
    references the overridden full name."""
    definitions = {
        "functions": {
            "shared|base_fn": _inline_fn_dict("base_fn"),
        },
    }
    resources = {
        "catalogs": {
            "c1": {
                "name": "c1",
                "schemas": [
                    {
                        "name": "s1",
                        "tables": [
                            {
                                "name": "t1",
                                "policies": [
                                    _fgac_policy(function={"$ref": "$defs/functions/shared|base_fn", "name": "alt_fn"})
                                ],
                            }
                        ],
                    }
                ],
            }
        }
    }
    resolved = resolve_refs(definitions, resources)
    result = consolidate_resources(resolved)

    schema = result["catalogs"]["c1"]["schemas"][0]
    assert [f["name"] for f in schema.get("functions", [])] == ["alt_fn"]
    (policy,) = schema["tables"][0]["policies"]
    assert policy["function"] == "c1.s1.alt_fn"


def test_consolidator_raises_when_inline_function_missing_name():
    """An inline function dict without a 'name' raises OrchestratorError naming the policy."""
    data = {
        "catalogs": {
            "c1": {
                "name": "c1",
                "policies": [
                    _fgac_policy(name="my_policy", function={"return": "col"}),
                ],
            }
        }
    }
    with pytest.raises(OrchestratorError, match="my_policy"):
        consolidate_resources(data)


def test_consolidator_leaves_string_function_untouched():
    """A policy with function: '<str>' passes through unchanged. Grant policies
    (which have no function field) also pass through."""
    data = {
        "catalogs": {
            "c1": {
                "name": "c1",
                "schemas": [
                    {
                        "name": "s1",
                        "policies": [
                            _fgac_policy(function="c1.s1.existing_fn"),
                            {
                                "name": "grant_select",
                                "type": "grant",
                                "privileges": ["select"],
                                "to": ["analysts"],
                            },
                        ],
                    }
                ],
            }
        }
    }
    result = consolidate_resources(data)

    schema = result["catalogs"]["c1"]["schemas"][0]
    assert schema.get("functions", []) == []  # nothing extracted
    policies = schema["policies"]
    assert policies[0]["function"] == "c1.s1.existing_fn"
    assert "function" not in policies[1]  # grant policy unchanged


def test_consolidator_handles_mixed_inline_and_string_functions_in_same_schema():
    data = {
        "catalogs": {
            "c1": {
                "name": "c1",
                "schemas": [
                    {
                        "name": "s1",
                        "policies": [
                            _fgac_policy(name="inlined", function=_inline_fn_dict("mask_inlined")),
                            _fgac_policy(name="external", function="c1.s1.other_fn"),
                        ],
                    }
                ],
            }
        }
    }
    result = consolidate_resources(data)

    schema = result["catalogs"]["c1"]["schemas"][0]
    assert [f["name"] for f in schema.get("functions", [])] == ["mask_inlined"]
    assert schema["policies"][0]["function"] == "c1.s1.mask_inlined"
    assert schema["policies"][1]["function"] == "c1.s1.other_fn"


def test_consolidator_duplicate_inline_function_names_surface_at_model_validation():
    """Two policies inlining the same function name in the same schema do NOT fail
    consolidation — but SchemaConfig validation raises DuplicateResourceError."""
    data = {
        "catalogs": {
            "c1": {
                "name": "c1",
                "schemas": [
                    {
                        "name": "s1",
                        "policies": [
                            _fgac_policy(name="policy_a", function=_inline_fn_dict("dup")),
                            _fgac_policy(name="policy_b", function=_inline_fn_dict("dup")),
                        ],
                    }
                ],
            }
        }
    }
    result = consolidate_resources(data)

    # Consolidation itself succeeds; both functions land side by side.
    schema = result["catalogs"]["c1"]["schemas"][0]
    assert len(schema.get("functions", [])) == 2

    # Pydantic validation raises DuplicateResourceError.
    with pytest.raises(DuplicateResourceError, match="dup"):
        ResourcesConfig.model_validate(result)
