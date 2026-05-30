from __future__ import annotations

import pytest

from uc_declarative_abac.configs import resolve_refs
from uc_declarative_abac.utils import (
    ResolutionError,
    UnreferencedDefinitionError,
)



# ---------------------------------------------------------------------------
# Basic ref resolution
# ---------------------------------------------------------------------------


def test_resolver_resolves_single_ref():
    """A $ref to a schema definition is replaced with the full definition content."""
    definitions = {
        "schemas": {
            "ops|sales": {
                "name": "sales",
                "comment": "Sales schema",
                "tags": {"domain": "operations"},
            },
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [
                    {"$ref": "$defs/schemas/ops|sales"},
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    resolved_schema = result["catalogs"]["main"]["schemas"][0]
    assert resolved_schema["name"] == "sales"
    assert resolved_schema["comment"] == "Sales schema"
    assert resolved_schema["tags"] == {"domain": "operations"}
    assert "$ref" not in resolved_schema


# ---------------------------------------------------------------------------
# Override behaviour
# ---------------------------------------------------------------------------


def test_resolver_applies_override_on_ref():
    """Sibling keys on a $ref entry override the corresponding definition fields."""
    definitions = {
        "schemas": {
            "ops|sales": {
                "name": "sales",
                "comment": "Sales schema",
            },
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ops|sales",
                        "name": "sales_staging",
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    resolved_schema = result["catalogs"]["main"]["schemas"][0]
    assert resolved_schema["name"] == "sales_staging"
    # Non-overridden fields are preserved from the definition.
    assert resolved_schema["comment"] == "Sales schema"


def test_resolver_replace_strategy_behaves_like_legacy_update():
    """Under override_strategy='replace', overriding a nested key replaces it entirely (legacy behaviour)."""
    definitions = {
        "schemas": {
            "ops|sales": {
                "name": "sales",
                "tags": {"domain": "operations", "pii": "true"},
            },
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ops|sales",
                        "tags": {"env": "staging"},
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources, override_strategy="replace")

    resolved_tags = result["catalogs"]["main"]["schemas"][0]["tags"]
    # Under the replace strategy the override replaces the entire tags dict.
    assert resolved_tags == {"env": "staging"}


# ---------------------------------------------------------------------------
# override_strategy parameter wiring
# ---------------------------------------------------------------------------


def test_resolver_accepts_override_strategy_kwarg():
    """resolve_refs accepts override_strategy='merge' and override_strategy='replace'."""
    definitions = {"schemas": {"ops|sales": {"name": "sales"}}}
    resources = {"catalogs": {"main": {"schemas": [{"$ref": "$defs/schemas/ops|sales"}]}}}

    # Both explicit values should succeed.
    result_merge = resolve_refs(definitions, resources, override_strategy="merge")
    result_replace = resolve_refs(definitions, resources, override_strategy="replace")
    # And the default (no kwarg) should match the merge result — proves default is "merge".
    result_default = resolve_refs(definitions, resources)
    assert result_merge == result_default
    assert "catalogs" in result_replace


# ---------------------------------------------------------------------------
# merge strategy — maps
# ---------------------------------------------------------------------------


def test_resolver_merge_strategy_deep_merges_nested_map():
    """Override of a nested map merges keys instead of replacing the whole map."""
    definitions = {
        "schemas": {
            "ops|sales": {
                "name": "sales",
                "tags": {"domain": "operations", "pii": "true"},
            },
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ops|sales",
                        "tags": {"pii": "false", "env": "staging"},
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    resolved_tags = result["catalogs"]["main"]["schemas"][0]["tags"]
    # domain preserved from definition; pii overridden; env added from override.
    assert resolved_tags == {"domain": "operations", "pii": "false", "env": "staging"}


def test_resolver_merge_strategy_recursively_merges_dict_of_dicts():
    """A two-level-nested override only touches the keys it specifies; sibling subtrees untouched."""
    definitions = {
        "catalogs": {
            "ops": {
                "name": "ops",
                "settings": {
                    "ingest": {"format": "parquet", "compression": "snappy"},
                    "query": {"caching": "on", "ttl": "1h"},
                },
            },
        },
    }
    resources = {
        "catalogs": {
            "ops_test": {
                "$ref": "$defs/catalogs/ops",
                "settings": {
                    "query": {"ttl": "5m"},
                },
            },
        },
    }

    result = resolve_refs(definitions, resources)

    settings = result["catalogs"]["ops_test"]["settings"]
    # Sibling subtree 'ingest' preserved entirely.
    assert settings["ingest"] == {"format": "parquet", "compression": "snappy"}
    # 'query.caching' preserved from definition; 'query.ttl' overridden.
    assert settings["query"] == {"caching": "on", "ttl": "5m"}


def test_resolver_merge_strategy_override_leaf_replaces_scalar():
    """A scalar leaf is replaced wholesale by an override."""
    definitions = {
        "schemas": {
            "ops|sales": {"name": "sales", "comment": "Original"},
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [
                    {"$ref": "$defs/schemas/ops|sales", "comment": "Changed"},
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    schema = result["catalogs"]["main"]["schemas"][0]
    assert schema["comment"] == "Changed"
    assert schema["name"] == "sales"


def test_resolver_merge_strategy_override_none_replaces_value():
    """An explicit None in an override replaces the definition value."""
    definitions = {
        "schemas": {
            "ops|sales": {"name": "sales", "comment": "Original"},
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [
                    {"$ref": "$defs/schemas/ops|sales", "comment": None},
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    schema = result["catalogs"]["main"]["schemas"][0]
    assert schema["comment"] is None


# ---------------------------------------------------------------------------
# merge strategy — lists with identifiers
# ---------------------------------------------------------------------------


def test_resolver_merge_strategy_merges_list_of_dicts_by_name():
    """A list of dicts with 'name' identifiers is merged item-wise by matching name."""
    definitions = {
        "schemas": {
            "ops|sales": {
                "name": "sales",
                "tables": [
                    {"name": "orders", "comment": "Orders table"},
                    {"name": "quotes", "comment": "Quotes table"},
                ],
            },
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ops|sales",
                        "tables": [
                            {"name": "quotes", "comment": "TEST quotes"},
                            {"name": "leads", "comment": "Leads table"},
                        ],
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    tables = result["catalogs"]["main"]["schemas"][0]["tables"]
    # orders preserved from definition; quotes merged with override comment; leads appended.
    table_by_name = {t["name"]: t for t in tables}
    assert table_by_name["orders"]["comment"] == "Orders table"
    assert table_by_name["quotes"]["comment"] == "TEST quotes"
    assert table_by_name["leads"]["comment"] == "Leads table"
    assert len(tables) == 3


def test_resolver_merge_strategy_merges_list_of_refs_by_ref():
    """A list of {$ref: ...} items on both sides is merged by matching $ref strings."""
    definitions = {
        "schemas": {
            "ops|sales": {
                "name": "sales",
                "tables": [
                    {"$ref": "$defs/tables/ops|sales|orders"},
                    {"$ref": "$defs/tables/ops|sales|quotes"},
                ],
            },
        },
        "tables": {
            "ops|sales|orders": {"name": "orders", "comment": "Orders table"},
            "ops|sales|quotes": {"name": "quotes", "comment": "Quotes table"},
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ops|sales",
                        "tables": [
                            {
                                "$ref": "$defs/tables/ops|sales|quotes",
                                "comment": "TEST quotes",
                            },
                        ],
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    tables = result["catalogs"]["main"]["schemas"][0]["tables"]
    # The two definition refs are preserved; the override-side ref matches 'quotes' by $ref
    # and contributes a comment override.
    table_by_name = {t["name"]: t for t in tables}
    assert "orders" in table_by_name
    assert table_by_name["orders"]["comment"] == "Orders table"
    assert table_by_name["quotes"]["comment"] == "TEST quotes"
    assert len(tables) == 2


def test_resolver_merge_strategy_uses_alias_as_identifier_when_no_name():
    """Items without 'name' but with 'alias' are matched by 'alias'."""
    definitions = {
        "schemas": {
            "ops|sales": {
                "name": "sales",
                "columns": [
                    {"alias": "id", "comment": "Original id"},
                    {"alias": "total", "comment": "Original total"},
                ],
            },
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ops|sales",
                        "columns": [
                            {"alias": "total", "comment": "Overridden total"},
                        ],
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    columns = result["catalogs"]["main"]["schemas"][0]["columns"]
    col_by_alias = {c["alias"]: c for c in columns}
    assert col_by_alias["id"]["comment"] == "Original id"
    assert col_by_alias["total"]["comment"] == "Overridden total"
    assert len(columns) == 2


def test_resolver_merge_strategy_prefers_alias_over_ref_as_identifier():
    """When an item has 'alias' and '$ref' but no 'name', 'alias' is the identifier."""
    definitions = {
        "schemas": {
            "ops|sales": {
                "name": "sales",
                "columns": [
                    {"alias": "id", "comment": "Original"},
                ],
            },
        },
        "tables": {
            "ops|sales|template": {"name": "template", "comment": "Template"},
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ops|sales",
                        "columns": [
                            {
                                "$ref": "$defs/tables/ops|sales|template",
                                "alias": "id",
                                "comment": "Overridden",
                            },
                        ],
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    columns = result["catalogs"]["main"]["schemas"][0]["columns"]
    # The override matches the definition's column by alias=id.
    assert len(columns) == 1
    assert columns[0]["alias"] == "id"
    assert columns[0]["comment"] == "Overridden"


def test_resolver_merge_strategy_prefers_name_over_ref_as_identifier():
    """When items carry both 'name' and '$ref', 'name' is the matching identifier."""
    definitions = {
        "schemas": {
            "ops|sales": {
                "name": "sales",
                "tables": [
                    {"name": "orders", "comment": "Original"},
                ],
            },
        },
        "tables": {
            "ops|sales|orders_template": {"name": "orders", "comment": "From template"},
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ops|sales",
                        "tables": [
                            {
                                "$ref": "$defs/tables/ops|sales|orders_template",
                                "name": "orders",
                                "comment": "Overridden",
                            },
                        ],
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    tables = result["catalogs"]["main"]["schemas"][0]["tables"]
    # Override identifier is 'name=orders', which matches the definition's table by name.
    # The override carries a comment override that wins.
    assert len(tables) == 1
    assert tables[0]["name"] == "orders"
    assert tables[0]["comment"] == "Overridden"


# ---------------------------------------------------------------------------
# merge strategy — lists of primitives
# ---------------------------------------------------------------------------


def test_resolver_merge_strategy_unions_lists_of_primitives():
    """Primitive lists are unioned (definition order first, then new items from override)."""
    definitions = {
        "policies": {
            "shared|grant": {
                "name": "grant",
                "privileges": ["SELECT", "USE_SCHEMA"],
            },
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "policies": [
                    {
                        "$ref": "$defs/policies/shared|grant",
                        "privileges": ["SELECT", "MODIFY"],
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    privileges = result["catalogs"]["main"]["policies"][0]["privileges"]
    # Definition order preserved, MODIFY appended, SELECT deduped.
    assert privileges == ["SELECT", "USE_SCHEMA", "MODIFY"]


def test_resolver_merge_strategy_leaves_primitive_list_unchanged_when_override_empty():
    """An empty override list leaves the definition's primitive list intact."""
    definitions = {
        "policies": {
            "shared|grant": {
                "name": "grant",
                "privileges": ["SELECT", "MODIFY"],
            },
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "policies": [
                    {"$ref": "$defs/policies/shared|grant", "privileges": []},
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    privileges = result["catalogs"]["main"]["policies"][0]["privileges"]
    assert privileges == ["SELECT", "MODIFY"]


# ---------------------------------------------------------------------------
# merge strategy — fallback to replace
# ---------------------------------------------------------------------------


def test_resolver_merge_strategy_replaces_list_when_items_lack_identifier():
    """A list of dicts whose items have no 'name' or '$ref' falls back to replace."""
    definitions = {
        "schemas": {
            "ops|sales": {
                "name": "sales",
                "extras": [{"comment": "first"}, {"comment": "second"}],
            },
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ops|sales",
                        "extras": [{"comment": "only"}],
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    extras = result["catalogs"]["main"]["schemas"][0]["extras"]
    # No identifiers → override wins entirely.
    assert extras == [{"comment": "only"}]


def test_resolver_merge_strategy_replaces_when_type_mismatch():
    """A type mismatch between definition value and override value → override wins."""
    definitions = {
        "schemas": {
            "ops|sales": {
                "name": "sales",
                # Definition has a dict; override will provide a list.
                "extras": {"key": "value"},
            },
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ops|sales",
                        "extras": ["a", "b"],
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    extras = result["catalogs"]["main"]["schemas"][0]["extras"]
    # Override wins on type mismatch.
    assert extras == ["a", "b"]


# ---------------------------------------------------------------------------
# Error detection preserved under both strategies
# ---------------------------------------------------------------------------


def test_resolver_merge_strategy_preserves_circular_detection():
    """Circular $refs raise ResolutionError under both merge and replace strategies."""
    definitions = {
        "schemas": {
            "a": {"name": "a", "tables": [{"$ref": "$defs/tables/b"}]},
        },
        "tables": {
            "b": {"name": "b", "columns": [{"$ref": "$defs/schemas/a"}]},
        },
    }
    resources = {"catalogs": {"main": {"schemas": [{"$ref": "$defs/schemas/a"}]}}}

    with pytest.raises(ResolutionError, match="[Cc]ircular"):
        resolve_refs(definitions, resources, override_strategy="merge")
    with pytest.raises(ResolutionError, match="[Cc]ircular"):
        resolve_refs(definitions, resources, override_strategy="replace")


def test_resolver_merge_strategy_preserves_unreferenced_detection():
    """Unreferenced definitions are detected under both merge and replace strategies."""
    definitions = {
        "schemas": {
            "ops|sales": {"name": "sales"},
            "ops|hr": {"name": "hr"},
        },
    }
    resources = {
        "catalogs": {"main": {"schemas": [{"$ref": "$defs/schemas/ops|sales"}]}}
    }
    with pytest.raises(UnreferencedDefinitionError, match="ops\\|hr"):
        resolve_refs(definitions, resources, override_strategy="merge")
    with pytest.raises(UnreferencedDefinitionError, match="ops\\|hr"):
        resolve_refs(definitions, resources, override_strategy="replace")


# ---------------------------------------------------------------------------
# Nested / recursive resolution
# ---------------------------------------------------------------------------


def test_resolver_resolves_nested_refs():
    """A schema definition containing table $refs has all levels resolved."""
    definitions = {
        "schemas": {
            "ops|sales": {
                "name": "sales",
                "tables": [
                    {"$ref": "$defs/tables/ops|sales|orders"},
                ],
            },
        },
        "tables": {
            "ops|sales|orders": {
                "name": "orders",
                "comment": "Orders table",
            },
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [
                    {"$ref": "$defs/schemas/ops|sales"},
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    resolved_table = result["catalogs"]["main"]["schemas"][0]["tables"][0]
    assert resolved_table["name"] == "orders"
    assert resolved_table["comment"] == "Orders table"
    assert "$ref" not in resolved_table


def test_resolver_resolves_refs_with_overrides_nested_within_override():
    """An override can contain $ref entries that themselves carry overrides."""
    definitions = {
        "schemas": {
            "ops|sales": {
                "name": "sales",
                "comment": "Sales schema",
                "tables": [
                    {"$ref": "$defs/tables/ops|sales|orders"},
                ],
            },
        },
        "tables": {
            "ops|sales|orders": {
                "name": "orders",
                "comment": "Orders table",
            },
            "ops|sales|quotes": {
                "name": "quotes",
                "comment": "Quotes table",
            },
        },
    }
    resources = {
        "catalogs": {
            "operations_test": {
                "comment": "TEST Operations catalog",
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ops|sales",
                        "name": "sales_staging",
                        "tables": [
                            {"$ref": "$defs/tables/ops|sales|orders"},
                            {
                                "$ref": "$defs/tables/ops|sales|quotes",
                                "comment": "This table only exists in TEST",
                            },
                        ],
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    schema = result["catalogs"]["operations_test"]["schemas"][0]
    assert schema["name"] == "sales_staging"
    assert schema["comment"] == "Sales schema"  # from definition, not overridden

    # The tables override replaced the definition's tables list entirely
    assert len(schema["tables"]) == 2

    # First table: resolved from ref, no overrides
    assert schema["tables"][0]["name"] == "orders"
    assert schema["tables"][0]["comment"] == "Orders table"
    assert "$ref" not in schema["tables"][0]

    # Second table: resolved from ref with comment override
    assert schema["tables"][1]["name"] == "quotes"
    assert schema["tables"][1]["comment"] == "This table only exists in TEST"
    assert "$ref" not in schema["tables"][1]


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


def test_resolver_raises_on_missing_ref():
    """A $ref pointing to a non-existent key raises ResolutionError."""
    definitions = {
        "schemas": {},
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [
                    {"$ref": "$defs/schemas/does|not|exist"},
                ],
            },
        },
    }

    with pytest.raises(ResolutionError, match="does|not|exist"):
        resolve_refs(definitions, resources)


# ---------------------------------------------------------------------------
# Pass-through / mixed entries
# ---------------------------------------------------------------------------


def test_resolver_passes_through_inline_entries():
    """Entries without $ref are left unchanged in the output."""
    definitions: dict = {}
    resources = {
        "catalogs": {
            "main": {
                "schemas": [
                    {"name": "raw", "comment": "Inline schema"},
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    resolved_schema = result["catalogs"]["main"]["schemas"][0]
    assert resolved_schema == {"name": "raw", "comment": "Inline schema"}


def test_resolver_handles_mixed_refs_and_inline():
    """A list containing both $ref entries and inline dicts resolves only the refs."""
    definitions = {
        "schemas": {
            "ops|sales": {
                "name": "sales",
                "comment": "From definition",
            },
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [
                    {"$ref": "$defs/schemas/ops|sales"},
                    {"name": "raw", "comment": "Inline"},
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    schemas = result["catalogs"]["main"]["schemas"]
    assert len(schemas) == 2

    # The ref entry is resolved.
    assert schemas[0]["name"] == "sales"
    assert schemas[0]["comment"] == "From definition"
    assert "$ref" not in schemas[0]

    # The inline entry is unchanged.
    assert schemas[1] == {"name": "raw", "comment": "Inline"}


# ---------------------------------------------------------------------------
# Unreferenced definitions
# ---------------------------------------------------------------------------


def test_resolver_raises_on_unreferenced_definition():
    definitions = {
        "schemas": {
            "ops|sales": {"name": "sales"},
            "ops|hr": {"name": "hr"},
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [{"$ref": "$defs/schemas/ops|sales"}],
            }
        }
    }
    with pytest.raises(UnreferencedDefinitionError, match="ops\\|hr"):
        resolve_refs(definitions, resources)


def test_resolver_passes_when_all_definitions_referenced():
    definitions = {
        "schemas": {
            "ops|sales": {"name": "sales"},
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [{"$ref": "$defs/schemas/ops|sales"}],
            }
        }
    }
    result = resolve_refs(definitions, resources)
    assert "catalogs" in result


def test_resolver_raises_with_multiple_unreferenced_definitions():
    definitions = {
        "schemas": {
            "ops|sales": {"name": "sales"},
            "ops|hr": {"name": "hr"},
        },
        "tables": {
            "ops|sales|orders": {"name": "orders"},
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [{"$ref": "$defs/schemas/ops|sales"}],
            }
        }
    }
    with pytest.raises(UnreferencedDefinitionError) as exc_info:
        resolve_refs(definitions, resources)
    msg = str(exc_info.value)
    assert "ops|hr" in msg
    assert "ops|sales|orders" in msg


# ---------------------------------------------------------------------------
# Malformed and circular refs
# ---------------------------------------------------------------------------


def test_resolver_raises_on_malformed_ref_without_slash():
    """A $ref value missing the second slash (type/key separator) raises ResolutionError."""
    definitions = {"schemas": {"ops|sales": {"name": "sales"}}}
    resources = {"catalogs": {"main": {"schemas": [{"$ref": "$defs/schemas_no_key"}]}}}

    with pytest.raises(ResolutionError):
        resolve_refs(definitions, resources)


def test_resolver_raises_on_circular_reference():
    """Definition A references B and B references A — raises ResolutionError with 'circular'."""
    definitions = {
        "schemas": {
            "a": {"name": "a", "tables": [{"$ref": "$defs/tables/b"}]},
        },
        "tables": {
            "b": {"name": "b", "columns": [{"$ref": "$defs/schemas/a"}]},
        },
    }
    resources = {"catalogs": {"main": {"schemas": [{"$ref": "$defs/schemas/a"}]}}}

    with pytest.raises(ResolutionError, match="[Cc]ircular"):
        resolve_refs(definitions, resources)


# ---------------------------------------------------------------------------
# Inline $defs string resolution
# ---------------------------------------------------------------------------


def test_resolver_resolves_inline_defs_string_value():
    """A field value like `function: $defs/functions/shared|fn_filter` resolves to the function definition dict."""
    definitions = {
        "functions": {
            "shared|fn_filter": {
                "name": "fn_filter",
                "parameters": [{"name": "office", "type": "STRING"}],
                "return": "BOOLEAN",
            },
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "policies": [
                    {
                        "name": "filter_by_office_location",
                        "function": "$defs/functions/shared|fn_filter",
                        "tags": {"office_location": "true"},
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    policy = result["catalogs"]["main"]["policies"][0]
    # The string is replaced with the full definition content (a dict).
    assert isinstance(policy["function"], dict)
    assert policy["function"]["name"] == "fn_filter"
    assert policy["function"]["parameters"] == [{"name": "office", "type": "STRING"}]
    assert policy["function"]["return"] == "BOOLEAN"
    # The rest of the policy is unchanged.
    assert policy["name"] == "filter_by_office_location"
    assert policy["tags"] == {"office_location": "true"}


def test_resolver_inline_defs_string_counts_as_referenced():
    """An inline $defs/... string value counts as a reference for unreferenced-definition detection."""
    definitions = {
        "functions": {
            "shared|fn_filter": {
                "name": "fn_filter",
                "parameters": [],
                "return": "BOOLEAN",
            },
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "policies": [
                    {
                        "name": "filter_policy",
                        "function": "$defs/functions/shared|fn_filter",
                    },
                ],
            },
        },
    }

    # Should NOT raise UnreferencedDefinitionError — the inline string counts as a reference.
    result = resolve_refs(definitions, resources)
    assert "catalogs" in result


def test_resolver_inline_defs_string_resolves_nested_refs():
    """When an inline $defs/... string resolves to a definition containing further refs, those are resolved too."""
    definitions = {
        "functions": {
            "shared|fn_filter": {
                "name": "fn_filter",
                "helper": {"$ref": "$defs/functions/shared|fn_helper"},
            },
            "shared|fn_helper": {
                "name": "fn_helper",
                "return": "STRING",
            },
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "policies": [
                    {
                        "name": "filter_policy",
                        "function": "$defs/functions/shared|fn_filter",
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    policy = result["catalogs"]["main"]["policies"][0]
    resolved_fn = policy["function"]
    assert isinstance(resolved_fn, dict)
    assert resolved_fn["name"] == "fn_filter"
    # The nested $ref inside the function definition was also resolved.
    assert isinstance(resolved_fn["helper"], dict)
    assert resolved_fn["helper"]["name"] == "fn_helper"
    assert resolved_fn["helper"]["return"] == "STRING"
    assert "$ref" not in resolved_fn["helper"]


def test_resolver_inline_defs_string_raises_on_missing_key():
    """An inline $defs/... string pointing to a non-existent key raises ResolutionError."""
    definitions = {
        "functions": {},
    }
    resources = {
        "catalogs": {
            "main": {
                "policies": [
                    {
                        "name": "filter_policy",
                        "function": "$defs/functions/shared|does_not_exist",
                    },
                ],
            },
        },
    }

    with pytest.raises(ResolutionError, match="does_not_exist"):
        resolve_refs(definitions, resources)


def test_resolver_inline_defs_string_raises_on_circular_reference():
    """Circular references involving inline $defs/... strings are detected and raise ResolutionError."""
    definitions = {
        "functions": {
            "shared|fn_a": {
                "name": "fn_a",
                "delegate": "$defs/functions/shared|fn_b",
            },
            "shared|fn_b": {
                "name": "fn_b",
                "delegate": "$defs/functions/shared|fn_a",
            },
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "policies": [
                    {
                        "name": "circular_policy",
                        "function": "$defs/functions/shared|fn_a",
                    },
                ],
            },
        },
    }

    with pytest.raises(ResolutionError, match="[Cc]ircular"):
        resolve_refs(definitions, resources)


def test_resolver_resolves_inline_defs_strings_in_list():
    """Bare $defs/... strings as list items are resolved to definition dicts (catalog-style shorthand)."""
    definitions = {
        "schemas": {
            "ops|sales": {"name": "sales", "comment": "Sales schema"},
            "people|hr": {"name": "hr", "comment": "HR schema"},
        },
        "policies": {
            "shared|mask_pii_email": {
                "name": "mask_pii_email",
                "type": "mask",
                "function": "platform.abac.mask_pii_email",
            },
        },
    }
    resources = {
        "catalogs": {
            "operations_prod": {
                "name": "operations_prod",
                "comment": "Production operations catalog",
                "policies": [
                    "$defs/policies/shared|mask_pii_email",
                ],
                "schemas": [
                    "$defs/schemas/ops|sales",
                    "$defs/schemas/people|hr",
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    catalog = result["catalogs"]["operations_prod"]
    # Policies list: bare string resolved to full definition dict
    assert len(catalog["policies"]) == 1
    assert isinstance(catalog["policies"][0], dict)
    assert catalog["policies"][0]["name"] == "mask_pii_email"
    assert catalog["policies"][0]["type"] == "mask"
    assert catalog["policies"][0]["function"] == "platform.abac.mask_pii_email"

    # Schemas list: both bare strings resolved to definition dicts
    assert len(catalog["schemas"]) == 2
    assert isinstance(catalog["schemas"][0], dict)
    assert catalog["schemas"][0]["name"] == "sales"
    assert catalog["schemas"][0]["comment"] == "Sales schema"
    assert isinstance(catalog["schemas"][1], dict)
    assert catalog["schemas"][1]["name"] == "hr"
    assert catalog["schemas"][1]["comment"] == "HR schema"


def test_resolver_leaves_non_defs_strings_unchanged():
    """Regular strings and strings that don't match the $defs/ prefix are left unchanged."""
    definitions: dict = {}
    resources = {
        "catalogs": {
            "main": {
                "policies": [
                    {
                        "name": "inline_policy",
                        "function": "platform.shared.mask_pii_email",
                        "comment": "A plain string",
                        "filter": "some_function_name",
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    policy = result["catalogs"]["main"]["policies"][0]
    assert policy["function"] == "platform.shared.mask_pii_email"
    assert policy["comment"] == "A plain string"
    assert policy["filter"] == "some_function_name"
