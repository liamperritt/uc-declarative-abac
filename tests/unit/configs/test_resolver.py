from __future__ import annotations

import pytest

from uc_declarative_abac.configs import resolve_refs
from uc_declarative_abac.utils import (
    ResolutionError,
    TemplateVariableError,
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
    resources = {
        "catalogs": {"main": {"schemas": [{"$ref": "$defs/schemas/ops|sales"}]}}
    }

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


def test_resolver_merge_strategy_preserves_both_refs_when_ref_identifiers_differ():
    """When list items on both sides carry $ref identifiers but the refs differ, both are preserved (no replacement)."""
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
            "ops|sales|leads": {"name": "leads", "comment": "Leads table"},
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ops|sales",
                        "tables": [
                            {"$ref": "$defs/tables/ops|sales|leads"},
                        ],
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    tables = result["catalogs"]["main"]["schemas"][0]["tables"]
    # The override's $ref doesn't match either definition $ref, so it's appended without
    # displacing the definition's refs. All three resolve independently in the post-merge pass.
    table_by_name = {t["name"]: t for t in tables}
    assert set(table_by_name) == {"orders", "quotes", "leads"}
    assert table_by_name["orders"]["comment"] == "Orders table"
    assert table_by_name["quotes"]["comment"] == "Quotes table"
    assert table_by_name["leads"]["comment"] == "Leads table"
    assert len(tables) == 3


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
# merge strategy — lists containing inline $defs/... strings
# ---------------------------------------------------------------------------


def test_resolver_merge_strategy_appends_inline_defs_string_to_definition_list():
    """An override list with an inline $defs/... string appends the resolved item to the definition list."""
    definitions = {
        "columns": {
            "region": {"name": "region", "type": "string"},
        },
        "tables": {
            "ops|sales|orders": {
                "name": "orders",
                "columns": [
                    {"name": "id", "type": "bigint"},
                    {"name": "total", "type": "decimal"},
                ],
            },
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "tables": [
                    {
                        "$ref": "$defs/tables/ops|sales|orders",
                        "columns": ["$defs/columns/region"],
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    columns = result["catalogs"]["main"]["tables"][0]["columns"]
    # The original two columns from the definition are preserved, and the inline-string
    # override resolves to the region column and is appended at the end.
    assert [c["name"] for c in columns] == ["id", "total", "region"]
    assert columns[2]["type"] == "string"


def test_resolver_merge_strategy_merges_inline_defs_string_into_list_when_definition_uses_inline_defs_strings():
    """When both sides use inline $defs/... string shorthand, the lists merge by resolved name."""
    definitions = {
        "columns": {
            "id": {"name": "id", "type": "bigint"},
            "total": {"name": "total", "type": "decimal"},
            "region": {"name": "region", "type": "string"},
        },
        "tables": {
            "ops|sales|orders": {
                "name": "orders",
                "columns": [
                    "$defs/columns/id",
                    "$defs/columns/total",
                ],
            },
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "tables": [
                    {
                        "$ref": "$defs/tables/ops|sales|orders",
                        "columns": ["$defs/columns/region"],
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    columns = result["catalogs"]["main"]["tables"][0]["columns"]
    assert [c["name"] for c in columns] == ["id", "total", "region"]
    assert all(isinstance(c, dict) for c in columns)


def test_resolver_merge_strategy_resolves_inline_defs_string_nested_in_sub_dict_list():
    """An inline $defs/... string inside a list field nested under a sub-dict is pre-resolved correctly."""
    definitions = {
        "columns": {
            "region": {"name": "region", "type": "string"},
        },
        "schemas": {
            "ops|sales": {
                "name": "sales",
                "metadata": {
                    "default_columns": [
                        {"name": "id", "type": "bigint"},
                        {"name": "total", "type": "decimal"},
                    ],
                },
            },
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ops|sales",
                        "metadata": {
                            "default_columns": ["$defs/columns/region"],
                        },
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    cols = result["catalogs"]["main"]["schemas"][0]["metadata"]["default_columns"]
    # The inline-string override sits inside `metadata.default_columns`; the resolver must
    # walk into the sub-dict to pre-resolve it so the list merge sees dicts on both sides
    # and appends `region` to the inherited columns instead of replacing them.
    assert [c["name"] for c in cols] == ["id", "total", "region"]


def test_resolver_merge_strategy_resolved_override_can_merge_onto_matching_definition_column():
    """An inline-string override that resolves to a same-name column merges, preserving definition-only fields."""
    definitions = {
        "columns": {
            "total_alt": {"name": "total", "comment": "Overridden"},
        },
        "tables": {
            "ops|sales|orders": {
                "name": "orders",
                "columns": [
                    {"name": "total", "type": "decimal", "comment": "Original"},
                ],
            },
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "tables": [
                    {
                        "$ref": "$defs/tables/ops|sales|orders",
                        "columns": ["$defs/columns/total_alt"],
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    columns = result["catalogs"]["main"]["tables"][0]["columns"]
    # By-name merge against the definition's total column: comment is overridden,
    # but `type` (which only exists on the definition side) is preserved.
    assert len(columns) == 1
    assert columns[0]["name"] == "total"
    assert columns[0]["comment"] == "Overridden"
    assert columns[0]["type"] == "decimal"


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


# ---------------------------------------------------------------------------
# Template variables ($vars + {{ placeholder }})
# ---------------------------------------------------------------------------


def _schema_defs():
    """A schema definition template with a required `env` and defaulted `medallion`."""
    return {
        "schemas": {
            "ingestion|salesforce": {
                "$vars": {"env": None, "medallion": "bronze"},
                "name": "salesforce",
                "tags": {
                    "environment": "{{ env }}",
                    "quality_tier": "{{ medallion }}",
                },
            },
        },
    }


def test_resolver_substitutes_ref_vars():
    """A $ref's $vars values are substituted into the template body."""
    resources = {
        "catalogs": {
            "ingestion_prod": {
                "name": "ingestion_prod",
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ingestion|salesforce",
                        "$vars": {"env": "prod", "medallion": "silver"},
                    },
                ],
            },
        },
    }

    result = resolve_refs(_schema_defs(), resources)

    schema = result["catalogs"]["ingestion_prod"]["schemas"][0]
    assert schema["tags"] == {"environment": "prod", "quality_tier": "silver"}
    # $vars is consumed, never left on the resolved body.
    assert "$vars" not in schema


def test_resolver_uses_definition_default_when_var_omitted():
    """A $ref that omits a defaulted variable picks up the definition's default."""
    resources = {
        "catalogs": {
            "ingestion_prod": {
                "name": "ingestion_prod",
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ingestion|salesforce",
                        "$vars": {"env": "prod"},  # medallion omitted → bronze
                    },
                ],
            },
        },
    }

    result = resolve_refs(_schema_defs(), resources)

    schema = result["catalogs"]["ingestion_prod"]["schemas"][0]
    assert schema["tags"]["quality_tier"] == "bronze"


def test_resolver_ref_var_overrides_definition_default():
    """A $ref supplying a defaulted variable overrides the default."""
    resources = {
        "catalogs": {
            "c": {
                "name": "c",
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ingestion|salesforce",
                        "$vars": {"env": "uat", "medallion": "gold"},
                    },
                ],
            },
        },
    }

    result = resolve_refs(_schema_defs(), resources)

    assert result["catalogs"]["c"]["schemas"][0]["tags"]["quality_tier"] == "gold"


def test_resolver_forwards_vars_through_nested_ref():
    """A definition forwards a variable to a child $ref via a {{ placeholder }} $vars value."""
    definitions = {
        "tables": {
            "ingestion|salesforce|account": {
                "$vars": {"env": None},
                "name": "account",
                "tags": {"environment": "{{ env }}"},
            },
        },
        "schemas": {
            "ingestion|salesforce": {
                "$vars": {"env": None},
                "name": "salesforce",
                "tables": [
                    {
                        "$ref": "$defs/tables/ingestion|salesforce|account",
                        "$vars": {"env": "{{ env }}"},
                    },
                ],
            },
        },
    }
    resources = {
        "catalogs": {
            "ingestion_prod": {
                "name": "ingestion_prod",
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ingestion|salesforce",
                        "$vars": {"env": "prod"},
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    table = result["catalogs"]["ingestion_prod"]["schemas"][0]["tables"][0]
    assert table["tags"]["environment"] == "prod"


def test_resolver_rejects_placeholder_in_resource_override():
    """A placeholder in a $ref override value at the resource level is an error.

    Resources are the concrete instance layer: a placeholder there is bound by nothing
    (the enclosing definition binds placeholders, and a resource is not a definition). The
    author must supply the literal or move the templating into a definition.
    """
    resources = {
        "catalogs": {
            "c": {
                "name": "c",
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ingestion|salesforce",
                        "name": "{{ env }}_salesforce_raw",
                        "$vars": {"env": "prod"},
                    },
                ],
            },
        },
    }

    with pytest.raises(TemplateVariableError):
        resolve_refs(_schema_defs(), resources)


def test_resolver_binds_child_ref_override_to_enclosing_definition():
    """An override a definition writes onto a child $ref is bound by that definition's $vars.

    The schema overrides the table's `comment` with `{{ env }}` — the schema's own
    variable. It is substituted in the schema's scope before the table $ref expands, so the
    table itself never needs to declare `env`.
    """
    definitions = {
        "tables": {
            "t": {"name": "account"},
        },
        "schemas": {
            "s": {
                "$vars": {"env": None},
                "name": "s_{{ env }}",
                "tables": [
                    {"$ref": "$defs/tables/t", "comment": "created in {{ env }}"},
                ],
            },
        },
    }
    resources = {
        "catalogs": {
            "c": {
                "name": "c",
                "schemas": [
                    {"$ref": "$defs/schemas/s", "$vars": {"env": "prod"}},
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    table = result["catalogs"]["c"]["schemas"][0]["tables"][0]
    assert table["name"] == "account"
    assert table["comment"] == "created in prod"


def test_resolver_supports_inline_ref_with_placeholder_override_in_definition():
    """A definition's inline $ref override may carry a placeholder bound by that definition.

    The catalog definition's `tags` inlines a shared `base_tags` fragment and adds
    `environment: '{{ env }}'`. The placeholder is the catalog's own (bound by its $vars),
    substituted before base_tags is merged — so base_tags never needs to know `env`. This
    previously raised a spurious "missing variable" because the placeholder was mis-bound to
    the base_tags $ref's (empty) scope.
    """
    definitions = {
        "tags": {
            "base_tags": {
                "governed_by": "uc_declarative_abac",
                "classification": "in_confidence",
            },
        },
        "catalogs": {
            "ingestion": {
                "$vars": {"env": None},
                "name": "ingestion_{{ env }}",
                "tags": {
                    "$ref": "$defs/tags/base_tags",
                    "environment": "{{ env }}",
                },
            },
        },
    }
    resources = {
        "catalogs": {
            "ingestion_prod": {
                "$ref": "$defs/catalogs/ingestion",
                "$vars": {"env": "prod"},
            },
        },
    }

    result = resolve_refs(definitions, resources)

    catalog = result["catalogs"]["ingestion_prod"]
    assert catalog["name"] == "ingestion_prod"
    assert catalog["tags"] == {
        "governed_by": "uc_declarative_abac",
        "classification": "in_confidence",
        "environment": "prod",
    }


def test_resolver_rejects_parent_widening_child_contract_via_override():
    """A parent cannot smuggle a variable into a child's contract via an override + $vars.

    The function template's contract is {redaction_character}. A schema references it and
    adds `owner: sp_..._{{ env }}` plus `$vars: {env: ...}`. Now `owner` is bound in the
    schema's scope, so `env` reaches the function $ref as a surplus argument the function
    never uses → unused-variable error. The function's declared contract is protected.
    """
    definitions = {
        "functions": {
            "abac|format_phone": {
                "$vars": {"redaction_character": "+"},
                "name": "format_phone",
                "return": "concat('{{ redaction_character }}', code, phone)",
            },
        },
        "schemas": {
            "liam_perritt|default": {
                "$vars": {"env": None},
                "name": "default",
                "functions": [
                    {
                        "$ref": "$defs/functions/abac|format_phone",
                        "$vars": {"env": "{{ env }}"},
                        "owner": "sp_uc_governor_{{ env }}",
                    },
                ],
            },
        },
    }
    resources = {
        "catalogs": {
            "c": {
                "name": "c",
                "schemas": [
                    {
                        "$ref": "$defs/schemas/liam_perritt|default",
                        "$vars": {"env": "prod"},
                    },
                ],
            },
        },
    }

    with pytest.raises(TemplateVariableError, match="[Uu]nused"):
        resolve_refs(definitions, resources)


def _format_phone_defs():
    """A function declaring a required `env` used *only* in `owner`, plus a defaulted var."""
    return {
        "functions": {
            "abac|format_phone": {
                "$vars": {"env": None, "redaction_character": "+"},
                "name": "format_phone",
                "owner": "sp_uc_governor_{{ env }}",
                "return": "concat('{{ redaction_character }}', code, phone)",
            },
        },
    }


def test_resolver_required_var_not_bypassed_by_overriding_its_usage():
    """A null-declared (required) var stays required even when the $ref overrides away its
    only usage and supplies no value — previously this silently succeeded."""
    resources = {
        "catalogs": {
            "c": {
                "name": "c",
                "schemas": [
                    {
                        "name": "s",
                        "functions": [
                            {
                                "$ref": "$defs/functions/abac|format_phone",
                                "owner": "sp_uc_governor_prod",  # removes the only {{ env }} usage
                            },
                        ],
                    },
                ],
            },
        },
    }

    with pytest.raises(TemplateVariableError, match="[Mm]issing"):
        resolve_refs(_format_phone_defs(), resources)


def test_resolver_supplying_declared_var_valid_even_if_usage_overridden():
    """Supplying a declared var is always valid — even when an override removed its usage.

    The corollary of "null = always required": the caller supplies `env` and also overrides
    `owner`, so `env` is unused in the resolved body, but it is a declared variable and must
    not be flagged as an unused argument.
    """
    resources = {
        "catalogs": {
            "c": {
                "name": "c",
                "schemas": [
                    {
                        "name": "s",
                        "functions": [
                            {
                                "$ref": "$defs/functions/abac|format_phone",
                                "owner": "sp_uc_governor_prod",
                                "$vars": {"env": "prod"},
                            },
                        ],
                    },
                ],
            },
        },
    }

    result = resolve_refs(_format_phone_defs(), resources)

    fn = result["catalogs"]["c"]["schemas"][0]["functions"][0]
    assert fn["owner"] == "sp_uc_governor_prod"  # the override literal
    assert fn["return"] == "concat('+', code, phone)"  # redaction_character default applied
    assert "$vars" not in fn


def test_resolver_defaulted_var_overridden_away_needs_no_value():
    """A defaulted (non-null) declared var whose usage is overridden away needs no value and
    is not flagged missing or unused (its default is simply never rendered)."""
    definitions = {
        "schemas": {
            "s": {
                "$vars": {"medallion": "bronze"},
                "name": "salesforce",
                "tags": {"quality_tier": "{{ medallion }}"},
            },
        },
    }
    resources = {
        "catalogs": {
            "c": {
                "name": "c",
                "schemas": [
                    {
                        "$ref": "$defs/schemas/s",
                        "tags": {"quality_tier": "gold"},  # overrides the only {{ medallion }} usage
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    assert result["catalogs"]["c"]["schemas"][0]["tags"]["quality_tier"] == "gold"


def test_resolver_inline_defs_string_equivalent_to_ref_dict_for_templated_def():
    """A bare `$defs/...` string binds the definition's own $vars defaults, like a $ref dict.

    A definition with a defaulted variable (here `redaction_character: '+'`) referenced by
    the bare-string form resolves against its own default and strips $vars — producing the
    same result as the `{$ref: ...}` form with no arguments.
    """
    definitions = {
        "functions": {
            "abac|format_phone": {
                "$vars": {"redaction_character": "+"},
                "name": "format_phone",
                "owner": "sp_uc_governor_test",
                "return": "concat('{{ redaction_character }}', code, phone)",
            },
        },
    }

    def _resources(functions):
        return {"catalogs": {"c": {"name": "c", "schemas": [
            {"name": "s", "functions": functions},
        ]}}}

    inline = resolve_refs(
        definitions, _resources(["$defs/functions/abac|format_phone"])
    )
    ref_dict = resolve_refs(
        definitions, _resources([{"$ref": "$defs/functions/abac|format_phone"}])
    )

    fn = inline["catalogs"]["c"]["schemas"][0]["functions"][0]
    assert fn == {
        "name": "format_phone",
        "owner": "sp_uc_governor_test",
        "return": "concat('+', code, phone)",
    }
    assert inline == ref_dict


def test_resolver_inline_defs_string_non_dict_body_is_unchanged():
    """A non-dict (list-bodied) definition referenced inline resolves without a $vars crash."""
    definitions = {
        "columns": {"pair": [{"name": "a", "type": "string"}, {"name": "b", "type": "string"}]},
    }
    resources = {"catalogs": {"c": {"name": "c", "tables": [
        {"name": "t", "columns": ["$defs/columns/pair"]},
    ]}}}

    result = resolve_refs(definitions, resources)

    # The list-bodied fragment resolves (no $vars handling applied to a non-dict body).
    assert result["catalogs"]["c"]["tables"][0]["columns"] == [
        [{"name": "a", "type": "string"}, {"name": "b", "type": "string"}],
    ]


def test_resolver_inline_defs_string_missing_required_var_errors():
    """A bare `$defs/...` string to a definition with a required (null) var can't bind it."""
    definitions = {
        "schemas": {
            "s": {"$vars": {"env": None}, "name": "s_{{ env }}"},
        },
    }
    # No way to supply `env` via a bare string → missing-variable error (not a leaked {{ }}).
    resources = {"catalogs": {"c": {"name": "c", "schemas": ["$defs/schemas/s"]}}}

    with pytest.raises(TemplateVariableError, match="[Mm]issing"):
        resolve_refs(definitions, resources)


def test_resolver_rejects_placeholder_in_resource_vars_value():
    """A placeholder in a resource-level $vars value is an error (resource $vars are literals)."""
    resources = {
        "catalogs": {
            "c": {
                "name": "c",
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ingestion|salesforce",
                        "$vars": {"env": "{{ env }}"},
                    },
                ],
            },
        },
    }

    with pytest.raises(TemplateVariableError):
        resolve_refs(_schema_defs(), resources)


def test_resolver_raises_on_malformed_placeholder_in_definition():
    """An identifier-shaped-but-invalid placeholder in a referenced definition is an error."""
    definitions = {
        "schemas": {"s": {"name": "s", "tags": {"e": "{{ my-var }}"}}},
    }
    resources = {"catalogs": {"c": {"name": "c", "schemas": [
        {"$ref": "$defs/schemas/s"},
    ]}}}

    with pytest.raises(TemplateVariableError, match="[Mm]alformed"):
        resolve_refs(definitions, resources)


def test_resolver_raises_on_malformed_placeholder_in_resource_value():
    """A malformed placeholder in a plain resource value is an error (not silently literal)."""
    resources = {"catalogs": {"c": {"name": "ingestion_{{ my-var }}"}}}

    with pytest.raises(TemplateVariableError, match="[Mm]alformed"):
        resolve_refs({}, resources)


def test_resolver_rejects_defs_reference_in_ref_vars_value():
    """A $ref's $vars value that looks like a $defs/ reference errors clearly (not 'must be a string')."""
    definitions = {
        "schemas": {"s": {"$vars": {"x": None}, "name": "{{ x }}"}},
        "columns": {"region": {"name": "region", "type": "string"}},
    }
    resources = {"catalogs": {"c": {"name": "c", "schemas": [
        {"$ref": "$defs/schemas/s", "$vars": {"x": "$defs/columns/region"}},
    ]}}}

    with pytest.raises(TemplateVariableError, match="reference"):
        resolve_refs(definitions, resources)


def test_resolver_rejects_defs_reference_in_definition_default():
    """A definition $vars default that looks like a $defs/ reference errors clearly."""
    definitions = {
        "schemas": {"s": {"$vars": {"x": "$defs/columns/region"}, "name": "{{ x }}"}},
        "columns": {"region": {"name": "region", "type": "string"}},
    }
    resources = {"catalogs": {"c": {"name": "c", "schemas": [
        {"$ref": "$defs/schemas/s"},
    ]}}}

    with pytest.raises(TemplateVariableError, match="reference"):
        resolve_refs(definitions, resources)


def test_resolver_raises_on_missing_var():
    """A $ref that fails to supply a required (non-defaulted) variable is an error."""
    resources = {
        "catalogs": {
            "c": {
                "name": "c",
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ingestion|salesforce",
                        "$vars": {"medallion": "bronze"},  # env missing
                    },
                ],
            },
        },
    }

    with pytest.raises(TemplateVariableError, match="[Mm]issing"):
        resolve_refs(_schema_defs(), resources)


def test_resolver_raises_on_unused_ref_var():
    """A $ref supplying a variable the template does not use is an error."""
    resources = {
        "catalogs": {
            "c": {
                "name": "c",
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ingestion|salesforce",
                        "$vars": {"env": "prod", "typo": "x"},
                    },
                ],
            },
        },
    }

    with pytest.raises(TemplateVariableError, match="[Uu]nused"):
        resolve_refs(_schema_defs(), resources)


def test_resolver_allows_forwarding_only_var():
    """A variable used only to forward to a child $ref is not flagged unused."""
    definitions = {
        "tables": {
            "t": {
                "$vars": {"env": None},
                "name": "account",
                "tags": {"environment": "{{ env }}"},
            },
        },
        "schemas": {
            "s": {
                "$vars": {"env": None},
                "name": "salesforce",
                "tables": [
                    {"$ref": "$defs/tables/t", "$vars": {"env": "{{ env }}"}},
                ],
            },
        },
    }
    resources = {
        "catalogs": {
            "c": {
                "name": "c",
                "schemas": [
                    {"$ref": "$defs/schemas/s", "$vars": {"env": "prod"}},
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    assert (
        result["catalogs"]["c"]["schemas"][0]["tables"][0]["tags"]["environment"]
        == "prod"
    )


def test_resolver_raises_on_placeholder_in_plain_resource_value():
    """A placeholder in a plain resource value is an error (resources must be concrete)."""
    resources = {
        "catalogs": {
            "c": {
                "name": "ingestion_{{ env }}",  # placeholder in a resource — nothing binds it
            },
        },
    }

    with pytest.raises(TemplateVariableError, match="resource value"):
        resolve_refs({}, resources)


def test_resolver_raises_on_placeholder_in_ref_target():
    """A placeholder in a $ref target is never substituted; it fails to resolve."""
    resources = {
        "catalogs": {
            "c": {
                "name": "c",
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ingestion|salesforce_{{ env }}",
                        "$vars": {"env": "prod"},
                    },
                ],
            },
        },
    }

    # The target is not a real definition key and the placeholder is not substituted,
    # so resolution fails (unresolved ref), not a silent success.
    with pytest.raises((ResolutionError, TemplateVariableError)):
        resolve_refs(_schema_defs(), resources)


def test_resolver_null_default_is_still_required():
    """A null-declared variable has no default, so a $ref must still supply it."""
    resources = {
        "catalogs": {
            "c": {
                "name": "c",
                "schemas": [
                    {
                        "$ref": "$defs/schemas/ingestion|salesforce",
                        "$vars": {"medallion": "bronze"},  # env (null) not supplied
                    },
                ],
            },
        },
    }

    with pytest.raises(TemplateVariableError, match="[Mm]issing"):
        resolve_refs(_schema_defs(), resources)


def test_resolver_empty_string_var_binds_empty():
    """An explicit empty-string variable value binds the placeholder to empty."""
    definitions = {
        "schemas": {
            "s": {
                "$vars": {"suffix": None},
                "name": "base{{ suffix }}",
            },
        },
    }
    resources = {
        "catalogs": {
            "c": {
                "name": "c",
                "schemas": [
                    {"$ref": "$defs/schemas/s", "$vars": {"suffix": ""}},
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    assert result["catalogs"]["c"]["schemas"][0]["name"] == "base"


def test_resolver_rejects_non_string_var():
    """A non-string $ref variable value is an error (strings only)."""
    definitions = {
        "schemas": {
            "s": {"$vars": {"n": None}, "name": "s_{{ n }}"},
        },
    }
    resources = {
        "catalogs": {
            "c": {
                "name": "c",
                "schemas": [
                    {"$ref": "$defs/schemas/s", "$vars": {"n": 3}},
                ],
            },
        },
    }

    with pytest.raises(TemplateVariableError, match="must be a string"):
        resolve_refs(definitions, resources)


def test_resolver_escaped_double_braces_survive_substitution_and_guard():
    """Escaped {{{{ }}}} in a function body resolves to literal {{ }} and is not flagged."""
    definitions = {
        "functions": {
            "shared|mask_for_env": {
                "$vars": {"env": None},
                "name": "mask_for_{{ env }}",
                "return": "CASE WHEN '{{ env }}' = 'prod' "
                "THEN CONCAT('{{{{', val, '}}}}') ELSE val END",
            },
        },
    }
    resources = {
        "catalogs": {
            "c": {
                "name": "c",
                "functions": [
                    {
                        "$ref": "$defs/functions/shared|mask_for_env",
                        "$vars": {"env": "prod"},
                    },
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    fn = result["catalogs"]["c"]["functions"][0]
    assert fn["name"] == "mask_for_prod"
    # {{ env }} substituted; the escaped literal braces collapse to single double-braces.
    assert fn["return"] == (
        "CASE WHEN 'prod' = 'prod' THEN CONCAT('{{', val, '}}') ELSE val END"
    )


def test_resolver_replace_strategy_drops_definition_defaults():
    """Under replace, a $ref's $vars wholesale-replaces the definition's defaults."""
    resources = {
        "catalogs": {
            "c": {
                "name": "c",
                "schemas": [
                    {
                        # Under replace, this $vars replaces the definition's
                        # {env: null, medallion: bronze} entirely, so medallion is
                        # no longer defaulted and its placeholder is unbound.
                        "$ref": "$defs/schemas/ingestion|salesforce",
                        "$vars": {"env": "prod"},
                    },
                ],
            },
        },
    }

    with pytest.raises(TemplateVariableError, match="[Mm]issing"):
        resolve_refs(_schema_defs(), resources, override_strategy="replace")


def test_resolver_config_without_vars_is_unchanged():
    """A config with no $vars / placeholders resolves exactly as before."""
    definitions = {
        "schemas": {
            "ops|sales": {"name": "sales", "comment": "Sales"},
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [{"$ref": "$defs/schemas/ops|sales"}],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    schema = result["catalogs"]["main"]["schemas"][0]
    assert schema == {"name": "sales", "comment": "Sales"}


def test_resolver_legacy_params_key_is_inert():
    """After the rename, a `$params` key is no longer the feature trigger.

    It is treated as an ordinary field (not template variables), so it neither binds
    placeholders nor gets stripped — it just passes through like any other key.
    """
    definitions = {
        "schemas": {
            "ops|sales": {"name": "sales", "$params": {"env": "prod"}},
        },
    }
    resources = {
        "catalogs": {
            "main": {
                "schemas": [{"$ref": "$defs/schemas/ops|sales"}],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    schema = result["catalogs"]["main"]["schemas"][0]
    # `$params` is not consumed as a $vars block; it survives as a plain field.
    assert schema == {"name": "sales", "$params": {"env": "prod"}}


def test_resolver_undeclared_vars_allowed_when_no_signature_block():
    """A definition with no $vars block uses implicit variables (all required)."""
    definitions = {
        "schemas": {
            "s": {"name": "salesforce_{{ env }}"},  # implicit env, no $vars block
        },
    }
    resources = {
        "catalogs": {
            "c": {
                "name": "c",
                "schemas": [
                    {"$ref": "$defs/schemas/s", "$vars": {"env": "prod"}},
                ],
            },
        },
    }

    result = resolve_refs(definitions, resources)

    assert result["catalogs"]["c"]["schemas"][0]["name"] == "salesforce_prod"


def test_resolver_raises_on_incomplete_signature_undeclared_placeholder():
    """A declared $vars missing a body placeholder is a hard error, upfront."""
    definitions = {
        "schemas": {
            "s": {
                "$vars": {"env": None},  # region used in body but not declared
                "name": "{{ env }}_{{ region }}",
            },
        },
    }
    resources = {
        "catalogs": {
            "c": {
                "name": "c",
                "schemas": [
                    {
                        "$ref": "$defs/schemas/s",
                        "$vars": {"env": "p", "region": "us"},
                    },
                ],
            },
        },
    }

    with pytest.raises(TemplateVariableError, match="undeclared"):
        resolve_refs(definitions, resources)


def test_resolver_raises_on_incomplete_signature_unused_declaration():
    """A declared variable the body never uses is a hard error, upfront."""
    definitions = {
        "schemas": {
            "s": {
                "$vars": {"env": None, "extra": "x"},  # extra unused
                "name": "{{ env }}",
            },
        },
    }
    resources = {
        "catalogs": {
            "c": {
                "name": "c",
                "schemas": [
                    {"$ref": "$defs/schemas/s", "$vars": {"env": "prod"}},
                ],
            },
        },
    }

    with pytest.raises(TemplateVariableError, match="never uses"):
        resolve_refs(definitions, resources)
