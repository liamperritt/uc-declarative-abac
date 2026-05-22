from __future__ import annotations

import pytest

from uc_declarative_abac.configs.resolver import resolve_refs
from uc_declarative_abac.types import ResolutionError, UnreferencedDefinitionError


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


def test_resolver_override_replaces_entirely():
    """Overriding a nested key replaces it entirely — no deep merge."""
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

    result = resolve_refs(definitions, resources)

    resolved_tags = result["catalogs"]["main"]["schemas"][0]["tags"]
    # The override replaces the entire tags dict; original keys are gone.
    assert resolved_tags == {"env": "staging"}


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
