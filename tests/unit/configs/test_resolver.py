from __future__ import annotations

import pytest

from uc_abac_governor.configs.resolver import resolve_refs
from uc_abac_governor.types import ResolutionError, UnreferencedDefinitionError


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
