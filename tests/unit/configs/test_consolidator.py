import pytest

from uc_abac_governor.configs.consolidator import consolidate_resources
from uc_abac_governor.types import GovernorError


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
    with pytest.raises(GovernorError):
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
    with pytest.raises(GovernorError):
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
    with pytest.raises(GovernorError):
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
    with pytest.raises(GovernorError):
        consolidate_resources(data)
