from __future__ import annotations

import pytest
from pydantic import ValidationError

from uc_abac_governor.models import ConfigFile


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
                        "privileges": ["SELECT", "USAGE"],
                        "to": ["analysts"],
                        "tags": {"domain": "analytics"},
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
# ConfigFile
# ---------------------------------------------------------------------------


def test_config_file_validates_valid_config():
    """A well-formed resolved dict passes ConfigFile.model_validate() without errors."""
    config = ConfigFile.model_validate(_full_config())

    catalog = config.catalogs["analytics"]
    assert catalog.name == "analytics"
    assert catalog.tags == {"domain": "analytics", "env": "prod"}
    assert len(catalog.policies) == 1
    assert catalog.policies[0].privileges == ["SELECT", "USAGE"]
    assert len(catalog.schemas) == 1
    schema = catalog.schemas[0]
    assert schema.name == "sales"
    assert len(schema.tables) == 1
    assert len(schema.volumes) == 1
    assert len(schema.tables[0].columns) == 2


def test_config_file_rejects_missing_catalogs():
    """A dict with no 'catalogs' key raises a validation error."""
    with pytest.raises(ValidationError) as exc_info:
        ConfigFile.model_validate({})

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
                        "tags": {"domain": "analytics"},
                    }
                ],
            }
        }
    }
    with pytest.raises(ValidationError) as exc_info:
        ConfigFile.model_validate(data)

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
                        "privileges": ["SELECT"],
                        "tags": {"domain": "analytics"},
                    }
                ],
            }
        }
    }
    with pytest.raises(ValidationError) as exc_info:
        ConfigFile.model_validate(data)

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
    config = ConfigFile.model_validate(data)

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
    config = ConfigFile.model_validate(data)

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
    config = ConfigFile.model_validate(data)

    assert config.catalogs["ops_prod"].name == "operations_production"
