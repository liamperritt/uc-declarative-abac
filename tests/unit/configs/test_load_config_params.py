from __future__ import annotations

import pytest

from uc_declarative_abac.orchestrator import load_config
from uc_declarative_abac.utils import TemplateParameterError

# ---------------------------------------------------------------------------
# Template parameters through the full offline load_config pipeline
# (discovery -> resolve_refs -> consolidate_resources -> ResourcesConfig)
# ---------------------------------------------------------------------------


def _env_catalog_config(env: str) -> dict:
    """A catalog resource instantiating a parameterised schema definition for `env`."""
    return {
        "definitions": {
            "schemas": {
                "ingestion|salesforce": {
                    "$params": {"env": None, "medallion": "bronze"},
                    "name": "salesforce",
                    "tags": {
                        "environment": "{{ env }}",
                        "quality_tier": "{{ medallion }}",
                    },
                },
            },
        },
        "resources": {
            "catalogs": {
                f"ingestion_{env}": {
                    "name": f"ingestion_{env}",
                    "schemas": [
                        {
                            "$ref": "$defs/schemas/ingestion|salesforce",
                            "$params": {"env": env},
                        },
                    ],
                },
            },
        },
    }


def test_load_config_resolves_params_end_to_end(tmp_yaml_dir):
    """A $params config resolves to concrete objects through the whole pipeline."""
    root = tmp_yaml_dir({"ingestion_uat.yaml": _env_catalog_config("uat")})

    config = load_config(root)

    catalog = config.catalogs["ingestion_uat"]
    schema = catalog.schemas[0]
    assert schema.tags == {"environment": "uat", "quality_tier": "bronze"}


def test_load_config_raises_config_error_on_missing_param(tmp_yaml_dir):
    """A $ref that omits a required param fails the offline load with a config error."""
    config = _env_catalog_config("dev")
    # Drop the required `env` argument from the $ref.
    config["resources"]["catalogs"]["ingestion_dev"]["schemas"][0]["$params"] = {}
    root = tmp_yaml_dir({"ingestion_dev.yaml": config})

    with pytest.raises(TemplateParameterError, match="[Mm]issing"):
        load_config(root)
