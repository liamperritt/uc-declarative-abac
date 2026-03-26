from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, field_validator, model_validator

from uc_abac_governor.types import PrivilegeType


def _coerce_null_tag_values(tags: dict | None) -> dict | None:
    """Replace None tag values with empty strings."""
    if tags is None:
        return None
    return {k: (v if v is not None else "") for k, v in tags.items()}


class GrantPolicyConfig(BaseModel):
    name: str | None = None
    type: Literal["grant"]
    privileges: list[PrivilegeType]
    to: list[str]
    tags: dict[str, str]

    @field_validator("tags", mode="before")
    @classmethod
    def _coerce_null_tags(cls, v: dict) -> dict:
        return _coerce_null_tag_values(v) or {}


class SecurableConfig(BaseModel):
    """Base model for all UC securable configs. Not intended to be instantiated directly."""
    name: str
    tags: dict[str, str] | None = None

    @field_validator("tags", mode="before")
    @classmethod
    def _coerce_null_tags(cls, v: dict | None) -> dict | None:
        return _coerce_null_tag_values(v)


class ColumnConfig(SecurableConfig):
    pass


class VolumeConfig(SecurableConfig):
    pass


class TableConfig(SecurableConfig):
    policies: list[GrantPolicyConfig] | None = None
    columns: list[ColumnConfig] | None = None


class SchemaConfig(SecurableConfig):
    policies: list[GrantPolicyConfig] | None = None
    tables: list[TableConfig] | None = None
    volumes: list[VolumeConfig] | None = None


class CatalogConfig(SecurableConfig):
    policies: list[GrantPolicyConfig] | None = None
    schemas: list[SchemaConfig] | None = None


class ConfigFile(BaseModel):
    catalogs: dict[str, CatalogConfig]

    @model_validator(mode="before")
    @classmethod
    def _inject_catalog_names_from_keys(cls, data: dict) -> dict:
        """Set each catalog's name from its dict key when name is not provided."""
        catalogs = data.get("catalogs")
        if not isinstance(catalogs, dict):
            return data
        return {
            **data,
            "catalogs": {
                key: {**catalog, "name": catalog.get("name", key)}
                if isinstance(catalog, dict)
                else catalog
                for key, catalog in catalogs.items()
            },
        }
