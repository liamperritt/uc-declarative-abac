from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class SecurableConfig(BaseModel):
    """Base model for all UC securable configs. Not intended to be instantiated directly."""

    name: str
    tags: dict[str, str | None] | None = None


class ColumnConfig(SecurableConfig):
    pass


class VolumeConfig(SecurableConfig):
    pass


class TableConfig(SecurableConfig):
    columns: list[ColumnConfig] | None = None


class SchemaConfig(SecurableConfig):
    tables: list[TableConfig] | None = None
    volumes: list[VolumeConfig] | None = None


class GrantPolicyConfig(BaseModel):
    name: str | None = None
    type: Literal["grant"]
    privileges: list[str]
    to: list[str]
    tags: dict[str, str | None]


class CatalogConfig(SecurableConfig):
    policies: list[GrantPolicyConfig] | None = None
    schemas: list[SchemaConfig] | None = None


class ConfigFile(BaseModel):
    catalogs: dict[str, CatalogConfig]
