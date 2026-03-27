from __future__ import annotations

from abc import abstractmethod
from datetime import date
from typing import Literal

from pydantic import BaseModel, computed_field, field_validator, model_validator

from uc_abac_governor.types import DuplicateResourceError, PrivilegeType


def _coerce_null_tag_values(tags: dict | None) -> dict | None:
    """Replace None tag values with empty strings."""
    if tags is None:
        return None
    return {k: (v if v is not None else "") for k, v in tags.items()}


def _check_duplicate_names(items: list, child_label: str, parent_label: str) -> None:
    """Raise DuplicateResourceError if any two dicts in items share the same 'name'."""
    seen: set[str] = set()
    for item in items:
        if isinstance(item, dict):
            name = item.get("name", "")
            if name in seen:
                raise DuplicateResourceError(
                    f"Duplicate {child_label} name '{name}' in {parent_label}"
                )
            seen.add(name)


class GrantPolicyConfig(BaseModel):
    catalog_name: str
    schema_name: str | None = None
    table_name: str | None = None
    name: str | None = None
    type: Literal["grant"]
    privileges: list[PrivilegeType]
    to: list[str]
    tags: dict[str, str] | None = None
    expiry_date: date | None = None

    @field_validator("tags", mode="before")
    @classmethod
    def _coerce_null_tags(cls, v: dict) -> dict:
        return _coerce_null_tag_values(v)

    @computed_field
    @property
    def parent_full_name(self) -> str:
        if self.table_name:
            return f"{self.catalog_name}.{self.schema_name}.{self.table_name}"
        if self.schema_name:
            return f"{self.catalog_name}.{self.schema_name}"
        return self.catalog_name


class SecurableConfig(BaseModel):
    """Base model for all UC securable configs. Not intended to be instantiated directly."""
    name: str
    tags: dict[str, str] | None = None

    @computed_field
    @property
    @abstractmethod
    def full_name(self) -> str:
        raise NotImplementedError(
            "Subclasses of SecurableConfig must implement the 'full_name' property."
        )

    @field_validator("tags", mode="before")
    @classmethod
    def _coerce_null_tags(cls, v: dict | None) -> dict | None:
        return _coerce_null_tag_values(v)


class ColumnConfig(SecurableConfig):
    catalog_name: str
    schema_name: str
    table_name: str

    @computed_field
    @property
    def full_name(self) -> str:
        return f"{self.catalog_name}.{self.schema_name}.{self.table_name}.{self.name}"


class VolumeConfig(SecurableConfig):
    catalog_name: str
    schema_name: str

    @computed_field
    @property
    def full_name(self) -> str:
        return f"{self.catalog_name}.{self.schema_name}.{self.name}"


class TableConfig(SecurableConfig):
    catalog_name: str
    schema_name: str
    policies: list[GrantPolicyConfig] | None = None
    columns: list[ColumnConfig] | None = None

    @model_validator(mode="before")
    @classmethod
    def _inject_parent_names(cls, data: dict) -> dict:
        catalog_name = data.get("catalog_name", "")
        schema_name = data.get("schema_name", "")
        table_name = data.get("name", "")
        _check_duplicate_names(
            data.get("columns", []) or [],
            "column",
            f"table '{table_name}'",
        )
        for policy_dict in data.get("policies", []) or []:
            if isinstance(policy_dict, dict):
                policy_dict.setdefault("catalog_name", catalog_name)
                policy_dict.setdefault("schema_name", schema_name)
                policy_dict.setdefault("table_name", table_name)
        for col_dict in data.get("columns", []) or []:
            if isinstance(col_dict, dict):
                col_dict.setdefault("catalog_name", catalog_name)
                col_dict.setdefault("schema_name", schema_name)
                col_dict.setdefault("table_name", table_name)
        return data

    @computed_field
    @property
    def full_name(self) -> str:
        return f"{self.catalog_name}.{self.schema_name}.{self.name}"


class SchemaConfig(SecurableConfig):
    catalog_name: str
    policies: list[GrantPolicyConfig] | None = None
    tables: list[TableConfig] | None = None
    volumes: list[VolumeConfig] | None = None

    @model_validator(mode="before")
    @classmethod
    def _inject_parent_names(cls, data: dict) -> dict:
        catalog_name = data.get("catalog_name", "")
        schema_name = data.get("name", "")
        _check_duplicate_names(
            data.get("tables", []) or [],
            "table",
            f"schema '{schema_name}'",
        )
        _check_duplicate_names(
            data.get("volumes", []) or [],
            "volume",
            f"schema '{schema_name}'",
        )
        for policy_dict in data.get("policies", []) or []:
            if isinstance(policy_dict, dict):
                policy_dict.setdefault("catalog_name", catalog_name)
                policy_dict.setdefault("schema_name", schema_name)
        for table_dict in data.get("tables", []) or []:
            if isinstance(table_dict, dict):
                table_dict.setdefault("catalog_name", catalog_name)
                table_dict.setdefault("schema_name", schema_name)
        for volume_dict in data.get("volumes", []) or []:
            if isinstance(volume_dict, dict):
                volume_dict.setdefault("catalog_name", catalog_name)
                volume_dict.setdefault("schema_name", schema_name)
        return data

    @computed_field
    @property
    def full_name(self) -> str:
        return f"{self.catalog_name}.{self.name}"


class CatalogConfig(SecurableConfig):
    policies: list[GrantPolicyConfig] | None = None
    schemas: list[SchemaConfig] | None = None

    @model_validator(mode="before")
    @classmethod
    def _inject_parent_names(cls, data: dict) -> dict:
        """Inject catalog_name into child schemas and policies."""
        if not isinstance(data, dict):
            return data
        catalog_name = data.get("name", "")
        _check_duplicate_names(
            data.get("schemas", []) or [],
            "schema",
            f"catalog '{catalog_name}'",
        )
        for schema_dict in data.get("schemas", []) or []:
            if isinstance(schema_dict, dict):
                schema_dict.setdefault("catalog_name", catalog_name)
        for policy_dict in data.get("policies", []) or []:
            if isinstance(policy_dict, dict):
                policy_dict.setdefault("catalog_name", catalog_name)
        return data

    @computed_field
    @property
    def full_name(self) -> str:
        return self.name


class ResourcesConfig(BaseModel):
    catalogs: dict[str, CatalogConfig]

    @model_validator(mode="before")
    @classmethod
    def _inject_catalog_names_from_keys(cls, data: dict) -> dict:
        """Set each catalog's name from its dict key when name is not provided."""
        catalogs = data.get("catalogs")
        if not isinstance(catalogs, dict):
            return data
        for key, catalog in catalogs.items():
            if isinstance(catalog, dict):
                catalog.setdefault("name", key)
        return data
