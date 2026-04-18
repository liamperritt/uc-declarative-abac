from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Union
from datetime import date
from typing import Literal

from pydantic import BaseModel, Field, computed_field, field_validator, model_validator

from uc_abac_governor.types import DuplicateResourceError, PolicyType, PrivilegeType


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


class PolicyColumnConfig(BaseModel):
    name: str = Field(alias="alias")
    has_tags: dict[str, str]


class BasePolicyConfig(BaseModel, ABC):
    """Base model for all policy configs. Not intended to be instantiated directly."""
    catalog_name: str
    schema_name: str | None = None
    table_name: str | None = None
    name: str | None = None
    type: PolicyType
    has_tags: dict[str, str] | None = None

    @field_validator("has_tags", mode="before")
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


class BaseFgacPolicyConfig(BasePolicyConfig, ABC):
    """Base model for Fine-Grained Access Control (FGAC) policy configs. Not intended to be instantiated directly."""
    name: str
    type: Union[Literal[PolicyType.MASK], Literal[PolicyType.FILTER]]
    function: str
    to: list[str]
    exceptions: list[str] | None = Field(default=None, alias="except")
    columns: list[PolicyColumnConfig] | None = None
    comment: str | None = None


class MaskPolicyConfig(BaseFgacPolicyConfig):
    type: Literal[PolicyType.MASK] = PolicyType.MASK

    @model_validator(mode="after")
    def _require_at_least_one_column(self) -> "MaskPolicyConfig":
        if not self.columns:
            raise ValueError("Mask policies must define at least one column")
        return self


class FilterPolicyConfig(BaseFgacPolicyConfig):
    type: Literal[PolicyType.FILTER] = PolicyType.FILTER


class GrantPolicyConfig(BasePolicyConfig):
    type: Literal[PolicyType.GRANT] = PolicyType.GRANT
    privileges: list[PrivilegeType]
    to: list[str]
    expiry_date: date | None = None


PolicyConfig = Union[MaskPolicyConfig, FilterPolicyConfig, GrantPolicyConfig]


class ParameterConfig(BaseModel):
    name: str
    type: str

    @field_validator("type", mode="before")
    @classmethod
    def _coerce_type_to_uppercase(cls, v):
        if isinstance(v, str):
            return v.upper()
        return v


class BaseSecurableConfig(BaseModel, ABC):
    """Base model for all UC securable configs. Not intended to be instantiated directly."""
    name: str
    owner: str | None = None
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


class FunctionConfig(BaseSecurableConfig):
    catalog_name: str
    schema_name: str
    parameters: list[ParameterConfig] | None = None
    definition: str = Field(alias="return")
    comment: str | None = None
    tags: None = None

    @computed_field
    @property
    def full_name(self) -> str:
        return f"{self.catalog_name}.{self.schema_name}.{self.name}"

    @model_validator(mode="before")
    @classmethod
    def _reject_tags(cls, data):
        if isinstance(data, dict) and "tags" in data:
            raise ValueError("Functions do not support tags")
        return data


class ColumnConfig(BaseSecurableConfig):
    catalog_name: str
    schema_name: str
    table_name: str

    @field_validator("owner", mode="before")
    @classmethod
    def _reject_explicit_owner(cls, v):
        raise ValueError(
            "Owner cannot be explicitly set on a column; "
            "it is always inherited from the table"
        )

    @computed_field
    @property
    def full_name(self) -> str:
        return f"{self.catalog_name}.{self.schema_name}.{self.table_name}.{self.name}"


class VolumeConfig(BaseSecurableConfig):
    catalog_name: str
    schema_name: str

    @computed_field
    @property
    def full_name(self) -> str:
        return f"{self.catalog_name}.{self.schema_name}.{self.name}"


class TableConfig(BaseSecurableConfig):
    catalog_name: str
    schema_name: str
    policies: list[PolicyConfig] | None = None
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


class SchemaConfig(BaseSecurableConfig):
    catalog_name: str
    policies: list[PolicyConfig] | None = None
    tables: list[TableConfig] | None = None
    volumes: list[VolumeConfig] | None = None
    functions: list[FunctionConfig] | None = None

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
        _check_duplicate_names(
            data.get("functions", []) or [],
            "function",
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
        for function_dict in data.get("functions", []) or []:
            if isinstance(function_dict, dict):
                function_dict.setdefault("catalog_name", catalog_name)
                function_dict.setdefault("schema_name", schema_name)
        return data

    @computed_field
    @property
    def full_name(self) -> str:
        return f"{self.catalog_name}.{self.name}"


class CatalogConfig(BaseSecurableConfig):
    policies: list[PolicyConfig] | None = None
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


SecurableConfig = Union[CatalogConfig, SchemaConfig, TableConfig, VolumeConfig, FunctionConfig, ColumnConfig]


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
