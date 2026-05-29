from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Union
from datetime import date
from typing import Literal

from pydantic import AliasChoices, BaseModel, Field, computed_field, field_validator, model_validator

from uc_declarative_abac.types import PolicyType, PrivilegeType
from uc_declarative_abac.utils import DuplicateResourceError, validate_rfa_destinations


def _coerce_null_tag_values(tags: dict | None) -> dict | None:
    """Replace None tag values with empty strings."""
    if tags is None:
        return None
    return {k: (v if v is not None else "") for k, v in tags.items()}


def _check_duplicate_names(
    items: list, child_label: str, parent_label: str, key: str = "name",
) -> None:
    """Raise DuplicateResourceError if any two dicts in items share the same value
    for ``key``. Defaults to the 'name' key so existing call sites are unchanged."""
    seen: set[str] = set()
    for item in items:
        if isinstance(item, dict):
            name = item.get(key, "")
            if name in seen:
                raise DuplicateResourceError(
                    f"Duplicate {child_label} name '{name}' in {parent_label}"
                )
            seen.add(name)


def _validate_double_quote_not_in_comment(comment: str | None) -> str | None:
    """Reject double-quote characters in comments"""
    if isinstance(comment, str) and '"' in comment:
        raise ValueError(
            'comment must not contain a double-quote (") character'
        )
    return comment


class PolicyColumnConfig(BaseModel):
    alias: str
    has_tags: dict[str, str]


class BasePolicyConfig(BaseModel, ABC):
    """Base model for all policy configs. Not intended to be instantiated directly."""
    catalog_name: str
    schema_name: str | None = None
    table_name: str | None = None
    name: str | None = None
    type: PolicyType
    has_tags: dict[str, str] | None = None
    comment: str | None = None

    @field_validator("has_tags", mode="before")
    @classmethod
    def _coerce_null_tags(cls, v: dict) -> dict:
        return _coerce_null_tag_values(v)

    @field_validator("comment", mode="before")
    @classmethod
    def _reject_double_quote_in_comment(cls, v: str | None) -> str | None:
        """Reject double-quote characters in comments — they would break the
        executor's double-quoted SQL ``COMMENT "..."`` clause. Single quotes
        are still allowed (the executor escapes them separately)."""
        return _validate_double_quote_not_in_comment(v)

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

    @model_validator(mode="before")
    @classmethod
    def _reject_duplicate_column_aliases(cls, data: dict) -> dict:
        if isinstance(data, dict):
            _check_duplicate_names(
                data.get("columns", []) or [],
                "column alias",
                f"policy '{data.get('name', '')}'",
                key="alias",
            )
        return data


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
    data_type: str = Field(
        validation_alias=AliasChoices("data_type", "type"),
    )

    @field_validator("data_type", mode="before")
    @classmethod
    def _coerce_data_type_to_uppercase(cls, v):
        if isinstance(v, str):
            return v.upper()
        return v


class BaseSecurableConfig(BaseModel, ABC):
    """Base model for all UC securable configs. Not intended to be instantiated directly."""
    name: str
    owner: str | None = None
    comment: str | None = None
    tags: dict[str, str] | None = None
    rfa_destinations: list[str] | None = None

    @field_validator("comment", mode="before")
    @classmethod
    def _reject_double_quote_in_comment(cls, v: str | None) -> str | None:
        """Reject double-quote characters in comments — they would break the
        executor's double-quoted SQL ``COMMENT "..."`` clause. Single quotes
        are still allowed (the executor escapes them separately)."""
        return _validate_double_quote_not_in_comment(v)

    @field_validator("rfa_destinations", mode="before")
    @classmethod
    def _classify_rfa_destinations(cls, v: list[str] | None) -> list[str] | None:
        """Run every RFA destination through the shared classifier so unrecognised
        strings surface at config-load with one error listing every offender."""
        if v is None:
            return None
        return validate_rfa_destinations(v)

    @computed_field
    @property
    @abstractmethod
    def full_name(self) -> str:
        raise NotImplementedError(
            "Subclasses of SecurableConfig must implement the 'full_name' property."
        )


class BaseTaggableConfig(BaseSecurableConfig, ABC):
    """Base model for all UC securable taggable configs. Not intended to be instantiated directly."""
    tags: dict[str, str] | None = None

    @field_validator("tags", mode="before")
    @classmethod
    def _coerce_null_tags(cls, v: dict | None) -> dict | None:
        return _coerce_null_tag_values(v)


class FunctionConfig(BaseSecurableConfig):
    catalog_name: str
    schema_name: str
    parameters: list[ParameterConfig] | None = None
    definition: str = Field(alias="return")

    @computed_field
    @property
    def full_name(self) -> str:
        return f"{self.catalog_name}.{self.schema_name}.{self.name}"

    @model_validator(mode="before")
    @classmethod
    def _reject_tags(cls, data):
        if isinstance(data, dict) and "tags" in data:
            raise ValueError("Function tags are not currently supported")
        return data


class ColumnConfig(BaseTaggableConfig):
    catalog_name: str
    schema_name: str
    table_name: str
    data_type: str | None = Field(
        default=None,
        validation_alias=AliasChoices("data_type", "type"),
    )

    @field_validator("owner", mode="before")
    @classmethod
    def _reject_explicit_owner(cls, v):
        raise ValueError(
            "Owner cannot be explicitly set on a column; "
            "it is always inherited from the table"
        )

    @field_validator("comment", mode="before")
    @classmethod
    def _reject_comment(cls, v):
        raise ValueError(
            "Column-level comments are not currently supported"
        )

    @field_validator("rfa_destinations", mode="before")
    @classmethod
    def _reject_rfa_destinations(cls, v):
        raise ValueError(
            "rfa_destinations is not supported on columns; "
            "set it on the table, schema, or catalog instead"
        )

    @computed_field
    @property
    def full_name(self) -> str:
        return f"{self.catalog_name}.{self.schema_name}.{self.table_name}.{self.name}"


class TableConfig(BaseTaggableConfig):
    catalog_name: str
    schema_name: str
    location: str | None = None
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


class VolumeConfig(BaseTaggableConfig):
    catalog_name: str
    schema_name: str
    location: str | None = None

    @computed_field
    @property
    def full_name(self) -> str:
        return f"{self.catalog_name}.{self.schema_name}.{self.name}"


class SchemaConfig(BaseTaggableConfig):
    catalog_name: str
    location: str | None = None
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


class CatalogConfig(BaseTaggableConfig):
    location: str | None = None
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


TaggableConfig = Union[CatalogConfig, SchemaConfig, TableConfig, VolumeConfig, ColumnConfig]

SecurableConfig = Union[TaggableConfig, FunctionConfig]


class GovernedTagConfig(BaseModel):
    """Account-level governed tag declaration. Serialised under `resources.governed_tags`."""
    name: str
    description: str | None = Field(
        default=None,
        validation_alias=AliasChoices("description", "comment"),
    )
    allowed_values: list[str] = Field(default_factory=list)
    assigners: list[str] = Field(default_factory=list)


class ResourcesConfig(BaseModel):
    catalogs: dict[str, CatalogConfig]
    governed_tags: dict[str, GovernedTagConfig] | None = None

    @model_validator(mode="before")
    @classmethod
    def _inject_names_and_reject_duplicates(cls, data: dict) -> dict:
        """Set each catalog's and governed tag's name from its dict key when
        not provided, then reject any two entries that share the same
        ``name`` (dict keys are unique by construction, but two entries can
        still explicitly set the same ``name`` field — both would target the
        same UC object)."""
        catalogs = data.get("catalogs")
        if isinstance(catalogs, dict):
            for key, catalog in catalogs.items():
                if isinstance(catalog, dict):
                    catalog.setdefault("name", key)
            _check_duplicate_names(
                list(catalogs.values()), "catalog", "resources",
            )
        governed_tags = data.get("governed_tags")
        if isinstance(governed_tags, dict):
            for key, gt in governed_tags.items():
                if isinstance(gt, dict):
                    gt.setdefault("name", key)
            _check_duplicate_names(
                list(governed_tags.values()), "governed tag", "resources",
            )
        return data
