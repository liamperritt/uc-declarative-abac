from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Annotated, Union
from datetime import date, datetime
from typing import Literal

from databricks.sdk.service.catalog import ColumnTypeName
from pydantic import (
    AfterValidator,
    AliasChoices,
    BaseModel,
    Field,
    Strict,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    computed_field,
    field_validator,
    model_validator,
)

from uc_declarative_abac.types import (
    ABSTRACT_PRIVILEGE_MAP,
    SECURABLE_TYPE_PRIVILEGE_MAP,
    AbstractedPrivilegeType,
    PolicyType,
    PrivilegeType,
    SecurableType,
)
from uc_declarative_abac.utils import (
    DuplicateResourceError,
    validate_rfa_destinations,
)


_VALID_DATA_TYPE_PREFIXES = frozenset(ct.value for ct in ColumnTypeName)
_DATA_TYPE_PREFIX_PATTERN = re.compile(r"^([A-Z_][A-Z0-9_]*)")

# Default principals for a mask/filter (FGAC) policy when 'to' is not provided —
# the Databricks all-users system group.
_DEFAULT_FGAC_TO = ("account users",)

# Canonical securable-type string values, used to normalise the policy 'for' field.
_SECURABLE_TYPE_VALUES = frozenset(s.value for s in SecurableType)


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
        if isinstance(item, dict) and key in item:
            name = item[key]
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


def _validate_data_type_prefix(v: str | None) -> str | None:
    """Reject data_type values whose leading identifier is not a member of
    ``databricks.sdk.service.catalog.ColumnTypeName``. Matching is
    case-insensitive and anchored to a token boundary so e.g. ``DECIMAL(10,2)``
    and ``ARRAY<STRING>`` are accepted but ``STRINGISH`` is not."""
    if v is None or not isinstance(v, str):
        return v
    match = _DATA_TYPE_PREFIX_PATTERN.match(v.upper())
    if not match or match.group(1) not in _VALID_DATA_TYPE_PREFIXES:
        raise ValueError(
            f"data_type {v!r} must start with one of the valid Unity Catalog "
            f"column types: {', '.join(sorted(_VALID_DATA_TYPE_PREFIXES))}"
        )
    return v


def _qualify_function_name(function: str, catalog_name: str, schema_name: str | None) -> str:
    """Complete a partially-qualified UC function name from the policy's own
    catalog/schema. 2+ dots → already qualified (unchanged); 1 dot (``schema.fn``)
    → prepend catalog; 0 dots (bare ``fn``) → prepend catalog.schema. A bare name
    on a catalog-level policy (no schema) falls back to the ``default`` schema,
    mirroring where inline catalog-level functions are deployed."""
    dots = function.count(".")
    if dots >= 2:
        return function
    if dots == 1:
        return f"{catalog_name}.{function}"
    return f"{catalog_name}.{schema_name or 'default'}.{function}"


def _reject_double_underscore_name(name: str) -> str:
    """Reject securable names that start with ``__``. That prefix is reserved for
    internal, hidden, Databricks-managed system securables (which the engine also
    excludes from actual state), so it must never be declared in config."""
    if name.startswith("__"):
        raise ValueError(
            f"securable name '{name}' must not start with '__' — that prefix is "
            f"reserved for internal, Databricks-managed system securables"
        )
    return name


# A securable name that may not start with the reserved ``__`` prefix. Applied to
# catalogs/schemas/tables/volumes/functions via BaseSecurableConfig; columns opt
# out by redeclaring ``name`` as a plain ``str``.
SecurableName = Annotated[str, AfterValidator(_reject_double_underscore_name)]


# A constant column value, preserving its native YAML-parsed type.
PolicyColumnConstantValue = Union[
    StrictBool,
    StrictInt,
    StrictFloat,
    Annotated[datetime, Strict()],
    Annotated[date, Strict()],
    StrictStr,
]


class PolicyColumnAliasConfig(BaseModel):
    alias: str
    has_tags: dict[str, str] | None = None
    has_any_of_tags: dict[str, str] | None = None

    @field_validator("has_tags", "has_any_of_tags", mode="before")
    @classmethod
    def _coerce_null_tags(cls, v: dict) -> dict:
        return _coerce_null_tag_values(v)

    @model_validator(mode="after")
    def _require_a_tag_match(self) -> "PolicyColumnAliasConfig":
        if not self.has_tags and not self.has_any_of_tags:
            raise ValueError(
                "policy column must specify 'has_tags' or 'has_any_of_tags'"
            )
        return self


class PolicyColumnConstantConfig(BaseModel):
    constant: PolicyColumnConstantValue


PolicyColumnConfig = Union[PolicyColumnAliasConfig, PolicyColumnConstantConfig]


class BasePolicyConfig(BaseModel, ABC):
    """Base model for all policy configs. Not intended to be instantiated directly."""
    catalog_name: str
    schema_name: str | None = None
    table_name: str | None = None
    name: str
    type: PolicyType
    has_tags: dict[str, str] | None = None
    has_any_of_tags: dict[str, str] | None = None
    comment: str | None = None
    for_securable_type: SecurableType | None = Field(default=None, alias="for")

    @field_validator("has_tags", "has_any_of_tags", mode="before")
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

    @field_validator("for_securable_type", mode="before")
    @classmethod
    def _normalise_for_securable_type(cls, v):
        """Accept the 'for' field in any case and as a trailing-'s' plural
        (e.g. 'tables', 'Schema', 'CATALOGS'), resolving it to the canonical
        securable-type string. Non-strings (None / an already-coerced enum)
        pass through untouched so pydantic can coerce/validate them as usual.
        Inherited by every policy subclass, including the
        ``Literal[SecurableType.TABLE]`` override on FGAC policies."""
        if not isinstance(v, str):
            return v
        normalised = v.strip().upper()
        if normalised not in _SECURABLE_TYPE_VALUES and normalised.endswith("S"):
            normalised = normalised[:-1]
        return normalised

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
    type: Union[Literal[PolicyType.MASK], Literal[PolicyType.FILTER]]
    function: str
    to: list[str] = Field(default_factory=lambda: list(_DEFAULT_FGAC_TO))
    exceptions: list[str] | None = Field(default=None, alias="except")
    columns: list[PolicyColumnConfig] | None = None
    for_securable_type: Literal[SecurableType.TABLE] | None = Field(default=SecurableType.TABLE, alias="for")

    @field_validator("to", mode="before")
    @classmethod
    def _default_to_when_null(cls, v):
        """An explicit null 'to' falls back to the default (the default_factory
        only covers the omitted-key case)."""
        return list(_DEFAULT_FGAC_TO) if v is None else v

    @model_validator(mode="after")
    def _qualify_function(self) -> "BaseFgacPolicyConfig":
        """Complete a partially-qualified ``function`` from the policy's own
        catalog/schema so a policy definition can be reused across environment
        catalogs without a ref override."""
        self.function = _qualify_function_name(
            self.function, self.catalog_name, self.schema_name
        )
        return self

    @model_validator(mode="before")
    @classmethod
    def _normalise_singular_column(cls, data: dict) -> dict:
        """Accept singular ``column: {...}`` as shorthand for ``columns: [{...}]``."""
        if not isinstance(data, dict) or "column" not in data:
            return data
        if "columns" in data:
            raise ValueError(
                "cannot specify both 'column' and 'columns' on a policy"
            )
        column = data["column"]
        if not isinstance(column, dict):
            raise ValueError(
                "'column' must be a mapping — either an 'alias' with "
                "'has_tags'/'has_any_of_tags', or a 'constant'"
            )
        return {**{k: v for k, v in data.items() if k != "column"}, "columns": [column]}

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

    @model_validator(mode="after")
    def _require_first_column_is_alias(self) -> "MaskPolicyConfig":
        if self.columns and not isinstance(self.columns[0], PolicyColumnAliasConfig):
            raise ValueError(
                "The first column of a mask policy must be a column alias, "
                "not a constant (it is the column being masked)"
            )
        return self


class FilterPolicyConfig(BaseFgacPolicyConfig):
    type: Literal[PolicyType.FILTER] = PolicyType.FILTER


def _privilege_applies(
    entry: PrivilegeType | AbstractedPrivilegeType,
    allowed: set[PrivilegeType],
) -> bool:
    """Whether a privilege entry is applicable to a securable type, given that
    type's ``allowed`` privilege set. A concrete privilege applies iff it is in
    ``allowed``; an abstraction applies iff at least one of its expanded
    privileges is in ``allowed`` (mirroring the compiler, which silently filters
    the non-applicable expansions)."""
    if isinstance(entry, AbstractedPrivilegeType):
        return bool(ABSTRACT_PRIVILEGE_MAP[entry] & allowed)
    return entry in allowed


class GrantPolicyConfig(BasePolicyConfig):
    type: Literal[PolicyType.GRANT] = PolicyType.GRANT
    privileges: list[PrivilegeType | AbstractedPrivilegeType]
    to: list[str]
    expiry_date: date | None = None

    @model_validator(mode="after")
    def _validate_privileges_match_securable_type(self) -> "GrantPolicyConfig":
        """When 'for' is set, every privilege must be applicable to that
        securable type. With 'for' omitted, all privileges are allowed."""
        if self.for_securable_type is None:
            return self
        allowed = SECURABLE_TYPE_PRIVILEGE_MAP.get(self.for_securable_type)
        if allowed is None:
            raise ValueError(
                f"grant policies do not support securable type "
                f"'{self.for_securable_type.value}'"
            )
        offending = [
            getattr(p, "value", p)
            for p in self.privileges
            if not _privilege_applies(p, allowed)
        ]
        if offending:
            raise ValueError(
                f"privileges {offending} are not applicable to securable type "
                f"'{self.for_securable_type.value}'"
            )
        return self


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

    @field_validator("data_type", mode="after")
    @classmethod
    def _validate_data_type(cls, v: str | None) -> str | None:
        return _validate_data_type_prefix(v)


class BaseSecurableConfig(BaseModel, ABC):
    """Base model for all UC securable configs. Not intended to be instantiated directly."""
    name: SecurableName
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
    # Columns are exempt from the '__' securable-name restriction
    name: str
    catalog_name: str
    schema_name: str
    table_name: str
    data_type: str | None = Field(
        default=None,
        validation_alias=AliasChoices("data_type", "type"),
    )

    @field_validator("data_type", mode="after")
    @classmethod
    def _validate_data_type(cls, v: str | None) -> str | None:
        return _validate_data_type_prefix(v)

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
        _check_duplicate_names(
            data.get("policies", []) or [],
            "policy",
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
        _check_duplicate_names(
            data.get("policies", []) or [],
            "policy",
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
        _check_duplicate_names(
            data.get("policies", []) or [],
            "policy",
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


class GroupConfig(BaseModel):
    """Represents a Databricks-managed group with optional members.

    ``id`` is the account-level SCIM / internal group id. When set, the engine
    matches the group by ``id`` rather than by ``name``, which lets a group be
    renamed: change ``name`` while keeping ``id`` and the engine updates the
    group's display name instead of treating it as a new group. It is accepted as
    either a string or an integer (a numeric id in YAML) and stored as a string.
    """
    name: str
    id: str | None = None
    members: list[str] = Field(default_factory=list)

    @field_validator("id", mode="before")
    @classmethod
    def _coerce_id_to_str(cls, v: object) -> object:
        """Accept a numeric group id and store it as a string, so an ``id``
        written without quotes in YAML matches the string ids used everywhere
        else (config, SCIM, the principal cache)."""
        return str(v) if isinstance(v, int) else v


class ResourcesConfig(BaseModel):
    catalogs: dict[str, CatalogConfig]
    governed_tags: dict[str, GovernedTagConfig] | None = None
    groups: dict[str, GroupConfig] | None = None

    @model_validator(mode="before")
    @classmethod
    def _inject_names_and_reject_duplicates(cls, data: dict) -> dict:
        """Set each catalog's, governed tag's and group's name from its dict
        key when not provided, then reject any two entries that share the same
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
        groups = data.get("groups")
        if isinstance(groups, dict):
            for key, grp in groups.items():
                if isinstance(grp, dict):
                    grp.setdefault("name", key)
                    if isinstance(grp.get("id"), int):
                        grp["id"] = str(grp["id"])
            _check_duplicate_names(
                list(groups.values()), "group", "resources",
            )
            _check_duplicate_names(
                [g for g in groups.values() if isinstance(g, dict) and g.get("id")],
                "group", "resources", key="id",
            )
        return data
