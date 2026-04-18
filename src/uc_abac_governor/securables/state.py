from __future__ import annotations

from dataclasses import dataclass, field

from uc_abac_governor.principals.state import Principal
from uc_abac_governor.types import SecurableType


@dataclass(frozen=True)
class SecurableAttributes:
    """Managed attributes for any securable type.

    Represents the governance-relevant attributes of a securable (not the full
    object state). Both desired (from config) and actual (from system tables)
    use this same representation.

    To add a new governed attribute (e.g. comment, rfa_destination):
    1. Add the field here with a default of None
    2. Update the compiler to emit it from config
    3. Update the state query to fetch it
    4. Add an _apply_<attr>_update() method to the executor
    """

    securable_type: SecurableType
    full_name: str
    owner: Principal | None = None


@dataclass(frozen=True)
class SecurableInfo:
    """Base state for securable creation/replacement.

    Subclass this for each securable type that needs create/replace support.
    The diff, executor, and uc_helper work with SecurableInfo polymorphically —
    they dispatch via structural pattern matching (match/case on the SecurableInfo
    subclass).

    To add creation support for a new securable type (e.g. tables):
    1. Create a TableInfo(SecurableInfo) subclass with table-specific fields
    2. Update the compiler to emit TableInfo instances
    3. Add a _build_create_table_sql() function to the executor
    4. Add a _build_replace_table_sql() if replacement is supported
    5. Update _build_create_sql() / _build_replace_sql() dispatch
    """

    securable_type: SecurableType
    full_name: str


@dataclass(frozen=True)
class FunctionInfo(SecurableInfo):
    """Function-specific state: parameters and body."""

    parameters: tuple[tuple[str, str], ...]
    definition: str


@dataclass(frozen=True)
class AttributeUpdate:
    """A single attribute change on a securable.

    Generic over attribute name so the differ doesn't need to know about
    each attribute type — it just compares fields and emits updates.
    """

    securable_type: SecurableType
    full_name: str
    attribute: str
    old_value: str | Principal
    new_value: str | Principal


@dataclass
class SecurableDiff:
    """All changes the executor needs to apply.

    Organised by operation type, not by securable type. The executor
    dispatches to type-specific logic via SecurableInfo polymorphism.
    """

    attributes_to_update: list[AttributeUpdate] = field(default_factory=list)
    securables_to_create: list[SecurableInfo] = field(default_factory=list)
    securables_to_replace: list[SecurableInfo] = field(default_factory=list)
