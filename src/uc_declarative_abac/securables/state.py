from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from uc_declarative_abac.principals.state import Principal
from uc_declarative_abac.types import SecurableType


@dataclass(frozen=True)
class SecurableAttributes:
    """Managed attributes for any securable type.

    Represents the governance-relevant attributes of a securable (not the full
    object state). Both desired (from config) and actual (from system tables)
    use this same representation.

    To add a new governed attribute (e.g. rfa_destination):
    1. Add the field here with a default of None
    2. Update the compiler to emit it from config
    3. Update the state query to fetch it
    4. Add an _apply_<attr>_update() method to the executor
    """

    securable_type: SecurableType
    full_name: str
    owner: Principal | None = None
    comment: str | None = None


@dataclass(frozen=True)
class Securable:
    """Base state for securable creation/replacement.

    Subclass this for each securable type that needs create/replace support.
    The diff, executor, and uc_helper work with Securable polymorphically —
    they dispatch via structural pattern matching (match/case on the Securable
    subclass).

    ``comment`` and ``location`` ride along here so the executor can embed them
    in CREATE statements for the four taggable types (catalogs, schemas, tables,
    volumes). ``comment`` is also a governed (updatable) attribute on
    ``SecurableAttributes``; ``location`` is **only** consulted at CREATE time —
    the engine does not fetch, diff, or alter it (same shape as
    ``Column.data_type``).

    To add creation support for a new securable type (e.g. tables):
    1. Create a Table(Securable) subclass with table-specific fields
    2. Update the compiler to emit Table instances
    3. Add a _build_create_table_sql() function to the executor
    4. Add a _build_replace_table_sql() if replacement is supported
    5. Update _build_create_sql() / _build_replace_sql() dispatch
    """

    securable_type: SecurableType
    full_name: str
    comment: str | None = field(default=None, kw_only=True)
    location: str | None = field(default=None, kw_only=True)


@dataclass(frozen=True)
class Column(Securable):
    """Column state: name (in full_name) + optional UC datatype string.

    Columns ride along inside Table.columns rather than being standalone securables
    in the diff — they're used by the executor to build CREATE TABLE SQL. ``data_type``
    may be None for columns declared purely for tagging on existing tables; table
    creation requires every column to have a non-None data_type.
    """

    securable_type: Literal[SecurableType.COLUMN]
    data_type: str | None = None


@dataclass(frozen=True)
class Table(Securable):
    """Table state with its declared columns (ordered).

    Column order is significant because CREATE TABLE SQL emits columns in tuple
    order; authors' YAML ordering is preserved.

    ``table_type`` is populated only on the actual-state side (from
    ``information_schema.tables``) — values include ``"MANAGED"``, ``"EXTERNAL"``,
    ``"VIEW"``, ``"MATERIALIZED_VIEW"``, ``"STREAMING_TABLE"``. The differ uses
    ``"VIEW"`` to refuse comment updates on views.
    """

    securable_type: Literal[SecurableType.TABLE]
    columns: tuple[Column, ...] = ()
    table_type: str | None = field(default=None, kw_only=True)


@dataclass(frozen=True)
class Function(Securable):
    """Function-specific state: parameters and body.

    ``comment`` is inherited from ``Securable`` and is part of the replaceable
    function definition — a change to the comment triggers a CREATE OR REPLACE
    FUNCTION, not a separate attribute update. ``location`` is inherited but
    unused (functions have no storage location).
    """

    securable_type: Literal[SecurableType.FUNCTION]
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
    dispatches to type-specific logic via Securable polymorphism.
    """

    attributes_to_update: list[AttributeUpdate] = field(default_factory=list)
    securables_to_create: list[Securable] = field(default_factory=list)
    securables_to_replace: list[Securable] = field(default_factory=list)
