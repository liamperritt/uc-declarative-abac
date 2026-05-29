from __future__ import annotations

from uc_declarative_abac.configs import (
    ColumnConfig,
    FunctionConfig,
    ResourcesConfig,
    SecurableConfig,
    TableConfig,
)
from uc_declarative_abac.principals import Principal
from uc_declarative_abac.securables.state import (
    Column,
    Function,
    Securable,
    SecurableAttributes,
    Table,
)
from uc_declarative_abac.types import (
    PrincipalType,
    SecurableType,
)


def _emit_attributes(
    securable_type: SecurableType,
    obj: SecurableConfig,
) -> SecurableAttributes | None:
    """Return a SecurableAttributes if any managed (updatable) attribute is set, else None.

    Managed attributes: ``owner``, ``comment``, and ``rfa_destinations``. Owner is
    emitted as an unresolved Principal (principal_type=UNKNOWN) carrying the
    display name from config; resolution happens post-fetch. ``comment`` is read
    directly from the config and only applies to the four taggable types
    (catalogs, schemas, tables, volumes); for functions only ``owner`` and
    ``rfa_destinations`` are emitted here (the function's comment lives on the
    ``Function`` securable itself since it's part of the replaceable definition).
    ``rfa_destinations`` is stored as a frozenset (order-insensitive); the
    Pydantic validator has already classified every entry, so no further
    validation is needed here.

    ``location`` is **not** a managed attribute — it's only consulted at CREATE
    time (see ``compile_desired_securables``), never diffed.
    """
    owner = (
        Principal(principal_type=PrincipalType.UNKNOWN, name=obj.owner)
        if obj.owner else None
    )
    if securable_type == SecurableType.FUNCTION:
        comment = None
    else:
        comment = getattr(obj, "comment", None)

    raw_rfa = getattr(obj, "rfa_destinations", None)
    rfa_destinations = frozenset(raw_rfa) if raw_rfa else None

    if owner is None and comment is None and rfa_destinations is None:
        return None
    return SecurableAttributes(
        securable_type=securable_type,
        full_name=obj.full_name,
        owner=owner,
        comment=comment,
        rfa_destinations=rfa_destinations,
    )


def compile_desired_attributes(config: ResourcesConfig) -> set[SecurableAttributes]:
    """Walk the config tree and emit SecurableAttributes for each securable with managed attributes."""
    attrs: set[SecurableAttributes] = set()

    for catalog in config.catalogs.values():
        if (attr := _emit_attributes(SecurableType.CATALOG, catalog)) is not None:
            attrs.add(attr)

        for schema in catalog.schemas or []:
            if (attr := _emit_attributes(SecurableType.SCHEMA, schema)) is not None:
                attrs.add(attr)

            for table in schema.tables or []:
                if (attr := _emit_attributes(SecurableType.TABLE, table)) is not None:
                    attrs.add(attr)

            for volume in schema.volumes or []:
                if (attr := _emit_attributes(SecurableType.VOLUME, volume)) is not None:
                    attrs.add(attr)

            for func in schema.functions or []:
                if (attr := _emit_attributes(SecurableType.FUNCTION, func)) is not None:
                    attrs.add(attr)

    return attrs


def _compile_function(func: FunctionConfig) -> Function:
    """Build a Function from a FunctionConfig."""
    parameters = tuple(
        (param.name, param.data_type) for param in func.parameters
    ) if func.parameters else ()
    return Function(
        securable_type=SecurableType.FUNCTION,
        full_name=func.full_name,
        parameters=parameters,
        definition=func.definition,
        comment=func.comment,
    )


def _compile_column(col: ColumnConfig) -> Column:
    """Build a Column from a ColumnConfig, preserving the optional UC datatype."""
    return Column(
        securable_type=SecurableType.COLUMN,
        full_name=col.full_name,
        data_type=col.data_type,
    )


def _compile_table(table: TableConfig) -> Table:
    """Build a Table with its declared columns in YAML declaration order.

    ``comment`` and ``location`` are plumbed onto the Table so the executor
    can embed them in the CREATE TABLE statement (LOCATION makes the table
    external).
    """
    return Table(
        securable_type=SecurableType.TABLE,
        full_name=table.full_name,
        columns=tuple(_compile_column(c) for c in (table.columns or [])),
        comment=table.comment,
        location=table.location,
    )


def compile_desired_securables(config: ResourcesConfig) -> set[Securable]:
    """Walk the config tree and emit a Securable for every declared securable.

    Catalogs, schemas, and volumes are emitted as base ``Securable`` instances
    carrying ``comment`` and ``location`` for the executor to embed in CREATE
    statements (``MANAGED LOCATION`` for catalogs/schemas, ``LOCATION`` for
    external tables, ``CREATE EXTERNAL VOLUME … LOCATION`` for external volumes).
    Tables are emitted as ``Table`` subclass instances carrying their declared
    columns plus ``comment`` / ``location``. Functions are emitted as
    ``Function`` instances carrying their parameters, definition, and optional
    comment so the differ can detect replacement.

    ``location`` is creation-only — the differ does not diff or alter it,
    matching the shape of ``Column.data_type``.
    """
    securables: set[Securable] = set()

    for catalog in config.catalogs.values():
        securables.add(Securable(
            securable_type=SecurableType.CATALOG,
            full_name=catalog.full_name,
            comment=catalog.comment,
            location=catalog.location,
        ))
        for schema in catalog.schemas or []:
            securables.add(Securable(
                securable_type=SecurableType.SCHEMA,
                full_name=schema.full_name,
                comment=schema.comment,
                location=schema.location,
            ))
            for table in schema.tables or []:
                securables.add(_compile_table(table))
            for volume in schema.volumes or []:
                securables.add(Securable(
                    securable_type=SecurableType.VOLUME,
                    full_name=volume.full_name,
                    comment=volume.comment,
                    location=volume.location,
                ))
            for func in schema.functions or []:
                securables.add(_compile_function(func))

    return securables
