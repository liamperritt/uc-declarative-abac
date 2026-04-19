from __future__ import annotations

from uc_abac_governor.configs.models import ColumnConfig, FunctionConfig, ResourcesConfig, SecurableConfig, TableConfig
from uc_abac_governor.principals.state import Principal
from uc_abac_governor.securables.state import Column, Function, SecurableAttributes, Securable, Table
from uc_abac_governor.types import PrincipalType, SecurableType


def _emit_attributes(
    securable_type: SecurableType,
    obj: SecurableConfig,
) -> SecurableAttributes | None:
    """Return a SecurableAttributes if the object has a non-None owner, else None.

    The owner is emitted as an unresolved Principal (principal_type=UNKNOWN)
    carrying the display name from config. Resolution happens post-fetch.
    """
    if obj.owner is None:
        return None
    return SecurableAttributes(
        securable_type=securable_type,
        full_name=obj.full_name,
        owner=Principal(principal_type=PrincipalType.UNKNOWN, name=obj.owner),
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
        (param.name, param.type) for param in func.parameters
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
    """Build a Table with its declared columns in YAML declaration order."""
    return Table(
        securable_type=SecurableType.TABLE,
        full_name=table.full_name,
        columns=tuple(_compile_column(c) for c in (table.columns or [])),
    )


def compile_desired_securables(config: ResourcesConfig) -> set[Securable]:
    """Walk the config tree and emit a Securable for every declared securable.

    Catalogs, schemas, and volumes are emitted as base ``Securable`` (type +
    full_name only). Tables are emitted as ``Table`` subclass instances carrying
    their declared columns (each column as a ``Column`` with an optional UC
    datatype) — the executor reads these when building ``CREATE TABLE`` SQL.
    Functions are emitted as ``Function`` instances carrying their parameters,
    definition, and optional comment so the differ can detect replacement.
    """
    securables: set[Securable] = set()

    for catalog in config.catalogs.values():
        securables.add(Securable(
            securable_type=SecurableType.CATALOG,
            full_name=catalog.full_name,
        ))
        for schema in catalog.schemas or []:
            securables.add(Securable(
                securable_type=SecurableType.SCHEMA,
                full_name=schema.full_name,
            ))
            for table in schema.tables or []:
                securables.add(_compile_table(table))
            for volume in schema.volumes or []:
                securables.add(Securable(
                    securable_type=SecurableType.VOLUME,
                    full_name=volume.full_name,
                ))
            for func in schema.functions or []:
                securables.add(_compile_function(func))

    return securables
