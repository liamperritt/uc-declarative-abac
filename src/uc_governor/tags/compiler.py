from __future__ import annotations

from uc_governor.models import ConfigFile, SecurableConfig
from uc_governor.tags.state import SecurableTag
from uc_governor.types import SecurableType


def _emit_tags(
    securable_type: SecurableType,
    full_name: str,
    obj: SecurableConfig,
) -> set[SecurableTag]:
    """Return a SecurableTag for each tag on the object, or an empty set."""
    if not obj.tags:
        return set()
    return {
        SecurableTag(
            securable_type=securable_type,
            securable_full_name=full_name,
            tag_name=key,
            tag_value=value,
        )
        for key, value in obj.tags.items()
    }


def compile_desired_tags(config: ConfigFile) -> set[SecurableTag]:
    """Walk the resolved config and emit SecurableTag entries for all tagged objects.

    Produces tags for catalogs, schemas, tables, and volumes.
    Uses the dict key as the object name when name is omitted.
    """
    tags: set[SecurableTag] = set()

    for catalog in config.catalogs.values():
        cat_name = catalog.name
        tags |= _emit_tags(SecurableType.CATALOG, cat_name, catalog)

        for schema in catalog.schemas or []:
            schema_full = f"{cat_name}.{schema.name}"
            tags |= _emit_tags(SecurableType.SCHEMA, schema_full, schema)

            for table in schema.tables or []:
                table_full = f"{schema_full}.{table.name}"
                tags |= _emit_tags(SecurableType.TABLE, table_full, table)
                for col in table.columns or []:
                    tags |= _emit_tags(SecurableType.COLUMN, f"{table_full}.{col.name}", col)

            for volume in schema.volumes or []:
                tags |= _emit_tags(SecurableType.VOLUME, f"{schema_full}.{volume.name}", volume)

    return tags
