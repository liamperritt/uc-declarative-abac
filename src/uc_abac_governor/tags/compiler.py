from __future__ import annotations

from uc_abac_governor.configs.models import ResourcesConfig, SecurableConfig
from uc_abac_governor.tags.state import SecurableTag
from uc_abac_governor.types import SecurableType


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


def compile_desired_tags(config: ResourcesConfig) -> set[SecurableTag]:
    """Walk the resolved config and emit SecurableTag entries for all tagged objects.

    Produces tags for catalogs, schemas, tables, volumes, and columns.
    """
    tags: set[SecurableTag] = set()

    for catalog in config.catalogs.values():
        tags |= _emit_tags(SecurableType.CATALOG, catalog.full_name, catalog)

        for schema in catalog.schemas or []:
            tags |= _emit_tags(SecurableType.SCHEMA, schema.full_name, schema)

            for table in schema.tables or []:
                tags |= _emit_tags(SecurableType.TABLE, table.full_name, table)
                for col in table.columns or []:
                    tags |= _emit_tags(SecurableType.COLUMN, col.full_name, col)

            for volume in schema.volumes or []:
                tags |= _emit_tags(SecurableType.VOLUME, volume.full_name, volume)

    return tags
