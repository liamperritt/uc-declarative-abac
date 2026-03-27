from __future__ import annotations

from uc_abac_governor.types import GovernorError


def consolidate_resources(resolved: dict) -> dict:
    """Restructure standalone resource declarations into the nested catalog hierarchy.

    Moves top-level schemas, tables, volumes, and policies into their parent
    catalog/schema/table based on catalog_name, schema_name, and table_name
    properties. Auto-creates parent catalogs and schemas if they don't exist.

    Returns the consolidated dict with only the 'catalogs' key remaining.
    """
    catalogs = resolved.setdefault("catalogs", {})

    for key, schema in resolved.pop("schemas", {}).items():
        cat_name = schema.get("catalog_name")
        if not cat_name:
            raise GovernorError(f"Standalone schema '{key}' is missing required 'catalog_name'")
        _ensure_catalog(catalogs, cat_name)
        catalogs[cat_name].setdefault("schemas", []).append(schema)

    for key, table in resolved.pop("tables", {}).items():
        cat_name = table.get("catalog_name")
        schema_name = table.get("schema_name")
        if not cat_name:
            raise GovernorError(f"Standalone table '{key}' is missing required 'catalog_name'")
        if not schema_name:
            raise GovernorError(f"Standalone table '{key}' is missing required 'schema_name'")
        _ensure_catalog(catalogs, cat_name)
        schema = _find_or_create_schema(catalogs[cat_name], schema_name)
        schema.setdefault("tables", []).append(table)

    for key, volume in resolved.pop("volumes", {}).items():
        cat_name = volume.get("catalog_name")
        schema_name = volume.get("schema_name")
        if not cat_name:
            raise GovernorError(f"Standalone volume '{key}' is missing required 'catalog_name'")
        if not schema_name:
            raise GovernorError(f"Standalone volume '{key}' is missing required 'schema_name'")
        _ensure_catalog(catalogs, cat_name)
        schema = _find_or_create_schema(catalogs[cat_name], schema_name)
        schema.setdefault("volumes", []).append(volume)

    for key, policy in resolved.pop("policies", {}).items():
        cat_name = policy.get("catalog_name")
        if not cat_name:
            raise GovernorError(f"Standalone policy '{key}' is missing required 'catalog_name'")
        schema_name = policy.get("schema_name")
        table_name = policy.get("table_name")
        _ensure_catalog(catalogs, cat_name)

        if table_name and schema_name:
            schema = _find_or_create_schema(catalogs[cat_name], schema_name)
            table = _find_or_create_table(schema, table_name)
            table.setdefault("policies", []).append(policy)
        elif schema_name:
            schema = _find_or_create_schema(catalogs[cat_name], schema_name)
            schema.setdefault("policies", []).append(policy)
        else:
            catalogs[cat_name].setdefault("policies", []).append(policy)

    return resolved


def _ensure_catalog(catalogs: dict, cat_name: str) -> None:
    """Ensure a catalog entry exists, creating a minimal one if needed."""
    if cat_name not in catalogs:
        catalogs[cat_name] = {"name": cat_name}


def _find_or_create_schema(catalog: dict, schema_name: str) -> dict:
    """Find a schema by name within a catalog, or create and append one."""
    schemas = catalog.setdefault("schemas", [])
    for schema in schemas:
        if isinstance(schema, dict) and schema.get("name") == schema_name:
            return schema
    new_schema = {"name": schema_name}
    schemas.append(new_schema)
    return new_schema


def _find_or_create_table(schema: dict, table_name: str) -> dict:
    """Find a table by name within a schema, or create and append one."""
    tables = schema.setdefault("tables", [])
    for table in tables:
        if isinstance(table, dict) and table.get("name") == table_name:
            return table
    new_table = {"name": table_name}
    tables.append(new_table)
    return new_table
