from __future__ import annotations

from typing import Iterable

from uc_abac_governor.types import GovernorError


_DEFAULT_SCHEMA_NAME = "default"


def _iter_nested_policies_with_target_schema(
    catalogs: dict,
) -> Iterable[tuple[dict, str, dict]]:
    """Yield (policy_dict, catalog_name, target_schema_dict) for every mask/filter
    policy nested in the catalog hierarchy.

    - Table-level policy → target is the enclosing schema.
    - Schema-level policy → target is the enclosing schema.
    - Catalog-level policy → target is the catalog's 'default' schema
      (created if it doesn't exist).
    """
    for cat_name, catalog in catalogs.items():
        catalog_policies = catalog.get("policies") or []
        if catalog_policies:
            default_schema = _find_or_create_schema(catalog, _DEFAULT_SCHEMA_NAME)
            for policy in catalog_policies:
                if isinstance(policy, dict):
                    yield policy, cat_name, default_schema

        for schema in catalog.get("schemas") or []:
            for policy in schema.get("policies") or []:
                if isinstance(policy, dict):
                    yield policy, cat_name, schema
            for table in schema.get("tables") or []:
                for policy in table.get("policies") or []:
                    if isinstance(policy, dict):
                        yield policy, cat_name, schema


def _rewrite_policy_function_to_full_name(
    policy: dict, catalog_name: str, schema: dict,
) -> None:
    """If policy['function'] is an inline function dict, move the function
    definition into the target schema's functions list and rewrite
    policy['function'] to the fully qualified name string. No-op for strings
    or missing function fields.

    SchemaConfig._inject_parent_names stamps catalog_name / schema_name on each
    function dict during validation, so the consolidator doesn't need to.
    """
    function = policy.get("function")
    if not isinstance(function, dict):
        return
    fn_name = function.get("name")
    if not fn_name:
        raise GovernorError(
            f"Inline function definition in policy '{policy.get('name', '<unnamed>')}' is missing required 'name' field"
        )
    schema.setdefault("functions", []).append(function)
    policy["function"] = f"{catalog_name}.{schema.get('name')}.{fn_name}"


def _extract_inline_policy_functions(catalogs: dict) -> None:
    """Walk every policy nested under a catalog; for each policy whose
    ``function`` field is an inline dict, move the function into the target
    schema's functions list and rewrite the policy's function field to the
    fully qualified name.

    Collision detection (two inline functions with the same name in the same
    schema) is delegated to SchemaConfig._inject_parent_names via pydantic.
    """
    for policy, catalog_name, target_schema in _iter_nested_policies_with_target_schema(catalogs):
        _rewrite_policy_function_to_full_name(policy, catalog_name, target_schema)


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

    _extract_inline_policy_functions(catalogs)

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
