from __future__ import annotations

from collections.abc import Iterator

from uc_declarative_abac.configs.models import (
    CatalogConfig,
    PolicyConfig,
    ResourcesConfig,
    SchemaConfig,
    SecurableConfig,
    TableConfig,
)


def _iter_table_securables(table: TableConfig) -> Iterator[SecurableConfig]:
    yield table
    yield from table.columns or []


def _iter_schema_securables(schema: SchemaConfig) -> Iterator[SecurableConfig]:
    yield schema
    for table in schema.tables or []:
        yield from _iter_table_securables(table)
    yield from schema.volumes or []
    yield from schema.functions or []


def _iter_catalog_securables(catalog: CatalogConfig) -> Iterator[SecurableConfig]:
    yield catalog
    for schema in catalog.schemas or []:
        yield from _iter_schema_securables(schema)


def iter_securable_configs(config: ResourcesConfig) -> Iterator[SecurableConfig]:
    """Yield every securable config in ``config``, parents before children.

    Walks catalogs → schemas → tables (then each table's columns) → volumes →
    functions. The single shared walk of the catalog hierarchy for code that needs
    to visit every configured securable regardless of type (e.g. collecting every
    owner or tag key referenced in config).
    """
    for catalog in config.catalogs.values():
        yield from _iter_catalog_securables(catalog)


def iter_policy_configs(config: ResourcesConfig) -> Iterator[PolicyConfig]:
    """Yield every policy config attached anywhere in ``config``.

    Policies may be attached to catalogs, schemas, and tables; this yields each
    one once, in hierarchy order. Any new policy attachment point (e.g. top-level
    metastore ``resources.policies``) must be added here, or the referenced
    principal / tag-key collectors will silently miss its policies.
    """
    for securable in iter_securable_configs(config):
        yield from getattr(securable, "policies", None) or []
