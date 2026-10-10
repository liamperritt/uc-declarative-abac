from __future__ import annotations

from uc_declarative_abac.configs import (
    ResourcesConfig,
    iter_policy_configs,
    iter_securable_configs,
)


def _full_config_with_all_types() -> dict:
    """Return a config with catalogs, schemas, tables, columns, volumes, and functions."""
    return {
        "catalogs": {
            "analytics": {
                "name": "analytics",
                "tags": {"domain": "analytics"},
                "policies": [
                    {
                        "name": "catalog_grant",
                        "type": "grant",
                        "privileges": ["use_catalog"],
                        "to": ["analysts"],
                        "has_tags": {"domain": "analytics"},
                    }
                ],
                "schemas": [
                    {
                        "name": "sales",
                        "tags": {"team": "sales"},
                        "policies": [
                            {
                                "name": "schema_grant",
                                "type": "grant",
                                "privileges": ["use_schema"],
                                "to": ["sales_team"],
                                "has_tags": {"team": "sales"},
                            }
                        ],
                        "tables": [
                            {
                                "name": "orders",
                                "tags": {"pii": "true"},
                                "policies": [
                                    {
                                        "name": "table_grant",
                                        "type": "grant",
                                        "privileges": ["select"],
                                        "to": ["readers"],
                                        "has_tags": {"pii": "true"},
                                    }
                                ],
                                "columns": [
                                    {"name": "email", "tags": {"pii_type": "email"}},
                                    {"name": "phone", "tags": {"pii_type": "phone"}},
                                    {"name": "amount"},
                                ],
                            },
                            {
                                "name": "customers",
                                "columns": [{"name": "customer_id"}],
                            },
                        ],
                        "volumes": [
                            {
                                "name": "raw_events",
                                "tags": {"classification": "raw"},
                            }
                        ],
                        "functions": [
                            {
                                "name": "mask_email",
                                "return": "STRING",
                            }
                        ],
                    }
                ],
            }
        }
    }


def _minimal_catalog() -> dict:
    """Return a minimal catalog with only a name."""
    return {
        "catalogs": {
            "bare": {
                "name": "bare",
            }
        }
    }


def test_traversal_yields_every_securable_in_catalog_hierarchy():
    """iter_securable_configs yields every securable: catalog, schemas, tables,
    columns, volumes, and functions."""
    config = ResourcesConfig.model_validate(_full_config_with_all_types())
    securables = list(iter_securable_configs(config))

    # Collect by type for easier assertions
    names = [s.name for s in securables]
    types = [type(s).__name__ for s in securables]

    # Should have catalog, schema, 2 tables, 3 columns, volume, function
    assert "analytics" in names
    assert "sales" in names
    assert "orders" in names
    assert "customers" in names
    assert "email" in names
    assert "phone" in names
    assert "amount" in names
    assert "raw_events" in names
    assert "mask_email" in names

    # Verify we have the right types
    assert "CatalogConfig" in types
    assert "SchemaConfig" in types
    assert "TableConfig" in types
    assert "ColumnConfig" in types
    assert "VolumeConfig" in types
    assert "FunctionConfig" in types


def test_traversal_yields_parents_before_children():
    """iter_securable_configs yields parents before children: catalog before
    schema before table before columns/volumes/functions."""
    config = ResourcesConfig.model_validate(_full_config_with_all_types())
    securables = list(iter_securable_configs(config))
    names = [s.name for s in securables]

    # Catalog should come first
    catalog_idx = names.index("analytics")

    # Schema should come after catalog
    schema_idx = names.index("sales")
    assert schema_idx > catalog_idx

    # Tables should come after schema
    orders_idx = names.index("orders")
    customers_idx = names.index("customers")
    assert orders_idx > schema_idx
    assert customers_idx > schema_idx

    # Columns should come after their table
    email_idx = names.index("email")
    assert email_idx > orders_idx

    # Volume should come after schema
    volume_idx = names.index("raw_events")
    assert volume_idx > schema_idx

    # Function should come after schema
    function_idx = names.index("mask_email")
    assert function_idx > schema_idx


def test_traversal_yields_policies_attached_at_every_level():
    """iter_policy_configs yields policies attached to catalogs, schemas, and
    tables."""
    config = ResourcesConfig.model_validate(_full_config_with_all_types())
    policies = list(iter_policy_configs(config))

    policy_names = [p.name for p in policies]

    # Should have catalog, schema, and table policies
    assert "catalog_grant" in policy_names
    assert "schema_grant" in policy_names
    assert "table_grant" in policy_names
    assert len(policies) == 3


def test_traversal_yields_nothing_extra_for_catalog_without_children():
    """A catalog with no schemas or policies yields just the catalog securable
    and no policies."""
    config = ResourcesConfig.model_validate(_minimal_catalog())
    securables = list(iter_securable_configs(config))
    policies = list(iter_policy_configs(config))

    assert len(securables) == 1
    assert securables[0].name == "bare"
    assert len(policies) == 0


def test_traversal_yields_policies_in_hierarchy_order():
    """iter_policy_configs visits policies in hierarchy order: catalog policies
    before schema policies before table policies."""
    config = ResourcesConfig.model_validate(_full_config_with_all_types())
    policies = list(iter_policy_configs(config))

    policy_names = [p.name for p in policies]

    # Catalog policy should come first
    catalog_idx = policy_names.index("catalog_grant")

    # Schema policy should come after catalog policy
    schema_idx = policy_names.index("schema_grant")
    assert schema_idx > catalog_idx

    # Table policy should come after schema policy
    table_idx = policy_names.index("table_grant")
    assert table_idx > schema_idx


def test_traversal_yields_securables_from_every_catalog():
    """iter_securable_configs handles multiple catalogs correctly."""
    config_dict = {
        "catalogs": {
            "cat1": {"name": "cat1", "schemas": [{"name": "s1"}]},
            "cat2": {"name": "cat2", "schemas": [{"name": "s2"}]},
        }
    }
    config = ResourcesConfig.model_validate(config_dict)
    securables = list(iter_securable_configs(config))

    names = [s.name for s in securables]
    assert "cat1" in names
    assert "cat2" in names
    assert "s1" in names
    assert "s2" in names
