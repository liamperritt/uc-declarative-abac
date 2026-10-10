from __future__ import annotations

from uc_declarative_abac.configs import ResourcesConfig
from uc_declarative_abac.principals import collect_referenced_principal_names


def test_references_collects_securable_owners_across_the_catalog_hierarchy():
    """Owners are collected from catalog, schema, table, volume, and function securables."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "name": "cat",
                    "owner": "catalog_owner",
                    "schemas": [
                        {
                            "name": "s1",
                            "owner": "schema_owner",
                            "tables": [
                                {
                                    "name": "t1",
                                    "owner": "table_owner",
                                }
                            ],
                            "volumes": [
                                {
                                    "name": "v1",
                                    "owner": "volume_owner",
                                }
                            ],
                            "functions": [
                                {
                                    "name": "f1",
                                    "owner": "function_owner",
                                    "return": "STRING",
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = collect_referenced_principal_names(config)

    assert {
        "catalog_owner",
        "schema_owner",
        "table_owner",
        "volume_owner",
        "function_owner",
    } <= result


def test_references_collects_policy_to_and_except_principals():
    """Policy 'to' and 'except' (exceptions) principals are collected from grant and mask policies."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "name": "cat",
                    "schemas": [
                        {
                            "name": "s",
                            "policies": [
                                {
                                    "name": "grant_policy",
                                    "type": "grant",
                                    "privileges": ["select"],
                                    "to": ["grant_to_user"],
                                }
                            ],
                            "tables": [
                                {
                                    "name": "t",
                                    "policies": [
                                        {
                                            "name": "mask_policy",
                                            "type": "mask",
                                            "function": "cat.s.mask_fn",
                                            "to": ["mask_to_user"],
                                            "except": ["mask_except_user"],
                                            "columns": [
                                                {
                                                    "alias": "pii_col",
                                                    "has_tags": {"pii": "email"},
                                                }
                                            ],
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = collect_referenced_principal_names(config)

    assert {
        "grant_to_user",
        "mask_to_user",
        "mask_except_user",
    } <= result


def test_references_collects_domain_owners():
    """Domain business_owners and technical_owners are collected."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {"cat": {"name": "cat"}},
            "governed_tags": {"finance": {"description": "Finance domain"}},
            "domains": {
                "finance_domain": {
                    "governed_tag": "finance",
                    "business_owners": ["finance_biz_owner"],
                    "technical_owners": ["finance_tech_owner"],
                }
            },
        }
    )

    result = collect_referenced_principal_names(config)

    assert {"finance_biz_owner", "finance_tech_owner"} <= result


def test_references_collects_governed_tag_assigners():
    """Governed tag assigners are collected."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {"cat": {"name": "cat"}},
            "governed_tags": {
                "pii": {
                    "description": "Personally identifiable information",
                    "assigners": ["pii_assigner_1", "pii_assigner_2"],
                },
                "classification": {
                    "description": "Data classification",
                    "assigners": ["classification_assigner"],
                },
            },
        }
    )

    result = collect_referenced_principal_names(config)

    assert {
        "pii_assigner_1",
        "pii_assigner_2",
        "classification_assigner",
    } <= result


def test_references_collects_group_members_and_assumers():
    """Group members and assumers are collected."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {"cat": {"name": "cat"}},
            "groups": {
                "group1": {
                    "name": "group1",
                    "members": ["alice@example.com", "bob@example.com"],
                    "assumers": ["charlie@example.com"],
                },
                "group2": {
                    "name": "group2",
                    "members": ["dave@example.com"],
                },
            },
        }
    )

    result = collect_referenced_principal_names(config)

    assert {
        "alice@example.com",
        "bob@example.com",
        "charlie@example.com",
        "dave@example.com",
    } <= result


def test_references_deduplicates_names_referenced_in_several_places():
    """Principal names referenced in multiple places appear once in the result."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "name": "cat",
                    "owner": "shared_user",
                    "schemas": [
                        {
                            "name": "s",
                            "policies": [
                                {
                                    "name": "grant_policy",
                                    "type": "grant",
                                    "privileges": ["select"],
                                    "to": ["shared_user"],  # same as catalog owner
                                }
                            ],
                        }
                    ],
                }
            },
            "groups": {
                "group1": {
                    "name": "group1",
                    "members": ["shared_user"],  # same again
                }
            },
        }
    )

    result = collect_referenced_principal_names(config)

    # shared_user should appear in result exactly once (deduplicated in set)
    assert "shared_user" in result
    assert isinstance(result, set)
    assert len([name for name in result if name == "shared_user"]) == 1


def test_references_returns_empty_set_for_config_without_principal_references():
    """A minimal catalog with no owners/policies/domains/tags/groups returns an empty set."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "name": "cat",
                    "schemas": [
                        {
                            "name": "s",
                            "tables": [
                                {
                                    "name": "t",
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = collect_referenced_principal_names(config)

    assert result == set()
