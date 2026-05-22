from __future__ import annotations

from datetime import date

from uc_declarative_abac.configs.models import ResourcesConfig
from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.principals.state import Principal
from uc_declarative_abac.privileges.compiler import compile_desired_privileges
from uc_declarative_abac.privileges.state import SecurablePrivilege
from uc_declarative_abac.tags.state import SecurableTag
from uc_declarative_abac.types import (
    PrincipalType,
    PrivilegeType,
    SecurableType,
    UngovernedTagError,
)


# Permissive superset of every tag key used across the fixtures in this file.
# Tests that target the "ungoverned tag" validation pass a narrower set explicitly.
_GOVERNED_TAGS_IN_FIXTURES = {
    "sales", "a", "b", "env", "public", "writable", "pii",
    "team", "dept", "zone", "domain", "other", "level",
}


def _change_logger() -> ChangeLogger:
    return ChangeLogger()


def _compile(
    config: ResourcesConfig,
    desired_tags: set[SecurableTag],
    governed_tag_names: set[str] | None = None,
    change_logger: ChangeLogger | None = None,
    run_date: date | None = None,
) -> set[SecurablePrivilege]:
    names = _GOVERNED_TAGS_IN_FIXTURES if governed_tag_names is None else governed_tag_names
    logger = change_logger if change_logger is not None else _change_logger()
    return compile_desired_privileges(
        config, desired_tags, names, logger, run_date=run_date,
    )


# ---------------------------------------------------------------------------
# Resolution of policies into privileges
# ---------------------------------------------------------------------------


def test_privilege_compiler_computes_privileges_from_policy():
    """A grant policy with tags: {sales: None} and a table tagged {sales: ""}
    produces SecurablePrivilege entries for each principal x privilege."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select", "modify"],
                            "to": ["analysts", "engineers"],
                            "has_tags": {"sales": None},
                        }
                    ],
                    "schemas": [
                        {
                            "name": "default",
                            "tables": [{"name": "orders"}],
                        }
                    ],
                }
            }
        }
    )

    desired_tags = {
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_catalog.default.orders",
            tag_name="sales",
            tag_value="",
        ),
    }

    result = _compile(config, desired_tags)

    assert result == {
        SecurablePrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_catalog.default.orders",
            principal=Principal(principal_type=PrincipalType.UNKNOWN, name="analysts"),
            privilege_type=PrivilegeType.SELECT,
        ),
        SecurablePrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_catalog.default.orders",
            principal=Principal(principal_type=PrincipalType.UNKNOWN, name="analysts"),
            privilege_type=PrivilegeType.MODIFY,
        ),
        SecurablePrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_catalog.default.orders",
            principal=Principal(principal_type=PrincipalType.UNKNOWN, name="engineers"),
            privilege_type=PrivilegeType.SELECT,
        ),
        SecurablePrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_catalog.default.orders",
            principal=Principal(principal_type=PrincipalType.UNKNOWN, name="engineers"),
            privilege_type=PrivilegeType.MODIFY,
        ),
    }


def test_privilege_compiler_policy_uses_and_semantics_for_multiple_tags():
    """A policy with tags: {a: x, b: y} only matches objects that have BOTH tags."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["team"],
                            "has_tags": {"a": "x", "b": "y"},
                        }
                    ],
                }
            }
        }
    )

    # table_both has both tags — should match
    # table_one has only one tag — should NOT match
    desired_tags = {
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="cat.s.table_both",
            tag_name="a",
            tag_value="x",
        ),
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="cat.s.table_both",
            tag_name="b",
            tag_value="y",
        ),
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="cat.s.table_one",
            tag_name="a",
            tag_value="x",
        ),
    }

    result = _compile(config, desired_tags)

    assert result == {
        SecurablePrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="cat.s.table_both",
            principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
            privilege_type=PrivilegeType.SELECT,
        ),
    }


def test_privilege_compiler_policy_skips_objects_without_matching_tags():
    """Objects without matching tags produce no privileges."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["team"],
                            "has_tags": {"env": "prod"},
                        }
                    ],
                }
            }
        }
    )

    desired_tags = {
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="cat.s.orders",
            tag_name="env",
            tag_value="dev",
        ),
    }

    result = _compile(config, desired_tags)

    assert result == set()


def test_privilege_compiler_handles_multiple_policies_per_catalog():
    """Two policies on the same catalog each independently match and generate privileges."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["readers"],
                            "has_tags": {"public": None},
                        },
                        {
                            "type": "grant",
                            "privileges": ["modify"],
                            "to": ["writers"],
                            "has_tags": {"writable": None},
                        },
                    ],
                }
            }
        }
    )

    desired_tags = {
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="cat.s.t1",
            tag_name="public",
            tag_value="",
        ),
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="cat.s.t2",
            tag_name="writable",
            tag_value="",
        ),
    }

    result = _compile(config, desired_tags)

    assert result == {
        SecurablePrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="cat.s.t1",
            principal=Principal(principal_type=PrincipalType.UNKNOWN, name="readers"),
            privilege_type=PrivilegeType.SELECT,
        ),
        SecurablePrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="cat.s.t2",
            principal=Principal(principal_type=PrincipalType.UNKNOWN, name="writers"),
            privilege_type=PrivilegeType.MODIFY,
        ),
    }


def test_privilege_compiler_handles_catalog_with_no_policies():
    """A catalog with no policies produces an empty set."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "schemas": [
                        {
                            "name": "sales",
                            "tables": [{"name": "orders", "tags": {"pii": "true"}}],
                        }
                    ],
                }
            }
        }
    )

    desired_tags = {
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="cat.sales.orders",
            tag_name="pii",
            tag_value="true",
        ),
    }

    result = _compile(config, desired_tags)

    assert result == set()


def test_privilege_compiler_matches_schema_level_policy():
    """A grant policy on a schema matches against desired tags for that schema."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "schemas": [
                        {
                            "name": "sales",
                            "tags": {"team": "data"},
                            "policies": [
                                {
                                    "type": "grant",
                                    "privileges": ["select"],
                                    "to": ["data_engineers"],
                                    "has_tags": {"team": "data"},
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )

    desired_tags = {
        SecurableTag(
            securable_type=SecurableType.SCHEMA,
            securable_full_name="my_catalog.sales",
            tag_name="team",
            tag_value="data",
        ),
    }

    result = _compile(config, desired_tags)

    assert SecurablePrivilege(
        securable_type=SecurableType.SCHEMA,
        securable_full_name="my_catalog.sales",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="data_engineers"),
        privilege_type=PrivilegeType.SELECT,
    ) in result


def test_privilege_compiler_matches_table_level_policy():
    """A grant policy on a table matches against desired tags for that table."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "schemas": [
                        {
                            "name": "sales",
                            "tables": [
                                {
                                    "name": "orders",
                                    "tags": {"sales": None},
                                    "policies": [
                                        {
                                            "type": "grant",
                                            "privileges": ["modify"],
                                            "to": ["sales_team"],
                                            "has_tags": {"sales": None},
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

    desired_tags = {
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_catalog.sales.orders",
            tag_name="sales",
            tag_value="",
        ),
    }

    result = _compile(config, desired_tags)

    assert SecurablePrivilege(
        securable_type=SecurableType.TABLE,
        securable_full_name="my_catalog.sales.orders",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="sales_team"),
        privilege_type=PrivilegeType.MODIFY,
    ) in result


def test_privilege_compiler_collects_policies_from_all_levels():
    """Policies at catalog, schema, and table levels all produce privileges."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["use_catalog"],
                            "to": ["all_users"],
                            "has_tags": {"env": "prod"},
                        }
                    ],
                    "schemas": [
                        {
                            "name": "sales",
                            "policies": [
                                {
                                    "type": "grant",
                                    "privileges": ["select"],
                                    "to": ["data_engineers"],
                                    "has_tags": {"team": "data"},
                                }
                            ],
                            "tables": [
                                {
                                    "name": "orders",
                                    "policies": [
                                        {
                                            "type": "grant",
                                            "privileges": ["modify"],
                                            "to": ["sales_team"],
                                            "has_tags": {"sales": None},
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

    desired_tags = {
        SecurableTag(
            securable_type=SecurableType.CATALOG,
            securable_full_name="my_catalog",
            tag_name="env",
            tag_value="prod",
        ),
        SecurableTag(
            securable_type=SecurableType.SCHEMA,
            securable_full_name="my_catalog.sales",
            tag_name="team",
            tag_value="data",
        ),
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_catalog.sales.orders",
            tag_name="sales",
            tag_value="",
        ),
    }

    result = _compile(config, desired_tags)

    assert len(result) >= 3
    assert SecurablePrivilege(
        securable_type=SecurableType.CATALOG,
        securable_full_name="my_catalog",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="all_users"),
        privilege_type=PrivilegeType.USE_CATALOG,
    ) in result
    assert SecurablePrivilege(
        securable_type=SecurableType.SCHEMA,
        securable_full_name="my_catalog.sales",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="data_engineers"),
        privilege_type=PrivilegeType.SELECT,
    ) in result
    assert SecurablePrivilege(
        securable_type=SecurableType.TABLE,
        securable_full_name="my_catalog.sales.orders",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="sales_team"),
        privilege_type=PrivilegeType.MODIFY,
    ) in result



# ---------------------------------------------------------------------------
# Matches against desired_tags parameter, not raw config
# ---------------------------------------------------------------------------


def test_privilege_compiler_matches_against_desired_tags():
    """The compiler uses the desired_tags parameter (not raw config) to match;
    if desired_tags is empty, no privileges are generated even if config has tags."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "tags": {"env": "prod"},
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["team"],
                            "has_tags": {"env": "prod"},
                        }
                    ],
                    "schemas": [
                        {
                            "name": "s",
                            "tags": {"env": "prod"},
                            "tables": [
                                {"name": "t", "tags": {"env": "prod"}},
                            ],
                        }
                    ],
                }
            }
        }
    )

    # Even though the config defines tags, passing an empty desired_tags set
    # means no securables can match the policy.
    result = _compile(config, desired_tags=set())

    assert result == set()


# ---------------------------------------------------------------------------
# SecurablePrivilege output type
# ---------------------------------------------------------------------------


def test_privilege_compiler_emits_securable_privileges_with_unresolved_principals():
    """The compiler emits SecurablePrivilege instances whose principals are unresolved."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["my_team"],
                            "has_tags": {"dept": "eng"},
                        }
                    ],
                }
            }
        }
    )

    desired_tags = {
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="cat.s.t",
            tag_name="dept",
            tag_value="eng",
        ),
    }

    result = _compile(config, desired_tags)

    assert isinstance(result, set)
    for elem in result:
        assert isinstance(elem, SecurablePrivilege)
        assert elem.principal.principal_type == PrincipalType.UNKNOWN
        assert elem.principal.name == "my_team"
        assert elem.principal.identifier == ""


# ---------------------------------------------------------------------------
# Privilege-securable compatibility
# ---------------------------------------------------------------------------


def test_privilege_compiler_filters_incompatible_privilege_for_volume():
    """SELECT is incompatible with VOLUME and should be filtered out;
    READ_VOLUME is compatible and should remain."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select", "read_volume"],
                            "to": ["team"],
                            "has_tags": {"zone": "landing"},
                        }
                    ],
                }
            }
        }
    )

    desired_tags = {
        SecurableTag(
            securable_type=SecurableType.VOLUME,
            securable_full_name="cat.raw.events",
            tag_name="zone",
            tag_value="landing",
        ),
    }

    result = _compile(config, desired_tags)

    assert SecurablePrivilege(
        securable_type=SecurableType.VOLUME,
        securable_full_name="cat.raw.events",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.READ_VOLUME,
    ) in result

    # SELECT is not valid on a VOLUME — must be excluded
    select_privileges = {p for p in result if p.privilege_type == PrivilegeType.SELECT}
    assert select_privileges == set()


def test_privilege_compiler_allows_select_on_table():
    """SELECT is compatible with TABLE; READ_VOLUME is not and should be filtered out."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select", "read_volume"],
                            "to": ["team"],
                            "has_tags": {"zone": "landing"},
                        }
                    ],
                }
            }
        }
    )

    desired_tags = {
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="cat.raw.events",
            tag_name="zone",
            tag_value="landing",
        ),
    }

    result = _compile(config, desired_tags)

    assert SecurablePrivilege(
        securable_type=SecurableType.TABLE,
        securable_full_name="cat.raw.events",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.SELECT,
    ) in result

    # READ_VOLUME is not valid on a TABLE — must be excluded
    read_volume_privileges = {p for p in result if p.privilege_type == PrivilegeType.READ_VOLUME}
    assert read_volume_privileges == set()


def test_privilege_compiler_allows_all_privileges_on_any_securable():
    """ALL_PRIVILEGES is compatible with any securable type, including VOLUME."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["all_privileges"],
                            "to": ["team"],
                            "has_tags": {"zone": "landing"},
                        }
                    ],
                }
            }
        }
    )

    desired_tags = {
        SecurableTag(
            securable_type=SecurableType.VOLUME,
            securable_full_name="cat.raw.files",
            tag_name="zone",
            tag_value="landing",
        ),
    }

    result = _compile(config, desired_tags)

    assert SecurablePrivilege(
        securable_type=SecurableType.VOLUME,
        securable_full_name="cat.raw.files",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.ALL_PRIVILEGES,
    ) in result


# ---------------------------------------------------------------------------
# Expiry date
# ---------------------------------------------------------------------------


def test_privilege_compiler_excludes_expired_policy():
    """A grant policy whose expiry_date <= run_date produces no privileges."""
    from datetime import date

    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["team"],
                            "has_tags": {"env": "prod"},
                            "expiry_date": date(2025, 1, 1),
                        }
                    ],
                }
            }
        }
    )

    desired_tags = {
        SecurableTag(
            securable_type=SecurableType.CATALOG,
            securable_full_name="cat",
            tag_name="env",
            tag_value="prod",
        ),
    }

    result = _compile(config, desired_tags, run_date=date(2025, 1, 1))

    assert result == set()


def test_privilege_compiler_includes_active_policy():
    """A grant policy whose expiry_date > run_date produces privileges normally."""
    from datetime import date

    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["team"],
                            "has_tags": {"env": "prod"},
                            "expiry_date": date(2026, 12, 31),
                        }
                    ],
                }
            }
        }
    )

    desired_tags = {
        SecurableTag(
            securable_type=SecurableType.CATALOG,
            securable_full_name="cat",
            tag_name="env",
            tag_value="prod",
        ),
    }

    result = _compile(config, desired_tags, run_date=date(2025, 6, 1))

    assert len(result) > 0


def test_privilege_compiler_includes_policy_with_no_expiry():
    """A grant policy with no expiry_date is always active regardless of run_date."""
    from datetime import date

    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["team"],
                            "has_tags": {"env": "prod"},
                        }
                    ],
                }
            }
        }
    )

    desired_tags = {
        SecurableTag(
            securable_type=SecurableType.CATALOG,
            securable_full_name="cat",
            tag_name="env",
            tag_value="prod",
        ),
    }

    result = _compile(config, desired_tags, run_date=date(2099, 12, 31))

    assert len(result) > 0


# ---------------------------------------------------------------------------
# Tagless direct policies
# ---------------------------------------------------------------------------


def test_privilege_compiler_grants_directly_when_policy_has_no_tags():
    """A grant policy with empty tags grants directly to its attached securable (catalog)."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["use_catalog"],
                            "to": ["team"],
                            "has_tags": {},
                        }
                    ],
                }
            }
        }
    )

    result = _compile(config, set())

    assert SecurablePrivilege(
        securable_type=SecurableType.CATALOG,
        securable_full_name="my_cat",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.USE_CATALOG,
    ) in result


def test_privilege_compiler_grants_directly_to_schema_when_policy_has_no_tags():
    """A grant policy with empty tags on a schema grants directly to that schema."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_cat": {
                    "schemas": [
                        {
                            "name": "sales",
                            "policies": [
                                {
                                    "type": "grant",
                                    "privileges": ["use_schema"],
                                    "to": ["team"],
                                    "has_tags": {},
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = _compile(config, set())

    assert SecurablePrivilege(
        securable_type=SecurableType.SCHEMA,
        securable_full_name="my_cat.sales",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.USE_SCHEMA,
    ) in result


# ---------------------------------------------------------------------------
# Scoped policy matching
# ---------------------------------------------------------------------------


def test_privilege_compiler_scopes_policy_to_attached_securable():
    """A tag-matching policy on schema 'sales' only matches objects within
    that schema, not objects in sibling schema 'hr' even if they share the
    same tags."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_cat": {
                    "schemas": [
                        {
                            "name": "sales",
                            "policies": [
                                {
                                    "type": "grant",
                                    "privileges": ["select"],
                                    "to": ["team"],
                                    "has_tags": {"dept": "eng"},
                                }
                            ],
                            "tables": [{"name": "orders", "tags": {"dept": "eng"}}],
                        },
                        {
                            "name": "hr",
                            "tables": [{"name": "employees", "tags": {"dept": "eng"}}],
                        },
                    ],
                }
            }
        }
    )

    desired_tags = {
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_cat.sales.orders",
            tag_name="dept",
            tag_value="eng",
        ),
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_cat.hr.employees",
            tag_name="dept",
            tag_value="eng",
        ),
    }

    result = _compile(config, desired_tags)

    # Policy is on schema 'sales' — should match its child table only
    assert SecurablePrivilege(
        securable_type=SecurableType.TABLE,
        securable_full_name="my_cat.sales.orders",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.SELECT,
    ) in result

    # Should NOT match table in sibling schema 'hr'
    assert SecurablePrivilege(
        securable_type=SecurableType.TABLE,
        securable_full_name="my_cat.hr.employees",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.SELECT,
    ) not in result


def test_privilege_compiler_scopes_catalog_policy_to_all_children():
    """A tag-matching policy at catalog level matches objects in ALL schemas
    under that catalog."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["team"],
                            "has_tags": {"env": "prod"},
                        }
                    ],
                    "schemas": [
                        {
                            "name": "sales",
                            "tables": [{"name": "orders", "tags": {"env": "prod"}}],
                        },
                        {
                            "name": "hr",
                            "tables": [{"name": "employees", "tags": {"env": "prod"}}],
                        },
                    ],
                }
            }
        }
    )

    desired_tags = {
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_cat.sales.orders",
            tag_name="env",
            tag_value="prod",
        ),
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_cat.hr.employees",
            tag_name="env",
            tag_value="prod",
        ),
    }

    result = _compile(config, desired_tags)

    # Catalog-level policy should match tables in BOTH schemas
    assert SecurablePrivilege(
        securable_type=SecurableType.TABLE,
        securable_full_name="my_cat.sales.orders",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.SELECT,
    ) in result

    assert SecurablePrivilege(
        securable_type=SecurableType.TABLE,
        securable_full_name="my_cat.hr.employees",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.SELECT,
    ) in result


def test_privilege_compiler_and_semantics_with_scoped_policy():
    """A schema-level policy requiring TWO tags only matches tables that have
    BOTH tags; tables with only one of the two tags are excluded."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_cat": {
                    "schemas": [
                        {
                            "name": "sales",
                            "policies": [
                                {
                                    "type": "grant",
                                    "privileges": ["select"],
                                    "to": ["team"],
                                    "has_tags": {"dept": "eng", "level": "senior"},
                                }
                            ],
                            "tables": [
                                {"name": "orders", "tags": {"dept": "eng", "level": "senior"}},
                                {"name": "users", "tags": {"dept": "eng"}},
                            ],
                        }
                    ],
                }
            }
        }
    )

    desired_tags = {
        # orders has BOTH tags
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_cat.sales.orders",
            tag_name="dept",
            tag_value="eng",
        ),
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_cat.sales.orders",
            tag_name="level",
            tag_value="senior",
        ),
        # users has only one tag
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_cat.sales.users",
            tag_name="dept",
            tag_value="eng",
        ),
    }

    result = _compile(config, desired_tags)

    # orders should match — has both tags
    assert SecurablePrivilege(
        securable_type=SecurableType.TABLE,
        securable_full_name="my_cat.sales.orders",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.SELECT,
    ) in result

    # users should NOT match — missing 'level: senior' tag
    assert SecurablePrivilege(
        securable_type=SecurableType.TABLE,
        securable_full_name="my_cat.sales.users",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.SELECT,
    ) not in result


# ---------------------------------------------------------------------------
# Wildcard tag value ("*")
# ---------------------------------------------------------------------------


def test_privilege_compiler_wildcard_matches_any_tag_value():
    """has_tags: {domain: '*'} should match objects with any value for 'domain'."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["team"],
                            "has_tags": {"domain": "*"},
                        }
                    ],
                }
            }
        }
    )
    desired_tags = {
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_cat.s.orders",
            tag_name="domain",
            tag_value="sales",
        ),
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_cat.s.logs",
            tag_name="domain",
            tag_value="platform",
        ),
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_cat.s.untagged",
            tag_name="other",
            tag_value="x",
        ),
    }

    result = _compile(config, desired_tags)

    matched_names = {p.securable_full_name for p in result}
    # Both tagged objects match regardless of value
    assert "my_cat.s.orders" in matched_names
    assert "my_cat.s.logs" in matched_names
    # Object without the 'domain' tag does not match
    assert "my_cat.s.untagged" not in matched_names


def test_privilege_compiler_wildcard_combines_with_concrete_tags():
    """has_tags with one '*' and one concrete value uses AND semantics —
    both tags must be present, the concrete one must also have the matching value."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "my_cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["team"],
                            "has_tags": {"domain": "*", "level": "senior"},
                        }
                    ],
                }
            }
        }
    )
    desired_tags = {
        # Matches: has both tags, 'level' is senior
        SecurableTag(SecurableType.TABLE, "my_cat.s.orders", "domain", "sales"),
        SecurableTag(SecurableType.TABLE, "my_cat.s.orders", "level", "senior"),
        # Does not match: wrong level value
        SecurableTag(SecurableType.TABLE, "my_cat.s.logs", "domain", "platform"),
        SecurableTag(SecurableType.TABLE, "my_cat.s.logs", "level", "junior"),
        # Does not match: missing 'level' tag
        SecurableTag(SecurableType.TABLE, "my_cat.s.untagged", "domain", "sales"),
    }

    result = _compile(config, desired_tags)

    matched_names = {p.securable_full_name for p in result}
    assert matched_names == {"my_cat.s.orders"}


# ---------------------------------------------------------------------------
# USE_CATALOG / USE_SCHEMA cascading to parent securables
# ---------------------------------------------------------------------------


def test_privilege_compiler_cascades_use_catalog_up_to_parent_when_match_is_schema():
    """USE_CATALOG on a policy whose tag matches a schema is emitted on the parent catalog."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["use_catalog"],
                            "to": ["team"],
                            "has_tags": {"env": "prod"},
                        }
                    ],
                }
            }
        }
    )
    desired_tags = {
        SecurableTag(SecurableType.SCHEMA, "cat.sales", "env", "prod"),
    }

    result = _compile(config, desired_tags)

    assert SecurablePrivilege(
        securable_type=SecurableType.CATALOG,
        securable_full_name="cat",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.USE_CATALOG,
    ) in result
    # USE_CATALOG must not land on the schema itself
    assert not any(
        p.securable_type == SecurableType.SCHEMA and p.privilege_type == PrivilegeType.USE_CATALOG
        for p in result
    )


def test_privilege_compiler_cascades_use_catalog_up_to_parent_when_match_is_table():
    """USE_CATALOG on a policy whose tag matches a table is emitted on the grandparent catalog."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["use_catalog"],
                            "to": ["team"],
                            "has_tags": {"env": "prod"},
                        }
                    ],
                }
            }
        }
    )
    desired_tags = {
        SecurableTag(SecurableType.TABLE, "cat.sales.orders", "env", "prod"),
    }

    result = _compile(config, desired_tags)

    assert SecurablePrivilege(
        securable_type=SecurableType.CATALOG,
        securable_full_name="cat",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.USE_CATALOG,
    ) in result
    # USE_CATALOG must not land on the table
    assert not any(
        p.securable_type == SecurableType.TABLE and p.privilege_type == PrivilegeType.USE_CATALOG
        for p in result
    )


def test_privilege_compiler_cascades_use_catalog_up_to_parent_when_match_is_volume():
    """USE_CATALOG on a policy whose tag matches a volume is emitted on the grandparent catalog."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["use_catalog"],
                            "to": ["team"],
                            "has_tags": {"zone": "landing"},
                        }
                    ],
                }
            }
        }
    )
    desired_tags = {
        SecurableTag(SecurableType.VOLUME, "cat.raw.events", "zone", "landing"),
    }

    result = _compile(config, desired_tags)

    assert SecurablePrivilege(
        securable_type=SecurableType.CATALOG,
        securable_full_name="cat",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.USE_CATALOG,
    ) in result
    assert not any(
        p.securable_type == SecurableType.VOLUME and p.privilege_type == PrivilegeType.USE_CATALOG
        for p in result
    )


def test_privilege_compiler_cascades_use_schema_up_to_parent_when_match_is_table():
    """USE_SCHEMA on a policy whose tag matches a table is emitted on the parent schema."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["use_schema"],
                            "to": ["team"],
                            "has_tags": {"env": "prod"},
                        }
                    ],
                }
            }
        }
    )
    desired_tags = {
        SecurableTag(SecurableType.TABLE, "cat.sales.orders", "env", "prod"),
    }

    result = _compile(config, desired_tags)

    assert SecurablePrivilege(
        securable_type=SecurableType.SCHEMA,
        securable_full_name="cat.sales",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.USE_SCHEMA,
    ) in result
    assert not any(
        p.securable_type == SecurableType.TABLE and p.privilege_type == PrivilegeType.USE_SCHEMA
        for p in result
    )


def test_privilege_compiler_cascades_use_schema_up_to_parent_when_match_is_volume():
    """USE_SCHEMA on a policy whose tag matches a volume is emitted on the parent schema."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["use_schema"],
                            "to": ["team"],
                            "has_tags": {"zone": "landing"},
                        }
                    ],
                }
            }
        }
    )
    desired_tags = {
        SecurableTag(SecurableType.VOLUME, "cat.raw.events", "zone", "landing"),
    }

    result = _compile(config, desired_tags)

    assert SecurablePrivilege(
        securable_type=SecurableType.SCHEMA,
        securable_full_name="cat.raw",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.USE_SCHEMA,
    ) in result
    assert not any(
        p.securable_type == SecurableType.VOLUME and p.privilege_type == PrivilegeType.USE_SCHEMA
        for p in result
    )


def test_privilege_compiler_emits_use_catalog_on_catalog_when_match_is_catalog():
    """USE_CATALOG on a policy whose tag matches the catalog is emitted on that catalog (identity)."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["use_catalog"],
                            "to": ["team"],
                            "has_tags": {"env": "prod"},
                        }
                    ],
                }
            }
        }
    )
    desired_tags = {
        SecurableTag(SecurableType.CATALOG, "cat", "env", "prod"),
    }

    result = _compile(config, desired_tags)

    assert SecurablePrivilege(
        securable_type=SecurableType.CATALOG,
        securable_full_name="cat",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.USE_CATALOG,
    ) in result


def test_privilege_compiler_emits_use_schema_on_schema_when_match_is_schema():
    """USE_SCHEMA on a policy whose tag matches a schema is emitted on that schema (identity)."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["use_schema"],
                            "to": ["team"],
                            "has_tags": {"env": "prod"},
                        }
                    ],
                }
            }
        }
    )
    desired_tags = {
        SecurableTag(SecurableType.SCHEMA, "cat.sales", "env", "prod"),
    }

    result = _compile(config, desired_tags)

    assert SecurablePrivilege(
        securable_type=SecurableType.SCHEMA,
        securable_full_name="cat.sales",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.USE_SCHEMA,
    ) in result


def test_privilege_compiler_emits_use_schema_on_catalog_when_match_is_catalog():
    """USE_SCHEMA on a policy whose tag matches the catalog itself is emitted on the catalog
    (UC semantics: grant USE_SCHEMA across all schemas in the catalog). Preserves existing behavior."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["use_schema"],
                            "to": ["team"],
                            "has_tags": {"env": "prod"},
                        }
                    ],
                }
            }
        }
    )
    desired_tags = {
        SecurableTag(SecurableType.CATALOG, "cat", "env", "prod"),
    }

    result = _compile(config, desired_tags)

    assert SecurablePrivilege(
        securable_type=SecurableType.CATALOG,
        securable_full_name="cat",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.USE_SCHEMA,
    ) in result


def test_privilege_compiler_deduplicates_cascaded_use_catalog_when_many_children_match_same_policy():
    """Multiple tables in the same catalog all cascading USE_CATALOG produce one emission, not many."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["use_catalog"],
                            "to": ["team"],
                            "has_tags": {"env": "prod"},
                        }
                    ],
                }
            }
        }
    )
    desired_tags = {
        SecurableTag(SecurableType.TABLE, "cat.sales.orders", "env", "prod"),
        SecurableTag(SecurableType.TABLE, "cat.sales.customers", "env", "prod"),
        SecurableTag(SecurableType.TABLE, "cat.hr.employees", "env", "prod"),
        SecurableTag(SecurableType.VOLUME, "cat.raw.events", "env", "prod"),
    }

    result = _compile(config, desired_tags)

    use_catalog_entries = [
        p for p in result if p.privilege_type == PrivilegeType.USE_CATALOG
    ]
    assert len(use_catalog_entries) == 1
    assert use_catalog_entries[0].securable_type == SecurableType.CATALOG
    assert use_catalog_entries[0].securable_full_name == "cat"


def test_privilege_compiler_deduplicates_cascaded_use_schema_when_many_tables_match_same_policy_in_one_schema():
    """Multiple tagged tables in the same schema cascade to a single USE_SCHEMA emission on that schema."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["use_schema"],
                            "to": ["team"],
                            "has_tags": {"env": "prod"},
                        }
                    ],
                }
            }
        }
    )
    desired_tags = {
        SecurableTag(SecurableType.TABLE, "cat.sales.orders", "env", "prod"),
        SecurableTag(SecurableType.TABLE, "cat.sales.customers", "env", "prod"),
        SecurableTag(SecurableType.TABLE, "cat.sales.invoices", "env", "prod"),
    }

    result = _compile(config, desired_tags)

    use_schema_entries = [
        p for p in result if p.privilege_type == PrivilegeType.USE_SCHEMA
    ]
    assert len(use_schema_entries) == 1
    assert use_schema_entries[0].securable_type == SecurableType.SCHEMA
    assert use_schema_entries[0].securable_full_name == "cat.sales"


def test_privilege_compiler_emits_select_on_table_and_cascades_use_catalog_and_use_schema_when_policy_lists_all_three():
    """A single policy listing [select, use_catalog, use_schema] matching a table emits:
    SELECT on the table, USE_SCHEMA on the parent schema, USE_CATALOG on the grandparent catalog."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select", "use_catalog", "use_schema"],
                            "to": ["team"],
                            "has_tags": {"env": "prod"},
                        }
                    ],
                }
            }
        }
    )
    desired_tags = {
        SecurableTag(SecurableType.TABLE, "cat.sales.orders", "env", "prod"),
    }

    result = _compile(config, desired_tags)

    assert SecurablePrivilege(
        securable_type=SecurableType.TABLE,
        securable_full_name="cat.sales.orders",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.SELECT,
    ) in result
    assert SecurablePrivilege(
        securable_type=SecurableType.SCHEMA,
        securable_full_name="cat.sales",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.USE_SCHEMA,
    ) in result
    assert SecurablePrivilege(
        securable_type=SecurableType.CATALOG,
        securable_full_name="cat",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.USE_CATALOG,
    ) in result


def test_privilege_compiler_drops_use_catalog_when_policy_attached_at_table_level():
    """A grant policy attached to a table cannot reach up to the catalog — USE_CATALOG
    and USE_SCHEMA targets fall outside the policy's scope and are dropped; only
    table-level privileges survive."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "schemas": [
                        {
                            "name": "sales",
                            "tables": [
                                {
                                    "name": "orders",
                                    "policies": [
                                        {
                                            "type": "grant",
                                            "privileges": ["select", "use_catalog", "use_schema"],
                                            "to": ["team"],
                                            "has_tags": {},
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

    result = _compile(config, set())

    assert SecurablePrivilege(
        securable_type=SecurableType.TABLE,
        securable_full_name="cat.sales.orders",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.SELECT,
    ) in result
    # USE_CATALOG and USE_SCHEMA must not leak outside the table-level scope.
    assert not any(p.privilege_type == PrivilegeType.USE_CATALOG for p in result)
    assert not any(p.privilege_type == PrivilegeType.USE_SCHEMA for p in result)


def test_privilege_compiler_drops_use_catalog_when_policy_attached_at_schema_level_matches_child_table():
    """A schema-attached grant policy that matches a tagged child table still cannot
    reach the catalog — USE_CATALOG is dropped, while USE_SCHEMA (target = the schema
    itself, which is in scope) is emitted on the schema."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "schemas": [
                        {
                            "name": "sales",
                            "policies": [
                                {
                                    "type": "grant",
                                    "privileges": ["select", "use_catalog", "use_schema"],
                                    "to": ["team"],
                                    "has_tags": {"env": "prod"},
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )
    desired_tags = {
        SecurableTag(SecurableType.TABLE, "cat.sales.orders", "env", "prod"),
    }

    result = _compile(config, desired_tags)

    assert SecurablePrivilege(
        securable_type=SecurableType.TABLE,
        securable_full_name="cat.sales.orders",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.SELECT,
    ) in result
    assert SecurablePrivilege(
        securable_type=SecurableType.SCHEMA,
        securable_full_name="cat.sales",
        principal=Principal(principal_type=PrincipalType.UNKNOWN, name="team"),
        privilege_type=PrivilegeType.USE_SCHEMA,
    ) in result
    # Parent catalog is outside the policy's scope.
    assert not any(p.privilege_type == PrivilegeType.USE_CATALOG for p in result)


def test_privilege_compiler_cascades_use_catalog_for_each_principal_when_policy_has_multiple_principals():
    """A policy listing multiple principals cascades USE_CATALOG to the parent catalog for each."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["use_catalog"],
                            "to": ["analysts", "engineers", "auditors"],
                            "has_tags": {"env": "prod"},
                        }
                    ],
                }
            }
        }
    )
    desired_tags = {
        SecurableTag(SecurableType.TABLE, "cat.sales.orders", "env", "prod"),
    }

    result = _compile(config, desired_tags)

    for principal_name in ("analysts", "engineers", "auditors"):
        assert SecurablePrivilege(
            securable_type=SecurableType.CATALOG,
            securable_full_name="cat",
            principal=Principal(principal_type=PrincipalType.UNKNOWN, name=principal_name),
            privilege_type=PrivilegeType.USE_CATALOG,
        ) in result


# ---------------------------------------------------------------------------
# Columns don't support grants in UC — never emit privileges on COLUMN securables
# ---------------------------------------------------------------------------


def test_privilege_compiler_does_not_emit_privileges_on_columns():
    """Unity Catalog does not support column-level GRANT/REVOKE. A policy whose
    tag matches a COLUMN must never produce a SecurablePrivilege with
    securable_type=COLUMN — such an entry would cause the executor to emit
    invalid ``GRANT ... ON COLUMN ...`` SQL."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select", "modify"],
                            "to": ["analysts"],
                            "has_tags": {"pii": "email"},
                        }
                    ],
                }
            }
        }
    )
    # A column (not a table) carries the tag.
    desired_tags = {
        SecurableTag(
            securable_type=SecurableType.COLUMN,
            securable_full_name="cat.sales.orders.email",
            tag_name="pii",
            tag_value="email",
        ),
    }

    result = _compile(config, desired_tags)

    # No COLUMN-targeted privileges — UC would reject them at execute time.
    column_privileges = {p for p in result if p.securable_type == SecurableType.COLUMN}
    assert column_privileges == set(), (
        f"Expected no COLUMN-targeted privileges, got: {column_privileges}"
    )


# ---------------------------------------------------------------------------
# Governed-tag validation
# ---------------------------------------------------------------------------


def test_privilege_compiler_logs_error_when_grant_policy_tag_is_ungoverned():
    """A grant policy whose has_tags references an ungoverned tag key logs
    an error identifying the offending key."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["team"],
                            "has_tags": {"ungoverned_key": "*"},
                        }
                    ],
                }
            }
        }
    )
    change_logger = _change_logger()

    _compile(
        config,
        desired_tags=set(),
        governed_tag_names={"env"},
        change_logger=change_logger,
    )

    assert change_logger.has_errors
    exceptions = [e.exception for e in change_logger.errors]
    assert any(isinstance(e, UngovernedTagError) for e in exceptions)
    combined = " ".join(str(e) for e in exceptions) + " ".join(
        e.context for e in change_logger.errors
    )
    assert "ungoverned_key" in combined


def test_privilege_compiler_skips_grant_policy_with_ungoverned_tag():
    """A grant policy referencing an ungoverned tag emits no privileges, while
    other grant policies in the same config compile normally."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["bad_team"],
                            "has_tags": {"ungoverned_key": "*"},
                        },
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["good_team"],
                            "has_tags": {"env": "prod"},
                        },
                    ],
                }
            }
        }
    )
    desired_tags = {
        SecurableTag(SecurableType.TABLE, "cat.s.t", "env", "prod"),
        SecurableTag(SecurableType.TABLE, "cat.s.t", "ungoverned_key", "whatever"),
    }

    result = _compile(
        config,
        desired_tags,
        governed_tag_names={"env"},
    )

    principals_in_result = {p.principal.name for p in result}
    assert "good_team" in principals_in_result
    assert "bad_team" not in principals_in_result


def test_privilege_compiler_accepts_tag_in_union_of_desired_and_actual_governed_tags():
    """A grant policy whose tag key is declared as a governed tag (via the
    desired+actual union) compiles without errors."""
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["team"],
                            "has_tags": {"only_actual_tag": "*"},
                        }
                    ],
                }
            }
        }
    )
    desired_tags = {
        SecurableTag(SecurableType.TABLE, "cat.s.t", "only_actual_tag", "v"),
    }
    change_logger = _change_logger()

    result = _compile(
        config,
        desired_tags,
        governed_tag_names={"only_actual_tag"},
        change_logger=change_logger,
    )

    assert not change_logger.has_errors
    assert any(p.principal.name == "team" for p in result)
