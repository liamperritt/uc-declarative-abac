from __future__ import annotations

from uc_abac_governor.models import ConfigFile
from uc_abac_governor.privileges.compiler import CompiledPrivilege, compile_desired_privileges
from uc_abac_governor.privileges.state import SecurablePrivilege
from uc_abac_governor.tags.state import SecurableTag
from uc_abac_governor.types import PrivilegeType, SecurableType


# ---------------------------------------------------------------------------
# Single policy with matching tags
# ---------------------------------------------------------------------------


def test_privilege_compiler_computes_privileges_from_policy():
    """A grant policy with tags: {sales: None} and a table tagged {sales: ""}
    produces CompiledPrivilege entries for each principal x privilege."""
    config = ConfigFile.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select", "modify"],
                            "to": ["analysts", "engineers"],
                            "tags": {"sales": None},
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

    result = compile_desired_privileges(config, desired_tags)

    assert result == {
        CompiledPrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_catalog.default.orders",
            principal="analysts",
            privilege_type=PrivilegeType.SELECT,
        ),
        CompiledPrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_catalog.default.orders",
            principal="analysts",
            privilege_type=PrivilegeType.MODIFY,
        ),
        CompiledPrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_catalog.default.orders",
            principal="engineers",
            privilege_type=PrivilegeType.SELECT,
        ),
        CompiledPrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_catalog.default.orders",
            principal="engineers",
            privilege_type=PrivilegeType.MODIFY,
        ),
    }


# ---------------------------------------------------------------------------
# AND semantics for multiple tags
# ---------------------------------------------------------------------------


def test_privilege_compiler_policy_uses_and_semantics_for_multiple_tags():
    """A policy with tags: {a: x, b: y} only matches objects that have BOTH tags."""
    config = ConfigFile.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["team"],
                            "tags": {"a": "x", "b": "y"},
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

    result = compile_desired_privileges(config, desired_tags)

    assert result == {
        CompiledPrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="cat.s.table_both",
            principal="team",
            privilege_type=PrivilegeType.SELECT,
        ),
    }


# ---------------------------------------------------------------------------
# No matching tags — no privileges
# ---------------------------------------------------------------------------


def test_privilege_compiler_policy_skips_objects_without_matching_tags():
    """Objects without matching tags produce no privileges."""
    config = ConfigFile.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["team"],
                            "tags": {"env": "prod"},
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

    result = compile_desired_privileges(config, desired_tags)

    assert result == set()


# ---------------------------------------------------------------------------
# Multiple policies per catalog
# ---------------------------------------------------------------------------


def test_privilege_compiler_handles_multiple_policies_per_catalog():
    """Two policies on the same catalog each independently match and generate privileges."""
    config = ConfigFile.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["readers"],
                            "tags": {"public": None},
                        },
                        {
                            "type": "grant",
                            "privileges": ["modify"],
                            "to": ["writers"],
                            "tags": {"writable": None},
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

    result = compile_desired_privileges(config, desired_tags)

    assert result == {
        CompiledPrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="cat.s.t1",
            principal="readers",
            privilege_type=PrivilegeType.SELECT,
        ),
        CompiledPrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="cat.s.t2",
            principal="writers",
            privilege_type=PrivilegeType.MODIFY,
        ),
    }


# ---------------------------------------------------------------------------
# Catalog with no policies
# ---------------------------------------------------------------------------


def test_privilege_compiler_handles_catalog_with_no_policies():
    """A catalog with no policies produces an empty set."""
    config = ConfigFile.model_validate(
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

    result = compile_desired_privileges(config, desired_tags)

    assert result == set()


# ---------------------------------------------------------------------------
# Matches against desired_tags parameter, not raw config
# ---------------------------------------------------------------------------


def test_privilege_compiler_matches_against_desired_tags():
    """The compiler uses the desired_tags parameter (not raw config) to match;
    if desired_tags is empty, no privileges are generated even if config has tags."""
    config = ConfigFile.model_validate(
        {
            "catalogs": {
                "cat": {
                    "tags": {"env": "prod"},
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["team"],
                            "tags": {"env": "prod"},
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
    result = compile_desired_privileges(config, desired_tags=set())

    assert result == set()


# ---------------------------------------------------------------------------
# Schema and table level policies
# ---------------------------------------------------------------------------


def test_privilege_compiler_matches_schema_level_policy():
    """A grant policy on a schema matches against desired tags for that schema."""
    config = ConfigFile.model_validate(
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
                                    "tags": {"team": "data"},
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

    result = compile_desired_privileges(config, desired_tags)

    assert CompiledPrivilege(
        securable_type=SecurableType.SCHEMA,
        securable_full_name="my_catalog.sales",
        principal="data_engineers",
        privilege_type=PrivilegeType.SELECT,
    ) in result


def test_privilege_compiler_matches_table_level_policy():
    """A grant policy on a table matches against desired tags for that table."""
    config = ConfigFile.model_validate(
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
                                            "tags": {"sales": None},
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

    result = compile_desired_privileges(config, desired_tags)

    assert CompiledPrivilege(
        securable_type=SecurableType.TABLE,
        securable_full_name="my_catalog.sales.orders",
        principal="sales_team",
        privilege_type=PrivilegeType.MODIFY,
    ) in result


def test_privilege_compiler_collects_policies_from_all_levels():
    """Policies at catalog, schema, and table levels all produce privileges."""
    config = ConfigFile.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["use_catalog"],
                            "to": ["all_users"],
                            "tags": {"env": "prod"},
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
                                    "tags": {"team": "data"},
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
                                            "tags": {"sales": None},
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

    result = compile_desired_privileges(config, desired_tags)

    assert len(result) >= 3
    assert CompiledPrivilege(
        securable_type=SecurableType.CATALOG,
        securable_full_name="my_catalog",
        principal="all_users",
        privilege_type=PrivilegeType.USE_CATALOG,
    ) in result
    assert CompiledPrivilege(
        securable_type=SecurableType.SCHEMA,
        securable_full_name="my_catalog.sales",
        principal="data_engineers",
        privilege_type=PrivilegeType.SELECT,
    ) in result
    assert CompiledPrivilege(
        securable_type=SecurableType.TABLE,
        securable_full_name="my_catalog.sales.orders",
        principal="sales_team",
        privilege_type=PrivilegeType.MODIFY,
    ) in result


# ---------------------------------------------------------------------------
# CompiledPrivilege output type
# ---------------------------------------------------------------------------


def test_privilege_compiler_emits_compiled_privilege_type():
    """The compiler emits CompiledPrivilege instances (not SecurablePrivilege)."""
    config = ConfigFile.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["my_team"],
                            "tags": {"dept": "eng"},
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

    result = compile_desired_privileges(config, desired_tags)

    assert isinstance(result, set)
    for elem in result:
        assert isinstance(elem, CompiledPrivilege)
        assert not isinstance(elem, SecurablePrivilege)


# ---------------------------------------------------------------------------
# Privilege-securable compatibility
# ---------------------------------------------------------------------------


def test_privilege_compiler_filters_incompatible_privilege_for_volume():
    """SELECT is incompatible with VOLUME and should be filtered out;
    READ_VOLUME is compatible and should remain."""
    config = ConfigFile.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select", "read_volume"],
                            "to": ["team"],
                            "tags": {"zone": "landing"},
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

    result = compile_desired_privileges(config, desired_tags)

    assert CompiledPrivilege(
        securable_type=SecurableType.VOLUME,
        securable_full_name="cat.raw.events",
        principal="team",
        privilege_type=PrivilegeType.READ_VOLUME,
    ) in result

    # SELECT is not valid on a VOLUME — must be excluded
    select_privileges = {p for p in result if p.privilege_type == PrivilegeType.SELECT}
    assert select_privileges == set()


def test_privilege_compiler_allows_select_on_table():
    """SELECT is compatible with TABLE; READ_VOLUME is not and should be filtered out."""
    config = ConfigFile.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select", "read_volume"],
                            "to": ["team"],
                            "tags": {"zone": "landing"},
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

    result = compile_desired_privileges(config, desired_tags)

    assert CompiledPrivilege(
        securable_type=SecurableType.TABLE,
        securable_full_name="cat.raw.events",
        principal="team",
        privilege_type=PrivilegeType.SELECT,
    ) in result

    # READ_VOLUME is not valid on a TABLE — must be excluded
    read_volume_privileges = {p for p in result if p.privilege_type == PrivilegeType.READ_VOLUME}
    assert read_volume_privileges == set()


def test_privilege_compiler_allows_all_privileges_on_any_securable():
    """ALL_PRIVILEGES is compatible with any securable type, including VOLUME."""
    config = ConfigFile.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["all_privileges"],
                            "to": ["team"],
                            "tags": {"zone": "landing"},
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

    result = compile_desired_privileges(config, desired_tags)

    assert CompiledPrivilege(
        securable_type=SecurableType.VOLUME,
        securable_full_name="cat.raw.files",
        principal="team",
        privilege_type=PrivilegeType.ALL_PRIVILEGES,
    ) in result


# ---------------------------------------------------------------------------
# Expiry date
# ---------------------------------------------------------------------------


def test_privilege_compiler_excludes_expired_policy():
    """A grant policy whose expiry_date <= run_date produces no privileges."""
    from datetime import date

    config = ConfigFile.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["team"],
                            "tags": {"env": "prod"},
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

    result = compile_desired_privileges(config, desired_tags, run_date=date(2025, 1, 1))

    assert result == set()


def test_privilege_compiler_includes_active_policy():
    """A grant policy whose expiry_date > run_date produces privileges normally."""
    from datetime import date

    config = ConfigFile.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["team"],
                            "tags": {"env": "prod"},
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

    result = compile_desired_privileges(config, desired_tags, run_date=date(2025, 6, 1))

    assert len(result) > 0


def test_privilege_compiler_includes_policy_with_no_expiry():
    """A grant policy with no expiry_date is always active regardless of run_date."""
    from datetime import date

    config = ConfigFile.model_validate(
        {
            "catalogs": {
                "cat": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["team"],
                            "tags": {"env": "prod"},
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

    result = compile_desired_privileges(config, desired_tags, run_date=date(2099, 12, 31))

    assert len(result) > 0
