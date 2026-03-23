from __future__ import annotations

from uc_abac_governor.models import ConfigFile
from uc_abac_governor.privileges.compiler import compile_desired_privileges
from uc_abac_governor.privileges.state import SecurablePrivilege
from uc_abac_governor.tags.state import SecurableTag
from uc_abac_governor.types import SecurableType


# ---------------------------------------------------------------------------
# Single policy with matching tags
# ---------------------------------------------------------------------------


def test_privilege_compiler_computes_privileges_from_policy():
    """A grant policy with tags: {sales: None} and a table tagged {sales: None}
    produces SecurablePrivilege entries for each principal x privilege."""
    config = ConfigFile.model_validate(
        {
            "catalogs": {
                "my_catalog": {
                    "policies": [
                        {
                            "type": "grant",
                            "privileges": ["SELECT", "MODIFY"],
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
            tag_value=None,
        ),
    }

    result = compile_desired_privileges(config, desired_tags)

    assert result == {
        SecurablePrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_catalog.default.orders",
            principal="analysts",
            privilege_type="SELECT",
        ),
        SecurablePrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_catalog.default.orders",
            principal="analysts",
            privilege_type="MODIFY",
        ),
        SecurablePrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_catalog.default.orders",
            principal="engineers",
            privilege_type="SELECT",
        ),
        SecurablePrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="my_catalog.default.orders",
            principal="engineers",
            privilege_type="MODIFY",
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
                            "privileges": ["SELECT"],
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
        SecurablePrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="cat.s.table_both",
            principal="team",
            privilege_type="SELECT",
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
                            "privileges": ["SELECT"],
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
                            "privileges": ["SELECT"],
                            "to": ["readers"],
                            "tags": {"public": None},
                        },
                        {
                            "type": "grant",
                            "privileges": ["MODIFY"],
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
            tag_value=None,
        ),
        SecurableTag(
            securable_type=SecurableType.TABLE,
            securable_full_name="cat.s.t2",
            tag_name="writable",
            tag_value=None,
        ),
    }

    result = compile_desired_privileges(config, desired_tags)

    assert result == {
        SecurablePrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="cat.s.t1",
            principal="readers",
            privilege_type="SELECT",
        ),
        SecurablePrivilege(
            securable_type=SecurableType.TABLE,
            securable_full_name="cat.s.t2",
            principal="writers",
            privilege_type="MODIFY",
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
                            "privileges": ["SELECT"],
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
