from __future__ import annotations

from uc_abac_governor.configs.models import ResourcesConfig
from uc_abac_governor.policies.compiler import compile_desired_policies
from uc_abac_governor.policies.state import Policy
from uc_abac_governor.types import PolicyType, SecurableType


def _fgac_policy(**overrides) -> dict:
    """Return a minimal mask policy dict with overrides applied."""
    base = {
        "name": "p1",
        "type": "mask",
        "function": "cat.default.mask_fn",
        "to": ["analysts"],
        "except": ["admins"],
        "columns": [{"alias": "c_pii", "has_tags": {"pii": "email"}}],
    }
    base.update(overrides)
    return base


def _catalog_with_policy(policy: dict, level: str = "table") -> dict:
    """Build a resources dict with a single policy attached at catalog / schema / table level."""
    if level == "catalog":
        return {
            "catalogs": {
                "cat": {"name": "cat", "policies": [policy]},
            }
        }
    if level == "schema":
        return {
            "catalogs": {
                "cat": {
                    "name": "cat",
                    "schemas": [
                        {"name": "s", "policies": [policy]}
                    ],
                }
            }
        }
    return {
        "catalogs": {
            "cat": {
                "name": "cat",
                "schemas": [
                    {
                        "name": "s",
                        "tables": [
                            {"name": "t", "policies": [policy]}
                        ],
                    }
                ],
            }
        }
    }


# ---------------------------------------------------------------------------
# Securable attachment level
# ---------------------------------------------------------------------------


def test_policy_compiler_emits_catalog_level_mask_policy():
    """A MASK policy on a catalog emits a Policy with securable_type=CATALOG."""
    config = ResourcesConfig.model_validate(
        _catalog_with_policy(_fgac_policy(), level="catalog")
    )

    result = compile_desired_policies(config)
    (policy,) = result
    assert policy.securable_type == SecurableType.CATALOG
    assert policy.securable_full_name == "cat"
    assert policy.policy_type == PolicyType.MASK
    assert policy.function_name == "cat.default.mask_fn"


def test_policy_compiler_emits_schema_level_filter_policy():
    """A FILTER policy on a schema emits a Policy with securable_type=SCHEMA."""
    filter_policy = _fgac_policy(type="filter", function="cat.default.filter_fn")
    config = ResourcesConfig.model_validate(
        _catalog_with_policy(filter_policy, level="schema")
    )

    result = compile_desired_policies(config)
    (policy,) = result
    assert policy.securable_type == SecurableType.SCHEMA
    assert policy.securable_full_name == "cat.s"
    assert policy.policy_type == PolicyType.FILTER


def test_policy_compiler_emits_table_level_mask_policy():
    """A MASK policy on a table emits a Policy with securable_type=TABLE."""
    config = ResourcesConfig.model_validate(
        _catalog_with_policy(_fgac_policy(), level="table")
    )

    result = compile_desired_policies(config)
    (policy,) = result
    assert policy.securable_type == SecurableType.TABLE
    assert policy.securable_full_name == "cat.s.t"


# ---------------------------------------------------------------------------
# Principals
# ---------------------------------------------------------------------------


def test_policy_compiler_emits_principals_as_unresolved():
    """to / except principals are emitted as unresolved Principal objects (name set, type UNKNOWN).

    Canonical sorting by (identifier, name) happens post-resolution in the
    domain resolver, not in the compiler.
    """
    policy_dict = _fgac_policy(to=["z_group", "a_group"], **{"except": ["z_adm", "a_adm"]})
    config = ResourcesConfig.model_validate(
        _catalog_with_policy(policy_dict, level="table")
    )

    (policy,) = compile_desired_policies(config)
    to_names = [p.name for p in policy.to_principals]
    except_names = [p.name for p in policy.except_principals]
    assert set(to_names) == {"z_group", "a_group"}
    assert set(except_names) == {"z_adm", "a_adm"}
    for p in (*policy.to_principals, *policy.except_principals):
        assert p.principal_type.name == "UNKNOWN"
        assert p.identifier == ""


def test_policy_compiler_handles_missing_except_principals():
    """Omitted 'except' yields an empty except_principals tuple."""
    policy_dict = _fgac_policy()
    policy_dict["except"] = None
    config = ResourcesConfig.model_validate(
        _catalog_with_policy(policy_dict, level="table")
    )

    (policy,) = compile_desired_policies(config)
    assert policy.except_principals == ()


# ---------------------------------------------------------------------------
# has_tags → WHEN clause
# ---------------------------------------------------------------------------


def test_policy_compiler_renders_when_from_has_tags():
    """has_tags with a concrete value renders as has_tag_value(k, v) in WHEN."""
    policy_dict = _fgac_policy(has_tags={"domain": "sales"})
    config = ResourcesConfig.model_validate(
        _catalog_with_policy(policy_dict, level="table")
    )

    (policy,) = compile_desired_policies(config)
    assert policy.when_condition == "has_tag_value('domain', 'sales')"


def test_policy_compiler_renders_when_with_wildcard():
    """has_tags value '*' renders as has_tag(k) (presence only)."""
    policy_dict = _fgac_policy(has_tags={"domain": "*"})
    config = ResourcesConfig.model_validate(
        _catalog_with_policy(policy_dict, level="table")
    )

    (policy,) = compile_desired_policies(config)
    assert policy.when_condition == "has_tag('domain')"


def test_policy_compiler_renders_when_with_empty_string():
    """has_tags with an empty string value renders as has_tag_value(k, '') (literal match)."""
    policy_dict = _fgac_policy(has_tags={"domain": ""})
    config = ResourcesConfig.model_validate(
        _catalog_with_policy(policy_dict, level="table")
    )

    (policy,) = compile_desired_policies(config)
    assert policy.when_condition == "has_tag_value('domain', '')"


def test_policy_compiler_renders_when_with_null_value():
    """has_tags with a null value is coerced to empty string by the config layer → has_tag_value(k, '')."""
    policy_dict = _fgac_policy(has_tags={"domain": None})
    config = ResourcesConfig.model_validate(
        _catalog_with_policy(policy_dict, level="table")
    )

    (policy,) = compile_desired_policies(config)
    assert policy.when_condition == "has_tag_value('domain', '')"


def test_policy_compiler_joins_multiple_has_tags_with_and():
    """Multiple has_tags entries are AND-joined, sorted by key."""
    policy_dict = _fgac_policy(has_tags={"b_tag": "v2", "a_tag": "v1"})
    config = ResourcesConfig.model_validate(
        _catalog_with_policy(policy_dict, level="table")
    )

    (policy,) = compile_desired_policies(config)
    assert policy.when_condition == (
        "has_tag_value('a_tag', 'v1') AND has_tag_value('b_tag', 'v2')"
    )


def test_policy_compiler_when_is_none_when_has_tags_empty():
    """A policy with no has_tags produces when_condition=None."""
    policy_dict = _fgac_policy()  # no has_tags
    config = ResourcesConfig.model_validate(
        _catalog_with_policy(policy_dict, level="table")
    )

    (policy,) = compile_desired_policies(config)
    assert policy.when_condition is None


# ---------------------------------------------------------------------------
# columns → MATCH COLUMNS, on_column, using_columns
# ---------------------------------------------------------------------------


def test_policy_compiler_mask_first_column_is_on_column():
    """For MASK, the first column in the list is on_column; the rest are using."""
    policy_dict = _fgac_policy(
        columns=[
            {"alias": "c_ssn", "has_tags": {"pii": "ssn"}},
            {"alias": "c_region", "has_tags": {"geo": "*"}},
        ],
    )
    config = ResourcesConfig.model_validate(
        _catalog_with_policy(policy_dict, level="table")
    )

    (policy,) = compile_desired_policies(config)
    assert policy.on_column == "c_ssn"
    assert policy.using_columns == ("c_region",)
    assert policy.match_columns == (
        ("c_ssn", "has_tag_value('pii', 'ssn')"),
        ("c_region", "has_tag('geo')"),
    )


def test_policy_compiler_filter_has_no_on_column():
    """For FILTER, on_column is None and all columns become using args."""
    policy_dict = _fgac_policy(
        type="filter",
        function="cat.default.filter_fn",
        columns=[
            {"alias": "c_region", "has_tags": {"geo": "*"}},
            {"alias": "c_sensitivity", "has_tags": {"lvl": "high"}},
        ],
    )
    config = ResourcesConfig.model_validate(
        _catalog_with_policy(policy_dict, level="table")
    )

    (policy,) = compile_desired_policies(config)
    assert policy.on_column is None
    assert policy.using_columns == ("c_region", "c_sensitivity")
    assert policy.match_columns == (
        ("c_region", "has_tag('geo')"),
        ("c_sensitivity", "has_tag_value('lvl', 'high')"),
    )


def test_policy_compiler_filter_without_columns_has_empty_tuples():
    """A FILTER policy with no columns produces empty match_columns and using_columns."""
    policy_dict = _fgac_policy(type="filter", function="cat.default.filter_fn")
    policy_dict.pop("columns")
    config = ResourcesConfig.model_validate(
        _catalog_with_policy(policy_dict, level="table")
    )

    (policy,) = compile_desired_policies(config)
    assert policy.match_columns == ()
    assert policy.using_columns == ()
    assert policy.on_column is None


def test_policy_compiler_columns_match_uses_and_joined_when_multiple_has_tags():
    """A column with multiple has_tags AND-joins them in the MATCH COLUMNS condition."""
    policy_dict = _fgac_policy(
        columns=[
            {"alias": "c", "has_tags": {"b": "v2", "a": "v1"}},
        ],
    )
    config = ResourcesConfig.model_validate(
        _catalog_with_policy(policy_dict, level="table")
    )

    (policy,) = compile_desired_policies(config)
    assert policy.match_columns == (
        ("c", "has_tag_value('a', 'v1') AND has_tag_value('b', 'v2')"),
    )


# ---------------------------------------------------------------------------
# Grant policies are ignored
# ---------------------------------------------------------------------------


def test_policy_compiler_ignores_grant_policies():
    """Grant policies are not emitted; they're handled by the privileges domain."""
    grant = {
        "name": "grant_reads",
        "type": "grant",
        "privileges": ["select"],
        "to": ["analysts"],
        "has_tags": {"domain": "sales"},
    }
    config = ResourcesConfig.model_validate(
        _catalog_with_policy(grant, level="catalog")
    )

    assert compile_desired_policies(config) == set()


# ---------------------------------------------------------------------------
# Multiple policies across the tree
# ---------------------------------------------------------------------------


def test_policy_compiler_walks_full_tree():
    """Policies at catalog, schema, and table levels are all collected."""
    catalog_policy = _fgac_policy(name="cat_p", columns=[{"alias": "c", "has_tags": {"pii": "email"}}])
    schema_policy = _fgac_policy(name="sch_p", columns=[{"alias": "c", "has_tags": {"pii": "phone"}}])
    table_policy = _fgac_policy(name="tab_p", columns=[{"alias": "c", "has_tags": {"pii": "ssn"}}])
    config = ResourcesConfig.model_validate(
        {
            "catalogs": {
                "cat": {
                    "name": "cat",
                    "policies": [catalog_policy],
                    "schemas": [
                        {
                            "name": "s",
                            "policies": [schema_policy],
                            "tables": [
                                {"name": "t", "policies": [table_policy]}
                            ],
                        }
                    ],
                }
            }
        }
    )

    result = compile_desired_policies(config)
    names = {p.name for p in result}
    assert names == {"cat_p", "sch_p", "tab_p"}
    by_name = {p.name: p for p in result}
    assert by_name["cat_p"].securable_type == SecurableType.CATALOG
    assert by_name["sch_p"].securable_type == SecurableType.SCHEMA
    assert by_name["tab_p"].securable_type == SecurableType.TABLE


def test_policy_compiler_returns_empty_when_no_policies():
    """A config without any mask/filter policies returns an empty set."""
    config = ResourcesConfig.model_validate(
        {"catalogs": {"cat": {"name": "cat"}}}
    )
    assert compile_desired_policies(config) == set()


def test_policy_compiler_returns_frozen_hashable_policies():
    """Emitted Policy instances are usable as set members (hashable)."""
    config = ResourcesConfig.model_validate(
        _catalog_with_policy(_fgac_policy(), level="table")
    )
    result = compile_desired_policies(config)
    assert isinstance(result, set)
    assert len(result) == 1
    (policy,) = result
    assert isinstance(policy, Policy)
