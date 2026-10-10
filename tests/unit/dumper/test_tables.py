"""Tests for dumper.tables row builders and specifications."""

from __future__ import annotations

from uc_declarative_abac import ActualState
from uc_declarative_abac.domains import Domain, DomainIcon
from uc_declarative_abac.dumper import (
    TABLE_SPECS,
    build_dump_context,
    split_securable_name,
)
from uc_declarative_abac.governed_tags import GovernedTag
from uc_declarative_abac.policies import Policy
from uc_declarative_abac.principals import Group, Principal
from uc_declarative_abac.privileges import SecurablePrivilege
from uc_declarative_abac.securables import Column, Function, SecurableAttributes, Table
from uc_declarative_abac.tags import SecurableTag
from uc_declarative_abac.types import (
    PolicyType,
    PrincipalType,
    PrivilegeType,
    SecurableType,
)

# --- Helpers ---


def _spec(name: str):
    """Return the TableSpec from TABLE_SPECS by name."""
    for spec in TABLE_SPECS:
        if spec.name == name:
            return spec
    raise ValueError(f"No spec found with name {name}")


def _state(**overrides: object) -> ActualState:
    """Build an ActualState with all-empty frozensets / {} principals by default."""
    defaults = {
        "groups": frozenset(),
        "all_account_groups": frozenset(),
        "governed_tags": frozenset(),
        "domains": frozenset(),
        "securables": frozenset(),
        "attributes": frozenset(),
        "tags": frozenset(),
        "policies": frozenset(),
        "privileges": frozenset(),
        "principals": {},
    }
    defaults.update(overrides)
    return ActualState(**defaults)  # type: ignore


def _rows(
    name: str, state: ActualState, referenced_tag_keys: frozenset[str] = frozenset()
):
    """Build rows for a table spec: list of dicts keyed by column name."""
    spec = _spec(name)
    context = build_dump_context(state, referenced_tag_keys)
    return spec.rows(state, context)


# --- Spec-level tests ---


def test_dumper_tables_specs_have_comments():
    """Every TableSpec has a non-empty table comment."""
    for spec in TABLE_SPECS:
        assert spec.comment, f"TableSpec {spec.name} has no comment"
        assert isinstance(spec.comment, str)
        assert len(spec.comment) > 0


def test_dumper_tables_columns_have_comments():
    """Every column in every TableSpec has a non-empty comment."""
    for spec in TABLE_SPECS:
        for col in spec.columns:
            assert col.comment, f"Column {col.name} in {spec.name} has no comment"
            assert isinstance(col.comment, str)
            assert len(col.comment) > 0


def test_dumper_tables_spec_names_and_order():
    """Table names are exactly the expected set in the expected order."""
    expected_names = [
        "securables",
        "securable_tags",
        "securable_privileges",
        "abac_policies",
        "governed_tags",
        "domains",
        "principals",
        "group_members",
        "group_assumers",
    ]
    actual_names = [spec.name for spec in TABLE_SPECS]
    assert actual_names == expected_names


def test_dumper_tables_row_column_alignment():
    """Every row dict produced has exactly the spec's column names as keys."""
    # For each table with a populated state, verify the row structure
    # Use one test row for each table type
    table = Table(SecurableType.TABLE, "c.s.t")
    user = Principal(PrincipalType.USER, identifier="alice", name="alice")
    tag = SecurableTag(SecurableType.TABLE, "c.s.t", "env", "prod")
    priv = SecurablePrivilege(
        SecurableType.TABLE,
        "c.s.t",
        user,
        PrivilegeType.SELECT,
    )
    policy = Policy(
        SecurableType.TABLE,
        "c.s.t",
        "mask_pii",
        PolicyType.MASK,
        "c.s.mask_func",
        (),
        (),
        None,
        (),
        "email",
        (),
    )
    governed_tag = GovernedTag("sensitivity")
    domain = Domain("data_domain")
    group = Group("data-team", members=frozenset([user]))

    test_states = [
        ("securables", _state(securables=frozenset([table]))),
        ("securable_tags", _state(tags=frozenset([tag]))),
        ("securable_privileges", _state(privileges=frozenset([priv]))),
        ("abac_policies", _state(policies=frozenset([policy]))),
        (
            "governed_tags",
            _state(governed_tags=frozenset([governed_tag])),
            frozenset(["sensitivity"]),
        ),
        ("domains", _state(domains=frozenset([domain]))),
        ("principals", _state(principals={"alice": user})),
        (
            "group_members",
            _state(groups=frozenset([group]), principals={"alice": user}),
        ),
        (
            "group_assumers",
            _state(
                groups=frozenset([Group("g", id="g1", assumers=frozenset([user]))]),
                principals={"alice": user},
            ),
        ),
    ]

    for spec_name_and_state in test_states:
        if len(spec_name_and_state) == 2:
            spec_name, state = spec_name_and_state
            ref_keys = frozenset()
        else:
            spec_name, state, ref_keys = spec_name_and_state

        spec = _spec(spec_name)
        rows = _rows(spec_name, state, ref_keys)
        for row in rows:
            expected_keys = {col.name for col in spec.columns}
            actual_keys = set(row.keys())
            assert actual_keys == expected_keys, (
                f"{spec_name}: row keys {actual_keys} != expected {expected_keys}"
            )


# --- split_securable_name tests ---


def test_dumper_tables_split_catalog():
    """split_securable_name for CATALOG 'c' -> ('c', None, None, 'c')."""
    result = split_securable_name(SecurableType.CATALOG, "c")
    assert result == ("c", None, None, "c")


def test_dumper_tables_split_schema():
    """split_securable_name for SCHEMA 'c.s' -> ('c', 's', None, 's')."""
    result = split_securable_name(SecurableType.SCHEMA, "c.s")
    assert result == ("c", "s", None, "s")


def test_dumper_tables_split_table():
    """split_securable_name for TABLE 'c.s.t' -> ('c', 's', 't', 't')."""
    result = split_securable_name(SecurableType.TABLE, "c.s.t")
    assert result == ("c", "s", "t", "t")


def test_dumper_tables_split_volume():
    """split_securable_name for VOLUME 'c.s.v' -> ('c', 's', None, 'v')."""
    result = split_securable_name(SecurableType.VOLUME, "c.s.v")
    assert result == ("c", "s", None, "v")


def test_dumper_tables_split_function():
    """split_securable_name for FUNCTION 'c.s.f' -> ('c', 's', None, 'f')."""
    result = split_securable_name(SecurableType.FUNCTION, "c.s.f")
    assert result == ("c", "s", None, "f")


def test_dumper_tables_split_column():
    """split_securable_name for COLUMN 'c.s.t.col' -> ('c', 's', 't', 'col')."""
    result = split_securable_name(SecurableType.COLUMN, "c.s.t.col")
    assert result == ("c", "s", "t", "col")


# --- securables table tests ---


def test_dumper_tables_securables_one_row_per_securable():
    """securables table: exactly one row per securable (not flattened by columns)."""
    col1 = Column(SecurableType.COLUMN, "c.s.t.col1", data_type="STRING")
    col2 = Column(SecurableType.COLUMN, "c.s.t.col2", data_type="INT")
    table = Table(SecurableType.TABLE, "c.s.t", columns=(col1, col2))
    state = _state(securables=frozenset([table]))
    rows = _rows("securables", state)
    assert len(rows) == 1


def test_dumper_tables_securables_table_columns_in_array():
    """securables table: table row has columns array with struct elements containing name."""
    col1 = Column(SecurableType.COLUMN, "c.s.t.col1", data_type="STRING")
    col2 = Column(SecurableType.COLUMN, "c.s.t.col2", data_type="INT")
    table = Table(SecurableType.TABLE, "c.s.t", columns=(col1, col2))
    state = _state(securables=frozenset([table]))
    rows = _rows("securables", state)
    assert len(rows) == 1
    row = rows[0]
    assert row["columns"] == ({"name": "col1"}, {"name": "col2"})


def test_dumper_tables_securables_non_table_columns_none():
    """securables table: non-table rows (volumes, functions) have columns=None."""
    func = Function(
        SecurableType.FUNCTION,
        "c.s.mask_pii",
        parameters=(("x", "STRING"),),
        definition="RETURN x",
    )
    state = _state(securables=frozenset([func]))
    rows = _rows("securables", state)
    assert len(rows) == 1
    assert rows[0]["columns"] is None


def test_dumper_tables_securables_function_parameters():
    """securables table: function rows render parameters as '<name> <type>' strings."""
    func = Function(
        SecurableType.FUNCTION,
        "c.s.mask_pii",
        parameters=(("x", "STRING"), ("n", "INT")),
        definition="RETURN x",
    )
    state = _state(securables=frozenset([func]))
    rows = _rows("securables", state)
    assert len(rows) == 1
    assert rows[0]["parameters"] == ("x STRING", "n INT")


def test_dumper_tables_securables_owner_from_attributes():
    """securables table: owner comes from SecurableAttributes as identifier."""
    owner = Principal(PrincipalType.USER, identifier="alice", name="alice")
    attr = SecurableAttributes(SecurableType.TABLE, "c.s.t", owner=owner)
    table = Table(SecurableType.TABLE, "c.s.t")
    state = _state(
        securables=frozenset([table]),
        attributes=frozenset([attr]),
    )
    rows = _rows("securables", state)
    assert len(rows) == 1
    assert rows[0]["owner"] == "alice"


def test_dumper_tables_securables_owner_none_when_no_attribute():
    """securables table: owner is None when no SecurableAttributes entry."""
    table = Table(SecurableType.TABLE, "c.s.t")
    state = _state(securables=frozenset([table]))
    rows = _rows("securables", state)
    assert len(rows) == 1
    assert rows[0]["owner"] is None


def test_dumper_tables_securables_comment_from_attributes():
    """securables table: comment comes from SecurableAttributes for CATALOG/SCHEMA/TABLE/VOLUME."""
    attr = SecurableAttributes(SecurableType.TABLE, "c.s.t", comment="This is my table")
    table = Table(SecurableType.TABLE, "c.s.t")
    state = _state(
        securables=frozenset([table]),
        attributes=frozenset([attr]),
    )
    rows = _rows("securables", state)
    assert len(rows) == 1
    assert rows[0]["comment"] == "This is my table"


def test_dumper_tables_securables_comment_from_function():
    """securables table: comment comes from Function.comment for FUNCTION rows."""
    func = Function(
        SecurableType.FUNCTION,
        "c.s.mask_pii",
        parameters=(("x", "STRING"),),
        definition="RETURN x",
        comment="Masks PII data",
    )
    state = _state(securables=frozenset([func]))
    rows = _rows("securables", state)
    assert len(rows) == 1
    assert rows[0]["comment"] == "Masks PII data"


def test_dumper_tables_securables_comment_none_when_unset():
    """securables table: comment is None when unset or no matching attribute."""
    table = Table(SecurableType.TABLE, "c.s.t")
    state = _state(securables=frozenset([table]))
    rows = _rows("securables", state)
    assert len(rows) == 1
    assert rows[0]["comment"] is None


def test_dumper_tables_securables_no_table_name_or_ordinal_columns():
    """securables table: has no table_name or ordinal_position columns."""
    spec = _spec("securables")
    col_names = {col.name for col in spec.columns}
    assert "table_name" not in col_names
    assert "ordinal_position" not in col_names


def test_dumper_tables_securables_has_columns_array():
    """securables table: has columns array column."""
    spec = _spec("securables")
    col_names = {col.name for col in spec.columns}
    assert "columns" in col_names


def test_dumper_tables_securables_columns_type():
    """securables table: columns column has sql_type ARRAY<STRUCT<name: STRING>>."""
    spec = _spec("securables")
    columns_col = next((col for col in spec.columns if col.name == "columns"), None)
    assert columns_col is not None
    assert columns_col.sql_type == "ARRAY<STRUCT<name: STRING>>"


# --- securable_tags table tests ---


def test_dumper_tables_securable_tags_one_row_per_tag():
    """securable_tags table: one row per securable and tag."""
    tag1 = SecurableTag(SecurableType.TABLE, "c.s.t", "env", "prod")
    tag2 = SecurableTag(SecurableType.TABLE, "c.s.t", "owner", "data-team")
    state = _state(tags=frozenset([tag1, tag2]))
    rows = _rows("securable_tags", state)
    assert len(rows) == 2


def test_dumper_tables_securable_tags_column_tag_paths():
    """securable_tags: column tag has table_name=parent, securable_name=col."""
    tag = SecurableTag(SecurableType.COLUMN, "c.s.t.col", "sensitivity", "high")
    state = _state(tags=frozenset([tag]))
    rows = _rows("securable_tags", state)
    assert len(rows) == 1
    row = rows[0]
    assert row["table_name"] == "t"
    assert row["securable_name"] == "col"
    assert row["securable_type"] == "COLUMN"


def test_dumper_tables_securable_tags_catalog_tag_schema_none():
    """securable_tags: catalog tag has schema_name=None."""
    tag = SecurableTag(SecurableType.CATALOG, "c", "owner", "data-team")
    state = _state(tags=frozenset([tag]))
    rows = _rows("securable_tags", state)
    assert len(rows) == 1
    assert rows[0]["schema_name"] is None


# --- securable_privileges table tests ---


def test_dumper_tables_securable_privileges_one_row_per_privilege():
    """securable_privileges table: one row per grantee and privilege."""
    user = Principal(PrincipalType.USER, identifier="alice", name="alice")
    priv1 = SecurablePrivilege(SecurableType.TABLE, "c.s.t", user, PrivilegeType.SELECT)
    priv2 = SecurablePrivilege(SecurableType.TABLE, "c.s.t", user, PrivilegeType.MODIFY)
    state = _state(privileges=frozenset([priv1, priv2]))
    rows = _rows("securable_privileges", state)
    assert len(rows) == 2


def test_dumper_tables_securable_privileges_no_table_name_column():
    """securable_privileges table: has no table_name column."""
    spec = _spec("securable_privileges")
    col_names = {col.name for col in spec.columns}
    assert "table_name" not in col_names


def test_dumper_tables_securable_privileges_privilege_type_rendering():
    """securable_privileges: privilege_type rendered as uppercase with spaces."""
    user = Principal(PrincipalType.USER, identifier="alice", name="alice")
    priv = SecurablePrivilege(
        SecurableType.CATALOG, "c", user, PrivilegeType.USE_CATALOG
    )
    state = _state(privileges=frozenset([priv]))
    rows = _rows("securable_privileges", state)
    assert len(rows) == 1
    assert rows[0]["privilege_type"] == "USE CATALOG"


def test_dumper_tables_securable_privileges_all_privileges_rendering():
    """securable_privileges: ALL_PRIVILEGES renders as 'ALL PRIVILEGES'."""
    user = Principal(PrincipalType.USER, identifier="alice", name="alice")
    priv = SecurablePrivilege(
        SecurableType.TABLE, "c.s.t", user, PrivilegeType.ALL_PRIVILEGES
    )
    state = _state(privileges=frozenset([priv]))
    rows = _rows("securable_privileges", state)
    assert len(rows) == 1
    assert rows[0]["privilege_type"] == "ALL PRIVILEGES"


def test_dumper_tables_securable_privileges_grantee_type_resolved():
    """securable_privileges: grantee_type from resolved principal."""
    sp = Principal(
        PrincipalType.SERVICE_PRINCIPAL,
        identifier="app-uuid-1",
        name="my-sp",
    )
    priv = SecurablePrivilege(
        SecurableType.TABLE,
        "c.s.t",
        Principal(PrincipalType.UNKNOWN, identifier="app-uuid-1"),
        PrivilegeType.SELECT,
    )
    state = _state(
        privileges=frozenset([priv]),
        principals={"my-sp": sp},
    )
    rows = _rows("securable_privileges", state)
    assert len(rows) == 1
    assert rows[0]["grantee_type"] == "SERVICE_PRINCIPAL"


def test_dumper_tables_securable_privileges_grantee_type_none_when_unresolved():
    """securable_privileges: grantee_type=None when unresolvable."""
    priv = SecurablePrivilege(
        SecurableType.TABLE,
        "c.s.t",
        Principal(PrincipalType.UNKNOWN, identifier="unknown-principal"),
        PrivilegeType.SELECT,
    )
    state = _state(privileges=frozenset([priv]))
    rows = _rows("securable_privileges", state)
    assert len(rows) == 1
    assert rows[0]["grantee_type"] is None


# --- abac_policies table tests ---


def test_dumper_tables_abac_policies_one_row_per_policy():
    """abac_policies table: one row per policy."""
    policy = Policy(
        SecurableType.TABLE,
        "c.s.t",
        "mask_pii",
        PolicyType.MASK,
        "c.s.mask_pii_email",
        (),
        (),
        None,
        (),
        "email",
        (),
    )
    state = _state(policies=frozenset([policy]))
    rows = _rows("abac_policies", state)
    assert len(rows) == 1


def test_dumper_tables_abac_policies_has_function_full_name_column():
    """abac_policies table: has 'function_full_name' column, not 'function_name'."""
    spec = _spec("abac_policies")
    col_names = {col.name for col in spec.columns}
    assert "function_full_name" in col_names
    assert "function_name" not in col_names


def test_dumper_tables_abac_policies_mask_policy_type():
    """abac_policies: PolicyType.MASK renders as 'COLUMN_MASK'."""
    policy = Policy(
        SecurableType.TABLE,
        "c.s.t",
        "mask_email",
        PolicyType.MASK,
        "c.s.mask_func",
        (),
        (),
        None,
        (),
        "email",
        (),
    )
    state = _state(policies=frozenset([policy]))
    rows = _rows("abac_policies", state)
    assert len(rows) == 1
    assert rows[0]["policy_type"] == "COLUMN_MASK"


def test_dumper_tables_abac_policies_filter_policy_type():
    """abac_policies: PolicyType.FILTER renders as 'ROW_FILTER'."""
    policy = Policy(
        SecurableType.TABLE,
        "c.s.t",
        "filter_sensitive",
        PolicyType.FILTER,
        "c.s.filter_func",
        (),
        (),
        None,
        (),
        None,
        (),
    )
    state = _state(policies=frozenset([policy]))
    rows = _rows("abac_policies", state)
    assert len(rows) == 1
    assert rows[0]["policy_type"] == "ROW_FILTER"


def test_dumper_tables_abac_policies_to_principals_rendered():
    """abac_policies: to_principals rendered as tuple of identifiers in order."""
    p1 = Principal(PrincipalType.USER, identifier="alice", name="alice")
    p2 = Principal(PrincipalType.GROUP, identifier="data-team", name="data-team")
    policy = Policy(
        SecurableType.TABLE,
        "c.s.t",
        "mask_pii",
        PolicyType.MASK,
        "c.s.mask_func",
        (p1, p2),
        (),
        None,
        (),
        "email",
        (),
    )
    state = _state(policies=frozenset([policy]))
    rows = _rows("abac_policies", state)
    assert len(rows) == 1
    assert rows[0]["to_principals"] == ("alice", "data-team")


def test_dumper_tables_abac_policies_except_principals_rendered():
    """abac_policies: except_principals rendered as tuple of identifiers in order."""
    p1 = Principal(PrincipalType.USER, identifier="bob", name="bob")
    policy = Policy(
        SecurableType.TABLE,
        "c.s.t",
        "mask_pii",
        PolicyType.MASK,
        "c.s.mask_func",
        (),
        (p1,),
        None,
        (),
        "email",
        (),
    )
    state = _state(policies=frozenset([policy]))
    rows = _rows("abac_policies", state)
    assert len(rows) == 1
    assert rows[0]["except_principals"] == ("bob",)


def test_dumper_tables_abac_policies_match_columns_rendered():
    """abac_policies: match_columns rendered as '<condition> AS <alias>' in order."""
    policy = Policy(
        SecurableType.TABLE,
        "c.s.t",
        "mask_pii",
        PolicyType.MASK,
        "c.s.mask_func",
        (),
        (),
        None,
        (("is_sensitive", "has_tag_value('sensitivity', 'high')"),),
        "email",
        (),
    )
    state = _state(policies=frozenset([policy]))
    rows = _rows("abac_policies", state)
    assert len(rows) == 1
    assert rows[0]["match_columns"] == (
        "has_tag_value('sensitivity', 'high') AS is_sensitive",
    )


def test_dumper_tables_abac_policies_function_full_name():
    """abac_policies: function_full_name comes from Policy.function_name."""
    policy = Policy(
        SecurableType.TABLE,
        "c.s.t",
        "mask_pii",
        PolicyType.MASK,
        "c.s.mask_pii_email",
        (),
        (),
        None,
        (),
        "email",
        (),
    )
    state = _state(policies=frozenset([policy]))
    rows = _rows("abac_policies", state)
    assert len(rows) == 1
    assert rows[0]["function_full_name"] == "c.s.mask_pii_email"


def test_dumper_tables_abac_policies_privileges_always_none():
    """abac_policies: privileges always None for mask/filter policies."""
    policy = Policy(
        SecurableType.TABLE,
        "c.s.t",
        "mask_pii",
        PolicyType.MASK,
        "c.s.mask_func",
        (),
        (),
        None,
        (),
        "email",
        (),
    )
    state = _state(policies=frozenset([policy]))
    rows = _rows("abac_policies", state)
    assert len(rows) == 1
    assert rows[0]["privileges"] is None


# --- governed_tags table tests ---


def test_dumper_tables_governed_tags_one_row_per_key():
    """governed_tags table: one row per tag key."""
    tag1 = GovernedTag("sensitivity", description="Data sensitivity level")
    tag2 = GovernedTag("env", description="Environment")
    state = _state(governed_tags=frozenset([tag1, tag2]))
    rows = _rows(
        "governed_tags", state, referenced_tag_keys=frozenset(["sensitivity", "env"])
    )
    assert len(rows) == 2


def test_dumper_tables_governed_tags_values_sorted():
    """governed_tags: values is sorted tuple of allowed_values."""
    tag = GovernedTag(
        "env",
        allowed_values=frozenset(["prod", "staging", "dev"]),
    )
    state = _state(governed_tags=frozenset([tag]))
    rows = _rows("governed_tags", state, referenced_tag_keys=frozenset(["env"]))
    assert len(rows) == 1
    assert rows[0]["values"] == ("dev", "prod", "staging")


def test_dumper_tables_governed_tags_description_none_when_empty():
    """governed_tags: description is None when empty string."""
    tag = GovernedTag("test_tag", description="")
    state = _state(governed_tags=frozenset([tag]))
    rows = _rows("governed_tags", state, referenced_tag_keys=frozenset(["test_tag"]))
    assert len(rows) == 1
    assert rows[0]["description"] is None


def test_dumper_tables_governed_tags_assigners_when_referenced():
    """governed_tags: assigners is sorted tuple of identifiers when referenced."""
    assigner1 = Principal(PrincipalType.USER, identifier="alice", name="alice")
    assigner2 = Principal(PrincipalType.USER, identifier="bob", name="bob")
    tag = GovernedTag("pii", assigners=frozenset([assigner2, assigner1]))
    state = _state(
        governed_tags=frozenset([tag]),
        principals={"alice": assigner1, "bob": assigner2},
    )
    rows = _rows("governed_tags", state, referenced_tag_keys=frozenset(["pii"]))
    assert len(rows) == 1
    assert rows[0]["assigners"] == ("alice", "bob")


def test_dumper_tables_governed_tags_assigners_none_when_not_referenced():
    """governed_tags: assigners is None when tag NOT in referenced_tag_keys."""
    tag = GovernedTag("unreferenced_tag", description="This tag is not referenced")
    state = _state(governed_tags=frozenset([tag]))
    rows = _rows("governed_tags", state, referenced_tag_keys=frozenset())
    assert len(rows) == 1
    assert rows[0]["assigners"] is None


def test_dumper_tables_governed_tags_empty_tuple_when_referenced_no_assigners():
    """governed_tags: assigners is empty tuple when referenced but has no assigners."""
    tag = GovernedTag("no_assigners")
    state = _state(governed_tags=frozenset([tag]))
    rows = _rows(
        "governed_tags", state, referenced_tag_keys=frozenset(["no_assigners"])
    )
    assert len(rows) == 1
    assert rows[0]["assigners"] == ()


# --- domains table tests ---


def test_dumper_tables_domains_one_row_per_domain():
    """domains table: one row per domain."""
    domain1 = Domain("data_domain", description="Our data domain")
    domain2 = Domain("analytics_domain", description="Analytics domain")
    state = _state(domains=frozenset([domain1, domain2]))
    rows = _rows("domains", state)
    assert len(rows) == 2


def test_dumper_tables_domains_icon_name_and_color():
    """domains: icon_name and icon_color from DomainIcon."""
    icon = DomainIcon(name="star", color="#FF5733")
    domain = Domain("starred_domain", icon=icon)
    state = _state(domains=frozenset([domain]))
    rows = _rows("domains", state)
    assert len(rows) == 1
    assert rows[0]["icon_name"] == "star"
    assert rows[0]["icon_color"] == "#FF5733"


def test_dumper_tables_domains_icon_none_when_not_set():
    """domains: icon_name and icon_color are None when icon is None."""
    domain = Domain("plain_domain")
    state = _state(domains=frozenset([domain]))
    rows = _rows("domains", state)
    assert len(rows) == 1
    assert rows[0]["icon_name"] is None
    assert rows[0]["icon_color"] is None


def test_dumper_tables_domains_business_owners_sorted():
    """domains: business_owners rendered as sorted tuple of identifiers."""
    owner1 = Principal(PrincipalType.USER, identifier="alice", name="alice")
    owner2 = Principal(PrincipalType.USER, identifier="bob", name="bob")
    domain = Domain(
        "owned_domain",
        business_owners=frozenset([owner2, owner1]),
    )
    state = _state(
        domains=frozenset([domain]),
        principals={"alice": owner1, "bob": owner2},
    )
    rows = _rows("domains", state)
    assert len(rows) == 1
    assert rows[0]["business_owners"] == ("alice", "bob")


def test_dumper_tables_domains_technical_owners_sorted():
    """domains: technical_owners rendered as sorted tuple of identifiers."""
    owner1 = Principal(PrincipalType.USER, identifier="charlie", name="charlie")
    domain = Domain("tech_domain", technical_owners=frozenset([owner1]))
    state = _state(
        domains=frozenset([domain]),
        principals={"charlie": owner1},
    )
    rows = _rows("domains", state)
    assert len(rows) == 1
    assert rows[0]["technical_owners"] == ("charlie",)


def test_dumper_tables_domains_parent_tag_key_none_when_empty():
    """domains: parent_tag_key is None when empty string."""
    domain = Domain("root_domain", parent_tag_key="")
    state = _state(domains=frozenset([domain]))
    rows = _rows("domains", state)
    assert len(rows) == 1
    assert rows[0]["parent_tag_key"] is None


def test_dumper_tables_domains_parent_tag_key_set():
    """domains: parent_tag_key copied when non-empty."""
    domain = Domain("child_domain", parent_tag_key="parent_domain")
    state = _state(domains=frozenset([domain]))
    rows = _rows("domains", state)
    assert len(rows) == 1
    assert rows[0]["parent_tag_key"] == "parent_domain"


def test_dumper_tables_domains_no_domain_id_column():
    """domains table: no domain_id, resource_name, or parent_domain_id columns."""
    spec = _spec("domains")
    col_names = {col.name for col in spec.columns}
    assert "domain_id" not in col_names
    assert "resource_name" not in col_names
    assert "parent_domain_id" not in col_names


# --- principals table tests ---


def test_dumper_tables_principals_one_row_per_principal():
    """principals table: one row per principal in state.principals."""
    user1 = Principal(PrincipalType.USER, identifier="alice", name="alice")
    user2 = Principal(PrincipalType.USER, identifier="bob", name="bob")
    state = _state(principals={"alice": user1, "bob": user2})
    rows = _rows("principals", state)
    assert len(rows) == 2


def test_dumper_tables_principals_user_type():
    """principals: USER -> email=identifier, application_id=None."""
    user = Principal(
        PrincipalType.USER,
        identifier="alice@company.com",
        name="alice",
        internal_id="123",
    )
    state = _state(principals={"alice": user})
    rows = _rows("principals", state)
    assert len(rows) == 1
    row = rows[0]
    assert row["principal_type"] == "USER"
    assert row["email"] == "alice@company.com"
    assert row["application_id"] is None


def test_dumper_tables_principals_service_principal_type():
    """principals: SERVICE_PRINCIPAL -> application_id=identifier, email=None."""
    sp = Principal(
        PrincipalType.SERVICE_PRINCIPAL,
        identifier="app-uuid-1",
        name="my-sp",
        internal_id="456",
    )
    state = _state(principals={"my-sp": sp})
    rows = _rows("principals", state)
    assert len(rows) == 1
    row = rows[0]
    assert row["principal_type"] == "SERVICE_PRINCIPAL"
    assert row["application_id"] == "app-uuid-1"
    assert row["email"] is None


def test_dumper_tables_principals_group_type():
    """principals: GROUP -> email=None, application_id=None."""
    group = Principal(
        PrincipalType.GROUP,
        identifier="data-team",
        name="data-team",
        internal_id="789",
    )
    state = _state(principals={"data-team": group})
    rows = _rows("principals", state)
    assert len(rows) == 1
    row = rows[0]
    assert row["principal_type"] == "GROUP"
    assert row["email"] is None
    assert row["application_id"] is None


def test_dumper_tables_principals_principal_id_from_internal_id():
    """principals: principal_id equals internal_id."""
    user = Principal(
        PrincipalType.USER,
        identifier="alice",
        name="alice",
        internal_id="123",
    )
    state = _state(principals={"alice": user})
    rows = _rows("principals", state)
    assert len(rows) == 1
    assert rows[0]["principal_id"] == "123"


def test_dumper_tables_principals_principal_id_none_when_unknown():
    """principals: principal_id is None when internal_id is None."""
    user = Principal(
        PrincipalType.USER,
        identifier="bob",
        name="bob",
        internal_id=None,
    )
    state = _state(principals={"bob": user})
    rows = _rows("principals", state)
    assert len(rows) == 1
    assert rows[0]["principal_id"] is None


# --- group_members table tests ---


def test_dumper_tables_group_members_one_row_per_member():
    """group_members table: one row per (group, direct member)."""
    user1 = Principal(PrincipalType.USER, identifier="alice", name="alice")
    user2 = Principal(PrincipalType.USER, identifier="bob", name="bob")
    group = Group("data-team", members=frozenset([user1, user2]))
    state = _state(
        groups=frozenset([group]),
        principals={"alice": user1, "bob": user2},
    )
    rows = _rows("group_members", state)
    assert len(rows) == 2


def test_dumper_tables_group_members_resolved_via_identifier_map():
    """group_members: members resolved via identifier reverse map."""
    sp = Principal(
        PrincipalType.SERVICE_PRINCIPAL,
        identifier="app-uuid-1",
        name="my-sp",
        internal_id="111",
    )
    unresolved_sp = Principal(PrincipalType.UNKNOWN, identifier="app-uuid-1")
    group = Group("dev-group", members=frozenset([unresolved_sp]))
    state = _state(
        groups=frozenset([group]),
        principals={"my-sp": sp},
    )
    rows = _rows("group_members", state)
    assert len(rows) == 1
    row = rows[0]
    assert row["member_id"] == "111"
    assert row["member_display_name"] == "my-sp"
    assert row["member_type"] == "SERVICE_PRINCIPAL"


def test_dumper_tables_group_members_unresolvable_member():
    """group_members: unresolvable member yields member_id=None, member_type=None."""
    unresolvable = Principal(PrincipalType.UNKNOWN, identifier="unknown-principal")
    group = Group("some-group", members=frozenset([unresolvable]))
    state = _state(groups=frozenset([group]))
    rows = _rows("group_members", state)
    assert len(rows) == 1
    row = rows[0]
    assert row["member_id"] is None
    assert row["member_type"] is None
    assert row["member_display_name"] == "unknown-principal"


def test_dumper_tables_group_members_resolved_with_no_internal_id():
    """group_members: resolved member with internal_id=None yields member_id=None."""
    member = Principal(
        PrincipalType.USER,
        identifier="charlie",
        name="charlie",
        internal_id=None,
    )
    group = Group("group-no-ids", members=frozenset([member]))
    state = _state(
        groups=frozenset([group]),
        principals={"charlie": member},
    )
    rows = _rows("group_members", state)
    assert len(rows) == 1
    row = rows[0]
    assert row["member_id"] is None
    assert row["member_display_name"] == "charlie"
    assert row["member_type"] == "USER"


def test_dumper_tables_group_members_account_users_excluded():
    """group_members: 'Account Users' group (case-insensitive) yields no rows."""
    user = Principal(PrincipalType.USER, identifier="alice", name="alice")
    group = Group("Account Users", members=frozenset([user]))
    state = _state(
        groups=frozenset([group]),
        principals={"alice": user},
    )
    rows = _rows("group_members", state)
    for row in rows:
        assert row.get("group_display_name", "").lower() != "account users"


def test_dumper_tables_group_members_none_members_no_rows():
    """group_members: group with members=None yields no rows for that group."""
    user = Principal(PrincipalType.USER, identifier="alice", name="alice")
    unmanaged_group = Group("unmanaged-group", members=None)
    managed_group = Group("managed-group", members=frozenset([user]))
    state = _state(
        groups=frozenset([unmanaged_group, managed_group]),
        principals={"alice": user},
    )
    rows = _rows("group_members", state)
    for row in rows:
        assert row.get("group_display_name") != "unmanaged-group"


# --- group_assumers table tests ---


def test_dumper_tables_group_assumers_one_row_per_assumer():
    """group_assumers table: one row per (group, assumer)."""
    user1 = Principal(PrincipalType.USER, identifier="alice", name="alice")
    user2 = Principal(PrincipalType.USER, identifier="bob", name="bob")
    group = Group("data-team", id="g1", assumers=frozenset([user1, user2]))
    state = _state(
        groups=frozenset([group]),
        principals={"alice": user1, "bob": user2},
    )
    rows = _rows("group_assumers", state)
    assert len(rows) == 2


def test_dumper_tables_group_assumers_resolved_via_identifier_map():
    """group_assumers: assumers resolved via identifier reverse map."""
    sp = Principal(
        PrincipalType.SERVICE_PRINCIPAL,
        identifier="app-uuid-1",
        name="my-sp",
        internal_id="111",
    )
    unresolved_sp = Principal(PrincipalType.UNKNOWN, identifier="app-uuid-1")
    group = Group("dev-group", id="g2", assumers=frozenset([unresolved_sp]))
    state = _state(
        groups=frozenset([group]),
        principals={"my-sp": sp},
    )
    rows = _rows("group_assumers", state)
    assert len(rows) == 1
    row = rows[0]
    assert row["assumer_id"] == "111"
    assert row["assumer_display_name"] == "my-sp"
    assert row["assumer_type"] == "SERVICE_PRINCIPAL"


def test_dumper_tables_group_assumers_unresolvable_assumer():
    """group_assumers: unresolvable assumer yields assumer_id=None, assumer_type=None."""
    unresolvable = Principal(PrincipalType.UNKNOWN, identifier="unknown-principal")
    group = Group("some-group", id="g3", assumers=frozenset([unresolvable]))
    state = _state(groups=frozenset([group]))
    rows = _rows("group_assumers", state)
    assert len(rows) == 1
    row = rows[0]
    assert row["assumer_id"] is None
    assert row["assumer_type"] is None
    assert row["assumer_display_name"] == "unknown-principal"


def test_dumper_tables_group_assumers_account_users_excluded():
    """group_assumers: 'Account Users' group (case-insensitive) yields no rows."""
    user = Principal(PrincipalType.USER, identifier="alice", name="alice")
    group = Group("Account Users", assumers=frozenset([user]))
    state = _state(
        groups=frozenset([group]),
        principals={"alice": user},
    )
    rows = _rows("group_assumers", state)
    for row in rows:
        assert row.get("group_display_name", "").lower() != "account users"


def test_dumper_tables_group_assumers_none_assumers_no_rows():
    """group_assumers: group with assumers=None yields no rows for that group."""
    user = Principal(PrincipalType.USER, identifier="alice", name="alice")
    unmanaged_group = Group("unmanaged-group", id="g4", assumers=None)
    managed_group = Group("managed-group", id="g5", assumers=frozenset([user]))
    state = _state(
        groups=frozenset([unmanaged_group, managed_group]),
        principals={"alice": user},
    )
    rows = _rows("group_assumers", state)
    for row in rows:
        assert row.get("group_display_name") != "unmanaged-group"


# ---------------------------------------------------------------------------
# Attachment paths and empty-vs-unknown arrays
# ---------------------------------------------------------------------------


def _policy_on(securable_type: SecurableType, full_name: str) -> Policy:
    return Policy(
        securable_type,
        full_name,
        "filter_rows",
        PolicyType.FILTER,
        "c.s.filter_func",
        (),
        (),
        None,
        (),
        None,
        (),
    )


def test_dumper_tables_abac_policies_catalog_policy_names_the_catalog():
    """securable_name is the attached securable's own name, as in every other table."""
    state = _state(policies=frozenset([_policy_on(SecurableType.CATALOG, "c")]))
    (row,) = _rows("abac_policies", state)
    assert (row["catalog_name"], row["schema_name"], row["securable_name"]) == (
        "c",
        None,
        "c",
    )
    assert row["on_securable_type"] == "CATALOG"


def test_dumper_tables_abac_policies_schema_policy_names_the_schema():
    state = _state(policies=frozenset([_policy_on(SecurableType.SCHEMA, "c.s")]))
    (row,) = _rows("abac_policies", state)
    assert (row["catalog_name"], row["schema_name"], row["securable_name"]) == (
        "c",
        "s",
        "s",
    )


def test_dumper_tables_abac_policies_table_policy_names_the_table():
    state = _state(policies=frozenset([_policy_on(SecurableType.TABLE, "c.s.t")]))
    (row,) = _rows("abac_policies", state)
    assert (row["catalog_name"], row["schema_name"], row["securable_name"]) == (
        "c",
        "s",
        "t",
    )


def test_dumper_tables_securables_table_without_columns_has_empty_columns():
    state = _state(securables=frozenset([Table(SecurableType.TABLE, "c.s.t")]))
    (row,) = _rows("securables", state)
    assert row["columns"] == ()


def test_dumper_tables_securables_function_without_parameters_has_empty_parameters():
    func = Function(SecurableType.FUNCTION, "c.s.f", parameters=(), definition="1")
    (row,) = _rows("securables", _state(securables=frozenset([func])))
    assert row["parameters"] == ()


def test_dumper_tables_domains_empty_owner_set_is_empty_not_null():
    domain = Domain(tag_key="d", business_owners=frozenset(), technical_owners=None)
    (row,) = _rows("domains", _state(domains=frozenset([domain])))
    assert row["business_owners"] == ()
    assert row["technical_owners"] is None


def test_dumper_tables_group_members_ignores_all_account_groups():
    """Only fetched groups carry membership; the identity-only account inventory
    must not produce rows."""
    user = Principal(PrincipalType.USER, identifier="alice", name="alice")
    inventory_only = Group("g", id="g1", members=frozenset([user]))
    state = _state(all_account_groups=frozenset([inventory_only]))
    assert _rows("group_members", state) == []


def test_dumper_tables_securables_keeps_dotted_column_names_intact():
    """A column name containing a dot (Delta column mapping) is written whole,
    matching securable_tags' split of the same column."""
    column = Column(SecurableType.COLUMN, "c.s.t.a.b", data_type="STRING")
    table = Table(SecurableType.TABLE, "c.s.t", columns=(column,))
    (row,) = _rows("securables", _state(securables=frozenset([table])))
    assert row["columns"] == ({"name": "a.b"},)
