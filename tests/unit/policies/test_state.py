from __future__ import annotations

from uc_declarative_abac.policies import Policy
from uc_declarative_abac.principals import Principal
from uc_declarative_abac.types import (
    PolicyType,
    PrincipalType,
    PrivilegeType,
    SecurableType,
)


def _policy(**overrides) -> Policy:
    base = {
        "securable_type": SecurableType.TABLE,
        "securable_full_name": "cat.sch.tbl",
        "name": "p",
        "policy_type": PolicyType.MASK,
        "function_name": "cat.sch.mask",
        "to_principals": (Principal(PrincipalType.UNKNOWN, name="analysts"),),
        "except_principals": (),
        "when_condition": None,
        "match_columns": (),
        "on_column": None,
        "using_columns": (),
    }
    base.update(overrides)
    return Policy(**base)


def test_policy_defaults_privileges_to_none():
    """A Policy built without privileges (the mask/filter case) has privileges None."""
    assert _policy().privileges is None


def test_policy_equality_unaffected_when_privileges_defaulted():
    """Two mask policies that don't set privileges still compare equal and hash equal."""
    p1 = _policy()
    p2 = _policy()
    assert p1 == p2
    assert hash(p1) == hash(p2)


def test_policy_accepts_privileges_tuple():
    """A Policy can carry a privileges tuple (used to represent grant/pseudo policies)."""
    p = _policy(
        policy_type=PolicyType.GRANT,
        privileges=(PrivilegeType.SELECT, PrivilegeType.MODIFY),
    )
    assert p.privileges == (PrivilegeType.SELECT, PrivilegeType.MODIFY)
