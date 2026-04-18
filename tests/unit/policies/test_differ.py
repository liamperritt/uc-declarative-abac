from __future__ import annotations

from uc_abac_governor.policies.differ import compute_policy_diff
from uc_abac_governor.policies.state import Policy, PolicyDiff
from uc_abac_governor.types import PolicyType, SecurableType


def _make_policy(**overrides) -> Policy:
    base = dict(
        securable_type=SecurableType.TABLE,
        securable_full_name="cat.s.t",
        name="p1",
        policy_type=PolicyType.MASK,
        function_name="cat.default.fn",
        to_principals=("analysts",),
        except_principals=(),
        when_condition=None,
        match_columns=(("c", "has_column_tag_value('pii', 'email')"),),
        on_column="c",
        using_columns=(),
    )
    base.update(overrides)
    return Policy(**base)


# ---------------------------------------------------------------------------
# to_create / to_replace / ignored
# ---------------------------------------------------------------------------


def test_policy_differ_emits_to_create_for_desired_only():
    desired = {_make_policy()}
    actual: set[Policy] = set()

    diff = compute_policy_diff(desired, actual)
    assert diff.to_create == desired
    assert diff.to_replace == set()


def test_policy_differ_empty_diff_when_desired_equals_actual():
    policy = _make_policy()
    diff = compute_policy_diff({policy}, {policy})
    assert diff.to_create == set()
    assert diff.to_replace == set()


def test_policy_differ_emits_to_replace_when_fields_differ():
    """Identity match (same type/name/full_name) with differing fields → to_replace."""
    desired = {_make_policy(function_name="cat.default.new_fn")}
    actual = {_make_policy(function_name="cat.default.old_fn")}

    diff = compute_policy_diff(desired, actual)
    assert diff.to_create == set()
    assert diff.to_replace == desired


def test_policy_differ_ignores_actual_only_policies():
    """Policies in actual but not desired are silently skipped (no delete)."""
    desired: set[Policy] = set()
    actual = {_make_policy()}

    diff = compute_policy_diff(desired, actual)
    assert diff == PolicyDiff()


def test_policy_differ_distinguishes_policies_by_securable():
    """Same policy name on different securables are treated as distinct."""
    desired = {
        _make_policy(securable_full_name="cat.s.t1"),
        _make_policy(securable_full_name="cat.s.t2"),
    }
    actual = {_make_policy(securable_full_name="cat.s.t1")}

    diff = compute_policy_diff(desired, actual)
    assert diff.to_replace == set()  # t1 matches identically
    assert len(diff.to_create) == 1
    (created,) = diff.to_create
    assert created.securable_full_name == "cat.s.t2"


def test_policy_differ_treats_to_principals_change_as_replace():
    desired = {_make_policy(to_principals=("analysts", "scientists"))}
    actual = {_make_policy(to_principals=("analysts",))}

    diff = compute_policy_diff(desired, actual)
    assert diff.to_replace == desired


def test_policy_differ_treats_when_condition_change_as_replace():
    desired = {_make_policy(when_condition="has_tag('env')")}
    actual = {_make_policy(when_condition=None)}

    diff = compute_policy_diff(desired, actual)
    assert diff.to_replace == desired
