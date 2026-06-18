from __future__ import annotations

from unittest.mock import MagicMock

from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.policies import (
    compute_policy_diff,
    Policy,
    PolicyDiff,
)
from uc_declarative_abac.principals import (
    Principal,
    PrincipalResolver,
)
from uc_declarative_abac.types import (
    PolicyType,
    PrincipalType,
    SecurableType,
)


def _resolver() -> PrincipalResolver:
    """A resolver whose ws_helper is never consulted — test inputs are already resolved."""
    return PrincipalResolver(MagicMock())


def _failing_resolver() -> PrincipalResolver:
    """A resolver whose ws_helper raises PrincipalValidationError for any lookup —
    used to exercise the unresolvable-principal paths."""
    from uc_declarative_abac.utils import PrincipalValidationError

    ws_helper = MagicMock()
    ws_helper.resolve_by_name.side_effect = lambda n: (_ for _ in ()).throw(
        PrincipalValidationError(f"Principal not found: {n}")
    )
    ws_helper.resolve_by_identifier.side_effect = lambda i: (_ for _ in ()).throw(
        PrincipalValidationError(f"Principal not found by identifier: {i}")
    )
    return PrincipalResolver(ws_helper)


def _selective_resolver(resolvable: dict[str, Principal]) -> PrincipalResolver:
    """A resolver that resolves identifiers/names present in ``resolvable`` and
    raises PrincipalValidationError for everything else. Keys are the identifier
    (for actual-state principals) or name (for config-side principals) carried by
    the unresolved input Principal; values are the resolved Principal to return."""
    from uc_declarative_abac.utils import PrincipalValidationError

    def _lookup(key: str) -> Principal:
        if key in resolvable:
            return resolvable[key]
        raise PrincipalValidationError(f"Principal not found: {key}")

    ws_helper = MagicMock()
    ws_helper.resolve_by_name.side_effect = _lookup
    ws_helper.resolve_by_identifier.side_effect = _lookup
    return PrincipalResolver(ws_helper)


def _change_logger() -> ChangeLogger:
    return ChangeLogger()


def _resolved(name: str, principal_type: PrincipalType = PrincipalType.GROUP) -> Principal:
    """Construct a resolved Principal (identifier == name) for use in test tuples."""
    return Principal(principal_type=principal_type, identifier=name, name=name)


def _make_policy(**overrides) -> Policy:
    base = dict(
        securable_type=SecurableType.TABLE,
        securable_full_name="cat.s.t",
        name="p1",
        policy_type=PolicyType.MASK,
        function_name="cat.default.fn",
        to_principals=(_resolved("analysts"),),
        except_principals=(),
        when_condition=None,
        match_columns=(("c", "has_tag_value('pii', 'email')"),),
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

    diff = compute_policy_diff(desired, actual, _resolver(), _change_logger())
    assert diff.to_create == desired
    assert diff.to_replace == set()


def test_policy_differ_empty_diff_when_desired_equals_actual():
    policy = _make_policy()
    diff = compute_policy_diff({policy}, {policy}, _resolver(), _change_logger())
    assert diff.to_create == set()
    assert diff.to_replace == set()


def test_policy_differ_emits_to_replace_when_fields_differ():
    """Identity match (same type/name/full_name) with differing fields → to_replace."""
    desired = {_make_policy(function_name="cat.default.new_fn")}
    actual = {_make_policy(function_name="cat.default.old_fn")}

    diff = compute_policy_diff(desired, actual, _resolver(), _change_logger())
    assert diff.to_create == set()
    assert diff.to_replace == desired


def test_policy_differ_ignores_actual_only_policies():
    """Policies in actual but not desired are silently skipped (no delete)."""
    desired: set[Policy] = set()
    actual = {_make_policy()}

    diff = compute_policy_diff(desired, actual, _resolver(), _change_logger())
    assert diff == PolicyDiff()


def test_policy_differ_distinguishes_policies_by_securable():
    """Same policy name on different securables are treated as distinct."""
    desired = {
        _make_policy(securable_full_name="cat.s.t1"),
        _make_policy(securable_full_name="cat.s.t2"),
    }
    actual = {_make_policy(securable_full_name="cat.s.t1")}

    diff = compute_policy_diff(desired, actual, _resolver(), _change_logger())
    assert diff.to_replace == set()  # t1 matches identically
    assert len(diff.to_create) == 1
    (created,) = diff.to_create
    assert created.securable_full_name == "cat.s.t2"


def test_policy_differ_treats_to_principals_change_as_replace():
    desired = {_make_policy(to_principals=(_resolved("analysts"), _resolved("scientists")))}
    actual = {_make_policy(to_principals=(_resolved("analysts"),))}

    diff = compute_policy_diff(desired, actual, _resolver(), _change_logger())
    assert diff.to_replace == desired


def test_policy_differ_treats_when_condition_change_as_replace():
    desired = {_make_policy(when_condition="has_tag('env')")}
    actual = {_make_policy(when_condition=None)}

    diff = compute_policy_diff(desired, actual, _resolver(), _change_logger())
    assert diff.to_replace == desired


def test_policy_differ_treats_comment_change_as_replace():
    """A change to Policy.comment triggers a replace on the same identity."""
    desired = {_make_policy(comment="new description")}
    actual = {_make_policy(comment="old description")}

    diff = compute_policy_diff(desired, actual, _resolver(), _change_logger())
    assert diff.to_replace == desired


def test_policy_differ_populates_old_policies_on_replace():
    """The prior actual-state policy is captured in diff.old_policies, keyed by
    identity, so the executor can pass it to the logger for a per-field diff."""
    old = _make_policy(function_name="cat.default.old_fn")
    new = _make_policy(function_name="cat.default.new_fn")
    desired = {new}
    actual = {old}

    diff = compute_policy_diff(desired, actual, _resolver(), _change_logger())

    identity = (new.securable_type, new.securable_full_name, new.name)
    assert diff.old_policies[identity] == old


def test_policy_differ_old_policies_empty_when_no_replacements():
    """Pure-create diffs leave diff.old_policies empty."""
    diff = compute_policy_diff({_make_policy()}, set(), _resolver(), _change_logger())
    assert diff.old_policies == {}


# ---------------------------------------------------------------------------
# Unresolvable principals: per-principal drop, actual-side warning vs config-side fatal
# ---------------------------------------------------------------------------


def test_policy_differ_warns_and_drops_unresolvable_actual_principal_keeping_policy():
    """An ACTUAL policy with one resolvable and one unresolvable identifier-only
    principal keeps the policy but drops only the unresolvable principal: a
    non-fatal warning is logged, no error, and the surviving policy carries just
    the resolvable principal. A desired policy referencing only the resolvable
    principal therefore matches it exactly — no to_create, no to_replace."""
    good = _resolved("analysts")
    actual = {
        _make_policy(
            to_principals=(
                Principal(PrincipalType.UNKNOWN, identifier="analysts"),
                Principal(PrincipalType.UNKNOWN, identifier="unresolvable-uuid"),
            ),
        )
    }
    desired = {_make_policy(to_principals=(good,))}
    change_logger = _change_logger()

    diff = compute_policy_diff(
        desired,
        actual,
        _selective_resolver({"analysts": good}),
        change_logger,
    )

    assert change_logger.has_errors is False
    assert len(change_logger.warnings) == 1
    # Policy survived in actual with only the resolvable principal → matches desired.
    assert diff.to_create == set()
    assert diff.to_replace == set()


def test_policy_differ_retains_policy_when_all_actual_principals_unresolvable():
    """An ACTUAL policy whose only principal is unresolvable is retained with an
    empty to_principals (not treated as absent). A desired policy with empty
    to_principals matches it, so no to_create/to_replace is produced, and only a
    warning (no error) is logged."""
    actual = {
        _make_policy(
            to_principals=(Principal(PrincipalType.UNKNOWN, identifier="unresolvable-uuid"),),
        )
    }
    desired = {_make_policy(to_principals=())}
    change_logger = _change_logger()

    diff = compute_policy_diff(
        desired,
        actual,
        _selective_resolver({}),
        change_logger,
    )

    assert change_logger.has_errors is False
    assert len(change_logger.warnings) == 1
    assert diff.to_create == set()
    assert diff.to_replace == set()


def test_policy_differ_config_side_unresolvable_principal_is_fatal():
    """A DESIRED policy whose config-side (name-only) principal cannot be resolved
    logs a fatal error — config typos must still fail the run."""
    desired = {
        _make_policy(
            to_principals=(Principal(PrincipalType.UNKNOWN, name="typo_group"),),
        )
    }
    change_logger = _change_logger()

    compute_policy_diff(desired, set(), _failing_resolver(), change_logger)

    assert change_logger.has_errors is True


def test_policy_differ_suppresses_warning_for_ignored_unresolvable_actual_principal():
    """An unresolvable actual-state principal whose identifier is in
    ignore_unresolvable is still dropped from the policy, but its resolution-failure
    warning is suppressed — no warning, no error — and the policy is retained."""
    ignored_id = "unresolvable-uuid"
    actual = {
        _make_policy(
            to_principals=(Principal(PrincipalType.UNKNOWN, identifier=ignored_id),),
        )
    }
    desired = {_make_policy(to_principals=())}
    change_logger = _change_logger()

    diff = compute_policy_diff(
        desired,
        actual,
        _failing_resolver(),
        change_logger,
        ignore_unresolvable=frozenset({ignored_id}),
    )

    assert change_logger.has_errors is False
    assert change_logger.warnings == []
    # Policy retained with empty principals → matches the empty-principal desired.
    assert diff.to_create == set()
    assert diff.to_replace == set()
