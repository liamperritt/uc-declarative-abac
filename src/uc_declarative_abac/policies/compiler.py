from __future__ import annotations

from collections.abc import Callable
from datetime import date, datetime

from uc_declarative_abac.configs import (
    BaseFgacPolicyConfig,
    PolicyColumnAliasConfig,
    PolicyColumnConfig,
    PolicyColumnConstantConfig,
    ResourcesConfig,
)
from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.policies.state import Policy
from uc_declarative_abac.principals import Principal
from uc_declarative_abac.types import (
    PolicyType,
    PrincipalType,
    SecurableType,
)
from uc_declarative_abac.utils import (
    ExecutionError,
    UngovernedTagError,
)

_WILDCARD = "*"


def compile_desired_policies(
    config: ResourcesConfig,
    governed_tag_names: set[str],
    change_logger: ChangeLogger,
) -> set[Policy]:
    """Walk the resolved config and emit Policy entries for all mask and filter policies.

    Grant policies are handled by the privileges domain and are ignored here.

    Every tag key referenced by a policy (at the policy level or in per-column
    ``has_tags``) must appear in ``governed_tag_names`` (the union of desired +
    actual governed tag names). Policies that reference an ungoverned key are
    dropped from the returned set and an ``UngovernedTagError`` is logged on
    ``change_logger`` for every offender.
    """
    policies: set[Policy] = set()
    for catalog in config.catalogs.values():
        for p in catalog.policies or []:
            if isinstance(p, BaseFgacPolicyConfig):
                built = _build_policy_if_valid(
                    SecurableType.CATALOG,
                    catalog.full_name,
                    p,
                    governed_tag_names,
                    change_logger,
                )
                if built is not None:
                    policies.add(built)
        for schema in catalog.schemas or []:
            for p in schema.policies or []:
                if isinstance(p, BaseFgacPolicyConfig):
                    built = _build_policy_if_valid(
                        SecurableType.SCHEMA,
                        schema.full_name,
                        p,
                        governed_tag_names,
                        change_logger,
                    )
                    if built is not None:
                        policies.add(built)
            for table in schema.tables or []:
                for p in table.policies or []:
                    if isinstance(p, BaseFgacPolicyConfig):
                        built = _build_policy_if_valid(
                            SecurableType.TABLE,
                            table.full_name,
                            p,
                            governed_tag_names,
                            change_logger,
                        )
                        if built is not None:
                            policies.add(built)
    return policies


def _build_policy_if_valid(
    securable_type: SecurableType,
    securable_full_name: str,
    policy: BaseFgacPolicyConfig,
    governed_tag_names: set[str],
    change_logger: ChangeLogger,
) -> Policy | None:
    """Validate every tag key referenced by the policy, logging errors for
    ungoverned keys and returning None if any were found."""
    ungoverned = _ungoverned_tag_keys(policy, governed_tag_names)
    if ungoverned:
        context = (
            f"Policy '{policy.name}' on {securable_type.value} {securable_full_name}"
        )
        for key in sorted(ungoverned):
            change_logger.log_error(
                ExecutionError(
                    context=context,
                    exception=UngovernedTagError(
                        f"{context} references ungoverned tag '{key}'"
                    ),
                )
            )
        return None
    return _build_policy(securable_type, securable_full_name, policy)


def _ungoverned_tag_keys(
    policy: BaseFgacPolicyConfig,
    governed_tag_names: set[str],
) -> set[str]:
    """Collect every tag key the policy references (policy-level + per-column)
    that is not in ``governed_tag_names``."""
    referenced: set[str] = set()
    referenced |= set(policy.has_tags or {})
    referenced |= set(policy.has_any_of_tags or {})
    referenced |= set(policy.has_none_of_tags or {})
    # For identity-attribute tag-matches the dict VALUES are governed tag keys on
    # the resource (the keys are identity-attribute names, not tags).
    referenced |= set((policy.has_identity_attribute_tag_matches or {}).values())
    referenced |= set((policy.has_any_of_identity_attribute_tag_matches or {}).values())
    referenced |= set((policy.has_none_of_identity_attribute_tag_matches or {}).values())
    for col in policy.columns or []:
        if isinstance(col, PolicyColumnAliasConfig):
            referenced |= set(col.has_tags or {})
            referenced |= set(col.has_any_of_tags or {})
            referenced |= set(col.has_none_of_tags or {})
    return referenced - governed_tag_names


def _build_policy(
    securable_type: SecurableType,
    securable_full_name: str,
    policy: BaseFgacPolicyConfig,
) -> Policy:
    match_columns = _build_match_columns(policy.columns)
    on_column, using_columns = _split_columns(policy, policy.columns)
    return Policy(
        securable_type=securable_type,
        securable_full_name=securable_full_name,
        name=policy.name,
        policy_type=policy.type,
        function_name=policy.function,
        to_principals=tuple(
            Principal(principal_type=PrincipalType.UNKNOWN, name=n) for n in policy.to
        ),
        except_principals=tuple(
            Principal(principal_type=PrincipalType.UNKNOWN, name=n)
            for n in (policy.exceptions or [])
        ),
        when_condition=_render_when(policy),
        match_columns=match_columns,
        on_column=on_column,
        using_columns=using_columns,
        comment=policy.comment,
        for_securable_type=policy.for_securable_type or SecurableType.TABLE,
    )


def _render_when(policy: BaseFgacPolicyConfig) -> str | None:
    """Render the policy's WHEN clause. Combines the tag predicate, the
    context-attribute predicate family (mask and filter), and the two
    identity-attribute predicate families (mask-only; always empty on filters),
    AND-joining every non-empty sub-expression. Each family contributes an AND
    group (``has_*``), an OR group (``has_any_of_*``), and a NOR group
    (``has_none_of_*``)."""
    parts = [
        _render_match_expr(
            policy.has_tags,
            policy.has_any_of_tags,
            policy.has_none_of_tags,
            _render_tag_atom,
        ),
        _render_match_expr(
            policy.has_context_attributes,
            policy.has_any_of_context_attributes,
            policy.has_none_of_context_attributes,
            _render_context_attribute_atom,
        ),
        _render_match_expr(
            policy.has_identity_attributes,
            policy.has_any_of_identity_attributes,
            policy.has_none_of_identity_attributes,
            _render_identity_attribute_atom,
        ),
        _render_match_expr(
            policy.has_identity_attribute_tag_matches,
            policy.has_any_of_identity_attribute_tag_matches,
            policy.has_none_of_identity_attribute_tag_matches,
            _render_identity_attribute_tag_match_atom,
        ),
    ]
    joined = " AND ".join(p for p in parts if p)
    return joined or None


def _render_match_expr(
    has_all: dict[str, str] | None,
    has_any: dict[str, str] | None,
    has_none: dict[str, str] | None,
    atom: Callable[[str, str], str],
) -> str | None:
    """Combine the AND group (``has_all``), the OR group (``has_any``), and the NOR
    group (``has_none``) into one boolean expression, rendering each entry via
    ``atom``. AND atoms come first (sorted by key); the OR group is appended next,
    parenthesised when it has more than one atom; the NOR group is appended last,
    each atom negated (``NOT ...``) and sorted by key. Returns None when all three
    groups are empty."""
    parts = [atom(k, v) for k, v in sorted((has_all or {}).items())]
    or_atoms = [atom(k, v) for k, v in sorted((has_any or {}).items())]
    if or_atoms:
        or_expr = " OR ".join(or_atoms)
        parts.append(f"({or_expr})" if len(or_atoms) > 1 else or_expr)
    parts.extend(f"NOT {atom(k, v)}" for k, v in sorted((has_none or {}).items()))
    if not parts:
        return None
    return " AND ".join(parts)


def _quote(value: str) -> str:
    """Render a string as a single-quoted SQL literal, escaping embedded single
    quotes by doubling them (e.g. ``O'Brien`` → ``'O''Brien'``) so a tag/attribute
    key or value containing a quote can't break out of the WHEN-clause atom."""
    return "'" + value.replace("'", "''") + "'"


def _render_tag_atom(key: str, value: str) -> str:
    if value == _WILDCARD:
        return f"has_tag({_quote(key)})"
    return f"has_tag_value({_quote(key)}, {_quote(value)})"


def _render_context_attribute_atom(key: str, value: str) -> str:
    if value == _WILDCARD:
        return f"has_context_attribute({_quote(key)})"
    return f"has_context_attribute_value({_quote(key)}, {_quote(value)})"


def _render_identity_attribute_atom(key: str, value: str) -> str:
    return f"has_identity_attribute_value({_quote(key)}, {_quote(value)})"


def _render_identity_attribute_tag_match_atom(key: str, value: str) -> str:
    return f"has_identity_attribute_tag_match({_quote(key)}, {_quote(value)})"


def _build_match_columns(
    columns: list[PolicyColumnConfig] | None,
) -> tuple[tuple[str, str], ...]:
    """Build the MATCH COLUMNS entries. Only alias columns are tag-matched;
    constant columns contribute no entry. An alias column with no tag predicate
    matches every column via a ``TRUE`` condition (the secure-by-default pattern)."""
    if not columns:
        return ()
    return tuple(
        (
            col.alias,
            _render_match_expr(
                col.has_tags, col.has_any_of_tags, col.has_none_of_tags, _render_tag_atom
            )
            or "TRUE",
        )
        for col in columns
        if isinstance(col, PolicyColumnAliasConfig)
    )


def _render_sql_constant(value: bool | float | str | date | datetime) -> str:
    """Render a constant column value as a SQL literal for the USING COLUMNS clause.

    That clause only accepts plain literals (strings, numbers, booleans) and column
    references — NOT typed-literal constructors like ``DATE '...'`` (which the parser
    reads as a column identifier followed by extra input). So dates and timestamps are
    rendered as plain single-quoted strings; the target function's parameter type drives
    any cast. Timestamps drop their timezone.

    bool → TRUE/FALSE, int/float → bare numeric, datetime → '2026-01-01 12:30:00',
    date → '2026-01-01', str → escaped single-quoted string.
    Order matters: bool is a subclass of int, and datetime of date.
    """
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, datetime):
        text = value.strftime("%Y-%m-%d %H:%M:%S")
    elif isinstance(value, date):
        text = value.isoformat()
    else:
        text = value
    escaped = text.replace("'", "''")
    return f"'{escaped}'"


def _using_token(col: PolicyColumnConfig) -> str:
    """The token a column contributes to USING COLUMNS — a SQL literal for a
    constant column, or the column alias otherwise."""
    if isinstance(col, PolicyColumnConstantConfig):
        return _render_sql_constant(col.constant)
    return col.alias


def _split_columns(
    policy: BaseFgacPolicyConfig,
    columns: list[PolicyColumnConfig] | None,
) -> tuple[str | None, tuple[str, ...]]:
    """Split columns into (on_column, using_columns), preserving declaration order.

    For MASK the first column is the masked column (ON COLUMN) and is always an
    alias (enforced by config validation); the rest become USING COLUMNS args.
    For FILTER there is no ON COLUMN and all columns become USING args. Constant
    columns are rendered as SQL literals.
    """
    if not columns:
        return None, ()
    if policy.type == PolicyType.MASK:
        return columns[0].alias, tuple(_using_token(col) for col in columns[1:])
    return None, tuple(_using_token(col) for col in columns)
