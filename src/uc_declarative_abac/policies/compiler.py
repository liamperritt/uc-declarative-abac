from __future__ import annotations

from datetime import date, datetime

from uc_declarative_abac.configs import (
    BaseFgacPolicyConfig,
    PolicyColumnAliasConfig,
    PolicyColumnConfig,
    PolicyColumnConstantConfig,
    ResourcesConfig,
)
from uc_declarative_abac.utils import (
    ExecutionError,
    UngovernedTagError,
)
from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.policies.state import Policy
from uc_declarative_abac.principals import Principal
from uc_declarative_abac.types import (
    PolicyType,
    PrincipalType,
    SecurableType,
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
                    SecurableType.CATALOG, catalog.full_name, p,
                    governed_tag_names, change_logger,
                )
                if built is not None:
                    policies.add(built)
        for schema in catalog.schemas or []:
            for p in schema.policies or []:
                if isinstance(p, BaseFgacPolicyConfig):
                    built = _build_policy_if_valid(
                        SecurableType.SCHEMA, schema.full_name, p,
                        governed_tag_names, change_logger,
                    )
                    if built is not None:
                        policies.add(built)
            for table in schema.tables or []:
                for p in table.policies or []:
                    if isinstance(p, BaseFgacPolicyConfig):
                        built = _build_policy_if_valid(
                            SecurableType.TABLE, table.full_name, p,
                            governed_tag_names, change_logger,
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
        context = f"Policy '{policy.name}' on {securable_type.value} {securable_full_name}"
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
    for col in policy.columns or []:
        if isinstance(col, PolicyColumnAliasConfig):
            referenced |= set(col.has_tags or {})
            referenced |= set(col.has_any_of_tags or {})
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
            Principal(principal_type=PrincipalType.UNKNOWN, name=n) for n in (policy.exceptions or [])
        ),
        when_condition=_render_when(policy.has_tags, policy.has_any_of_tags),
        match_columns=match_columns,
        on_column=on_column,
        using_columns=using_columns,
        comment=policy.comment,
        for_securable_type=policy.for_securable_type or SecurableType.TABLE,
    )


def _render_when(
    has_tags: dict[str, str] | None,
    has_any_of_tags: dict[str, str] | None,
) -> str | None:
    return _render_match_expr(has_tags, has_any_of_tags)


def _render_match_expr(
    has_tags: dict[str, str] | None,
    has_any_of_tags: dict[str, str] | None,
) -> str | None:
    """Combine the AND group (``has_tags``) and the OR group (``has_any_of_tags``)
    into one boolean tag expression. AND atoms come first (sorted by key); the OR
    group is appended last, parenthesised when it has more than one atom. Returns
    None when both groups are empty."""
    parts = [_render_tag_atom(k, v) for k, v in sorted((has_tags or {}).items())]
    or_atoms = [_render_tag_atom(k, v) for k, v in sorted((has_any_of_tags or {}).items())]
    if or_atoms:
        or_expr = " OR ".join(or_atoms)
        parts.append(f"({or_expr})" if len(or_atoms) > 1 else or_expr)
    if not parts:
        return None
    return " AND ".join(parts)


def _render_tag_atom(key: str, value: str) -> str:
    if value == _WILDCARD:
        return f"has_tag('{key}')"
    return f"has_tag_value('{key}', '{value}')"


def _build_match_columns(
    columns: list[PolicyColumnConfig] | None,
) -> tuple[tuple[str, str], ...]:
    """Build the MATCH COLUMNS entries. Only alias columns are tag-matched;
    constant columns contribute no entry."""
    if not columns:
        return ()
    return tuple(
        (col.alias, _render_match_expr(col.has_tags, col.has_any_of_tags) or "")
        for col in columns
        if isinstance(col, PolicyColumnAliasConfig)
    )


def _render_sql_constant(value: bool | int | float | str | date | datetime) -> str:
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
