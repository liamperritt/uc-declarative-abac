from __future__ import annotations

from uc_abac_governor.configs.models import (
    BaseFgacPolicyConfig,
    PolicyColumnConfig,
    ResourcesConfig,
)
from uc_abac_governor.policies.state import Policy
from uc_abac_governor.principals.state import Principal
from uc_abac_governor.types import PolicyType, PrincipalType, SecurableType


_WILDCARD = "*"


def compile_desired_policies(config: ResourcesConfig) -> set[Policy]:
    """Walk the resolved config and emit Policy entries for all mask and filter policies.

    Grant policies are handled by the privileges domain and are ignored here.
    """
    policies: set[Policy] = set()
    for catalog in config.catalogs.values():
        for p in catalog.policies or []:
            if isinstance(p, BaseFgacPolicyConfig):
                policies.add(_build_policy(SecurableType.CATALOG, catalog.full_name, p))
        for schema in catalog.schemas or []:
            for p in schema.policies or []:
                if isinstance(p, BaseFgacPolicyConfig):
                    policies.add(_build_policy(SecurableType.SCHEMA, schema.full_name, p))
            for table in schema.tables or []:
                for p in table.policies or []:
                    if isinstance(p, BaseFgacPolicyConfig):
                        policies.add(_build_policy(SecurableType.TABLE, table.full_name, p))
    return policies


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
        when_condition=_render_when(policy.has_tags),
        match_columns=match_columns,
        on_column=on_column,
        using_columns=using_columns,
        comment=policy.comment,
    )


def _render_when(has_tags: dict[str, str] | None) -> str | None:
    if not has_tags:
        return None
    return _render_tag_expr(has_tags)


def _render_tag_expr(tags: dict[str, str]) -> str:
    parts = [_render_tag_atom(k, v) for k, v in sorted(tags.items())]
    return " AND ".join(parts)


def _render_tag_atom(key: str, value: str) -> str:
    if value == _WILDCARD:
        return f"has_tag('{key}')"
    return f"has_tag_value('{key}', '{value}')"


def _build_match_columns(
    columns: list[PolicyColumnConfig] | None,
) -> tuple[tuple[str, str], ...]:
    if not columns:
        return ()
    return tuple(
        (col.alias, _render_tag_expr(col.has_tags or {}))
        for col in columns
    )


def _split_columns(
    policy: BaseFgacPolicyConfig,
    columns: list[PolicyColumnConfig] | None,
) -> tuple[str | None, tuple[str, ...]]:
    if not columns:
        return None, ()
    if policy.type == PolicyType.MASK:
        return columns[0].alias, tuple(col.alias for col in columns[1:])
    return None, tuple(col.alias for col in columns)
