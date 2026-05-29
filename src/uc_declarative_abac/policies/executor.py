from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_declarative_abac.helpers.unity_catalog import UnityCatalogHelper
    from uc_declarative_abac.logger import ChangeLogger

from uc_declarative_abac.utils import ExecutionError, quote_securable as quote_securable
from uc_declarative_abac.policies.state import Policy, PolicyDiff
from uc_declarative_abac.principals.resolver import ensure_all_resolved
from uc_declarative_abac.principals.state import Principal
from uc_declarative_abac.types import PolicyType


def execute_policy_diff(
    uc_helper: UnityCatalogHelper,
    diff: PolicyDiff,
    change_logger: ChangeLogger,
    dry_run: bool = False,
) -> list[str]:
    """Generate and execute CREATE [OR REPLACE] POLICY SQL from a PolicyDiff.

    Logs each change after successful execution (or unconditionally in dry-run mode).
    Returns the list of SQL statements executed (empty in dry-run mode).
    """
    statements: list[str] = []

    for policy in sorted(diff.to_create, key=_policy_sort_key):
        if _run_statement(uc_helper, _build_policy_sql(policy, or_replace=False), change_logger, dry_run, statements):
            change_logger.log_policy_create(policy)

    for policy in sorted(diff.to_replace, key=_policy_sort_key):
        if _run_statement(uc_helper, _build_policy_sql(policy, or_replace=True), change_logger, dry_run, statements):
            change_logger.log_policy_replace(policy)

    return statements


def _policy_sort_key(policy: Policy) -> tuple:
    return (policy.securable_type.value, policy.securable_full_name, policy.name)


def _run_statement(
    uc_helper: UnityCatalogHelper,
    stmt: str,
    change_logger: ChangeLogger,
    dry_run: bool,
    statements: list[str],
) -> bool:
    """Execute the statement unless dry_run. Returns True if logging should proceed."""
    if dry_run:
        return True
    try:
        uc_helper.execute_sql(stmt)
    except Exception as exc:
        change_logger.log_error(ExecutionError(context=stmt, exception=exc))
        return False
    statements.append(stmt)
    return True


def _quote_principals(principals: tuple[Principal, ...]) -> str:
    resolved = ensure_all_resolved(principals)
    return ", ".join(f"`{p.identifier}`" for p in resolved)


def _build_policy_sql(policy: Policy, or_replace: bool) -> str:
    prefix = "CREATE OR REPLACE POLICY" if or_replace else "CREATE POLICY"
    body_type = "COLUMN MASK" if policy.policy_type == PolicyType.MASK else "ROW FILTER"

    lines = [
        f"{prefix} `{policy.name}`",
        f"ON {policy.securable_type.value} {quote_securable(policy.securable_full_name)}",
    ]
    if policy.comment:
        escaped = policy.comment.replace("'", "\\'")
        lines.append(f'COMMENT "{escaped}"')
    lines.extend([
        f"{body_type} {quote_securable(policy.function_name)}",
        f"TO {_quote_principals(policy.to_principals)}",
    ])
    if policy.except_principals:
        lines.append(f"EXCEPT {_quote_principals(policy.except_principals)}")
    lines.append("FOR TABLES")
    if policy.when_condition:
        lines.append(f"WHEN {policy.when_condition}")
    if policy.match_columns:
        match = ", ".join(f"{cond} AS {alias}" for alias, cond in policy.match_columns)
        lines.append(f"MATCH COLUMNS {match}")
    if policy.on_column:
        lines.append(f"ON COLUMN {policy.on_column}")
    if policy.using_columns:
        using = ", ".join(policy.using_columns)
        lines.append(f"USING COLUMNS ({using})")
    return "\n".join(lines)
