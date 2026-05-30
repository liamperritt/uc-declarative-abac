from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_declarative_abac.helpers import UnityCatalogHelper
    from uc_declarative_abac.logger import ChangeLogger

from uc_declarative_abac.utils import (
    ExecutionError,
    parallel_for_each,
    quote_securable,
)
from uc_declarative_abac.policies.state import (
    Policy,
    PolicyDiff,
)
from uc_declarative_abac.principals import (
    ensure_all_resolved,
    Principal,
)
from uc_declarative_abac.types import PolicyType, SecurableType


def _policy_sort_key(policy: Policy) -> tuple:
    return (policy.securable_type.value, policy.securable_full_name, policy.name)


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


def _bucket_by_sec_type(policies: set[Policy]) -> dict[SecurableType, list[Policy]]:
    """Bucket policies by securable_type for parallel batching."""
    buckets: dict[SecurableType, list[Policy]] = defaultdict(list)
    for p in policies:
        buckets[p.securable_type].append(p)
    for sec_type in buckets:
        buckets[sec_type].sort(key=_policy_sort_key)
    return buckets


def _run_policy_batch(
    uc_helper: UnityCatalogHelper,
    policies: list[Policy],
    *,
    or_replace: bool,
    change_logger: ChangeLogger,
    dry_run: bool,
    max_workers: int,
) -> list[str]:
    """Execute one (sec_type, change_type) batch of policies in parallel.

    Streams per-item logs via ``on_complete``; returns successful statements
    in input order.
    """
    work_items: list[tuple[Policy, str]] = [
        (policy, _build_policy_sql(policy, or_replace=or_replace)) for policy in policies
    ]

    def worker(item: tuple[Policy, str]) -> None:
        _policy, stmt = item
        if not dry_run:
            uc_helper.execute_sql(stmt)

    def on_complete(item: tuple[Policy, str], _result, error) -> None:
        policy, stmt = item
        if error is not None:
            change_logger.log_error(ExecutionError(context=stmt, exception=error))
            return
        if or_replace:
            change_logger.log_policy_replace(policy)
        else:
            change_logger.log_policy_create(policy)

    results = parallel_for_each(
        work_items, worker, max_workers=max_workers, on_complete=on_complete,
    )
    if dry_run:
        return []
    return [stmt for (_policy, stmt), _result, error in results if error is None]


def execute_policy_diff(
    uc_helper: UnityCatalogHelper,
    diff: PolicyDiff,
    change_logger: ChangeLogger,
    dry_run: bool = False,
    max_parallel_changes: int = 8,
) -> list[str]:
    """Generate and execute CREATE [OR REPLACE] POLICY SQL from a PolicyDiff.

    Within each (securable_type, change_type) bundle, items run in parallel up to
    ``max_parallel_changes`` workers. Dry-run forces sequential execution.
    Logs each change after successful execution (or unconditionally in dry-run mode).
    Returns the list of SQL statements executed (empty in dry-run mode).
    """
    workers = 1 if dry_run else max_parallel_changes
    statements: list[str] = []

    creates_by_type = _bucket_by_sec_type(diff.to_create)
    for sec_type in sorted(creates_by_type, key=lambda t: t.value):
        statements.extend(_run_policy_batch(
            uc_helper, creates_by_type[sec_type],
            or_replace=False,
            change_logger=change_logger, dry_run=dry_run, max_workers=workers,
        ))

    replaces_by_type = _bucket_by_sec_type(diff.to_replace)
    for sec_type in sorted(replaces_by_type, key=lambda t: t.value):
        statements.extend(_run_policy_batch(
            uc_helper, replaces_by_type[sec_type],
            or_replace=True,
            change_logger=change_logger, dry_run=dry_run, max_workers=workers,
        ))

    return statements
