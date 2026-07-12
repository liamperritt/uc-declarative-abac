from __future__ import annotations

import logging
import sys
from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_declarative_abac.helpers import UnityCatalogHelper
    from uc_declarative_abac.logger import ChangeLogger

from uc_declarative_abac.utils import (
    ExecutionError,
    InteractiveConfirmationRequiredError,
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

_logger = logging.getLogger("uc_declarative_abac")


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
    lines.append(f"FOR {policy.for_securable_type.value}S")
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


def _build_drop_policy_sql(policy: Policy) -> str:
    return (
        f"DROP POLICY `{policy.name}` "
        f"ON {policy.securable_type.value} {quote_securable(policy.securable_full_name)}"
    )


def _prompt_delete_confirmation(policies: list[Policy]) -> bool:
    """Show the policies slated for deletion and require interactive confirmation.

    Accepts ``y``/``yes`` (case-insensitive); anything else aborts. Re-raises
    ``EOFError`` (e.g. a non-TTY stream) as ``InteractiveConfirmationRequiredError``
    so CI contexts get a clear "set --force" directive instead of a silent skip.
    """
    print(f"\nAbout to delete {len(policies)} policy(ies):")
    for policy in policies:
        print(
            f"  - {policy.policy_type.value} policy '{policy.name}' on "
            f"{policy.securable_type.value} {policy.securable_full_name}"
        )
    print()
    try:
        response = input(
            "This is irreversible and will remove masking/filtering from the "
            "affected securables. Confirm [y/N]: "
        )
    except EOFError as exc:
        raise InteractiveConfirmationRequiredError(
            "Cannot prompt for confirmation in a non-interactive context. "
            "Set --force to auto-confirm destructive actions."
        ) from exc
    return response.strip().lower() in {"y", "yes"}


def _execute_policy_deletes(
    uc_helper: UnityCatalogHelper,
    diff: PolicyDiff,
    change_logger: ChangeLogger,
    *,
    dry_run: bool,
    force: bool,
    max_workers: int,
) -> list[str]:
    """Drop each policy in ``to_delete``, gated by ``--force`` or interactive confirmation.

    Dry-run logs the deletions without prompting or issuing SQL. Otherwise, unless
    ``force`` is set, an interactive confirmation is required; a declined prompt
    aborts the whole run (``sys.exit(1)``), mirroring governed-tag deletion.
    """
    if not diff.to_delete:
        return []
    policies_sorted = sorted(diff.to_delete, key=_policy_sort_key)
    if dry_run:
        for policy in policies_sorted:
            change_logger.log_policy_delete(policy)
        return []
    if not force and not _prompt_delete_confirmation(policies_sorted):
        _logger.info("Policy deletion cancelled — aborting run.")
        sys.exit(1)

    work_items = [(policy, _build_drop_policy_sql(policy)) for policy in policies_sorted]

    def worker(item: tuple[Policy, str]) -> None:
        _policy, stmt = item
        uc_helper.execute_sql(stmt)

    def on_complete(item: tuple[Policy, str], _result, error) -> None:
        policy, stmt = item
        if error is not None:
            change_logger.log_error(ExecutionError(context=stmt, exception=error))
            return
        change_logger.log_policy_delete(policy)

    results = parallel_for_each(
        work_items, worker, max_workers=max_workers, on_complete=on_complete,
    )
    return [stmt for (_policy, stmt), _result, error in results if error is None]


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
    old_policies: dict[tuple, Policy],
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
            old = old_policies.get(
                (policy.securable_type, policy.securable_full_name, policy.name)
            )
            change_logger.log_policy_replace(policy, old)
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
    force: bool = False,
    max_parallel_changes: int = 8,
) -> list[str]:
    """Generate and execute CREATE [OR REPLACE] / DROP POLICY SQL from a PolicyDiff.

    Within each (securable_type, change_type) bundle, items run in parallel up to
    ``max_parallel_changes`` workers. Dry-run forces sequential execution.
    Logs each change after successful execution (or unconditionally in dry-run mode).
    Returns the list of SQL statements executed (empty in dry-run mode).

    Phases run create → replace → delete. Deletions (``diff.to_delete``, populated
    only when policy deletion is enabled) are destructive and gated: unless
    ``force`` is set, an interactive confirmation is required, and a declined
    prompt aborts the whole run.
    """
    workers = 1 if dry_run else max_parallel_changes
    statements: list[str] = []

    creates_by_type = _bucket_by_sec_type(diff.to_create)
    for sec_type in sorted(creates_by_type, key=lambda t: t.value):
        statements.extend(_run_policy_batch(
            uc_helper, creates_by_type[sec_type], diff.old_policies,
            or_replace=False,
            change_logger=change_logger, dry_run=dry_run, max_workers=workers,
        ))

    replaces_by_type = _bucket_by_sec_type(diff.to_replace)
    for sec_type in sorted(replaces_by_type, key=lambda t: t.value):
        statements.extend(_run_policy_batch(
            uc_helper, replaces_by_type[sec_type], diff.old_policies,
            or_replace=True,
            change_logger=change_logger, dry_run=dry_run, max_workers=workers,
        ))

    statements.extend(_execute_policy_deletes(
        uc_helper, diff, change_logger,
        dry_run=dry_run, force=force, max_workers=workers,
    ))

    return statements
