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
from uc_declarative_abac.principals import ensure_resolved
from uc_declarative_abac.privileges.state import (
    PrivilegeDiff,
    SecurablePrivilege,
)
from uc_declarative_abac.types import SecurableType


def _build_grant_sql(priv: SecurablePrivilege) -> str:
    """Build a GRANT SQL statement for a single privilege."""
    quoted = quote_securable(priv.securable_full_name)
    principal = ensure_resolved(priv.principal)
    return (
        f"GRANT {priv.privilege_type.upper()} "
        f"ON {priv.securable_type.value} {quoted} "
        f"TO `{principal.identifier}`"
    )


def _build_revoke_sql(priv: SecurablePrivilege) -> str:
    """Build a REVOKE SQL statement for a single privilege."""
    quoted = quote_securable(priv.securable_full_name)
    principal = ensure_resolved(priv.principal)
    return (
        f"REVOKE {priv.privilege_type.upper()} "
        f"ON {priv.securable_type.value} {quoted} "
        f"FROM `{principal.identifier}`"
    )


def _privilege_sort_key(priv: SecurablePrivilege) -> tuple:
    return (priv.securable_type.value, priv.securable_full_name)


def _bucket_by_sec_type(
    privileges: set[SecurablePrivilege],
) -> dict[SecurableType, list[SecurablePrivilege]]:
    """Bucket privileges by securable_type for parallel batching."""
    buckets: dict[SecurableType, list[SecurablePrivilege]] = defaultdict(list)
    for p in privileges:
        buckets[p.securable_type].append(p)
    for sec_type in buckets:
        buckets[sec_type].sort(key=_privilege_sort_key)
    return buckets


def _run_privilege_batch(
    uc_helper: UnityCatalogHelper,
    privileges: list[SecurablePrivilege],
    *,
    is_grant: bool,
    change_logger: ChangeLogger,
    dry_run: bool,
    max_workers: int,
) -> list[str]:
    """Execute one (sec_type, change_type) batch of grants or revokes in parallel.

    Streams per-item logs via ``on_complete``; returns successful statements in input order.
    """
    build_sql = _build_grant_sql if is_grant else _build_revoke_sql
    work_items: list[tuple[SecurablePrivilege, str]] = [
        (priv, build_sql(priv)) for priv in privileges
    ]

    def worker(item: tuple[SecurablePrivilege, str]) -> None:
        _priv, stmt = item
        if not dry_run:
            uc_helper.execute_sql(stmt)

    def on_complete(item: tuple[SecurablePrivilege, str], _result, error) -> None:
        priv, stmt = item
        if error is not None:
            change_logger.log_error(ExecutionError(context=stmt, exception=error))
            return
        if is_grant:
            change_logger.log_grant(priv)
        else:
            change_logger.log_revoke(priv)

    results = parallel_for_each(
        work_items, worker, max_workers=max_workers, on_complete=on_complete,
    )
    if dry_run:
        return []
    return [stmt for (_priv, stmt), _result, error in results if error is None]


def execute_privilege_diff(
    uc_helper: UnityCatalogHelper,
    diff: PrivilegeDiff,
    change_logger: ChangeLogger,
    dry_run: bool = False,
    max_parallel_changes: int = 8,
) -> list[str]:
    """Generate and execute GRANT/REVOKE SQL from a PrivilegeDiff.

    Within each (securable_type, change_type) bundle, items run in parallel up to
    ``max_parallel_changes`` workers. Dry-run forces sequential execution.
    Principal identifiers are read directly from the Principal object on each
    SecurablePrivilege.
    Logs each change after successful execution (or unconditionally in dry-run mode).
    Returns the list of SQL statements executed (empty in dry-run mode).
    """
    workers = 1 if dry_run else max_parallel_changes
    statements: list[str] = []

    grants_by_type = _bucket_by_sec_type(diff.to_grant)
    for sec_type in sorted(grants_by_type, key=lambda t: t.value):
        statements.extend(_run_privilege_batch(
            uc_helper, grants_by_type[sec_type],
            is_grant=True,
            change_logger=change_logger, dry_run=dry_run, max_workers=workers,
        ))

    revokes_by_type = _bucket_by_sec_type(diff.to_revoke)
    for sec_type in sorted(revokes_by_type, key=lambda t: t.value):
        statements.extend(_run_privilege_batch(
            uc_helper, revokes_by_type[sec_type],
            is_grant=False,
            change_logger=change_logger, dry_run=dry_run, max_workers=workers,
        ))

    return statements
