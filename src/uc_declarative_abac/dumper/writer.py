"""``dump_state``: fetch the actual state behind a config and write it to tables."""

from __future__ import annotations

import time
from functools import partial
from pathlib import Path
from typing import Literal

from databricks.sdk import WorkspaceClient
from databricks.sdk.errors import NotFound

from uc_declarative_abac.dumper.logger import DumpLogger
from uc_declarative_abac.dumper.sql import (
    InsertBatch,
    build_create_table_sql,
    build_insert_batches,
)
from uc_declarative_abac.dumper.tables import (
    TABLE_SPECS,
    DumpContext,
    TableSpec,
    build_dump_context,
)
from uc_declarative_abac.governed_tags import collect_referenced_tag_keys
from uc_declarative_abac.helpers import UnityCatalogHelper, WorkspaceHelper
from uc_declarative_abac.orchestrator import (
    ActualState,
    fetch_actual_state,
    load_config,
)
from uc_declarative_abac.utils import (
    ExecutionBatchError,
    ExecutionError,
    parallel_for_each,
    quote_securable,
)

DEFAULT_MAX_PARALLEL_TABLES = 8
DEFAULT_PROGRESS_INTERVAL_SECONDS = 10.0


def _ensure_target_schema(
    workspace_client: WorkspaceClient,
    uc_helper: UnityCatalogHelper,
    target_schema: str,
    logger: DumpLogger,
    dry_run: bool,
) -> None:
    """Create the target schema only when it is missing.

    Runs before the (slow) state fetch so a missing catalog or a permission problem
    fails fast. An existing schema gets no DDL at all; a missing one gets a plain
    ``CREATE SCHEMA``. The existence check is read-only, so it also runs in a dry run.
    """
    try:
        workspace_client.schemas.get(target_schema)
    except NotFound:
        if not dry_run:
            uc_helper.execute_sql(f"CREATE SCHEMA {quote_securable(target_schema)}")
        logger.log_target_schema_created(target_schema)
        return
    except Exception as exc:
        logger.log_error(
            ExecutionError(context=f"target schema {target_schema}", exception=exc)
        )
        raise
    logger.log_target_schema_exists(target_schema)


def _execute(
    statement: str, uc_helper: UnityCatalogHelper, logger: DumpLogger, dry_run: bool
) -> None:
    logger.log_statement(statement)
    if not dry_run:
        uc_helper.execute_sql(statement)


def _truncate_after_failure(
    table_full_name: str,
    failure: Exception,
    uc_helper: UnityCatalogHelper,
    logger: DumpLogger,
) -> None:
    """Empty a table whose INSERTs failed part-way.

    Without this the table would keep the batches that did land: a silently
    truncated snapshot that reads as complete. An empty table (alongside the run's
    non-zero exit) is unambiguous. If the TRUNCATE also fails, both errors are raised
    together so neither is lost.
    """
    statement = f"TRUNCATE TABLE {quote_securable(table_full_name)}"
    logger.log_statement(statement)
    try:
        uc_helper.execute_sql(statement)
    except Exception as truncate_exc:  # noqa: BLE001 — report alongside the original failure
        raise RuntimeError(
            f"{failure}; truncating the partially written table also failed: "
            f"{truncate_exc}"
        ) from failure


def _insert_batches(
    table_full_name: str,
    batches: list[InsertBatch],
    *,
    uc_helper: UnityCatalogHelper,
    logger: DumpLogger,
    dry_run: bool,
    progress_interval_seconds: float,
) -> None:
    """Run a table's INSERT batches in order, logging progress for long writes.

    After each batch, if ``progress_interval_seconds`` have passed since the table's
    last log line, the rows written so far are logged. Progress is only known at
    batch boundaries, and no line is logged once every row is in (the table's
    "Wrote to" line follows).
    """
    row_count = sum(batch.row_count for batch in batches)
    rows_written = 0
    last_logged = time.monotonic()
    for index, batch in enumerate(batches, start=1):
        logger.log_batch(
            table_full_name,
            index,
            len(batches),
            batch.row_count,
            len(batch.sql.encode("utf-8")),
        )
        _execute(batch.sql, uc_helper, logger, dry_run)
        rows_written += batch.row_count
        now = time.monotonic()
        if rows_written < row_count and now - last_logged >= progress_interval_seconds:
            logger.log_table_progress(table_full_name, rows_written, row_count)
            last_logged = now


def _write_table(
    spec: TableSpec,
    *,
    target_schema: str,
    state: ActualState,
    context: DumpContext,
    uc_helper: UnityCatalogHelper,
    logger: DumpLogger,
    dry_run: bool,
    progress_interval_seconds: float,
) -> tuple[int, int]:
    """Replace one table and load its rows; returns ``(row_count, batch_count)``.

    Runs on a worker thread. The table's statements run sequentially (CREATE first,
    then each INSERT batch) so there is never more than one writer per Delta table;
    parallelism is across tables only. If an INSERT fails after the CREATE succeeded,
    the table is truncated before the error propagates (see
    ``_truncate_after_failure``).
    """
    table_full_name = f"{target_schema}.{spec.name}"
    rows = spec.rows(state, context)
    logger.log_table_started(table_full_name, len(rows))
    batches = build_insert_batches(table_full_name, spec, rows)
    _execute(build_create_table_sql(table_full_name, spec), uc_helper, logger, dry_run)
    try:
        _insert_batches(
            table_full_name,
            batches,
            uc_helper=uc_helper,
            logger=logger,
            dry_run=dry_run,
            progress_interval_seconds=progress_interval_seconds,
        )
    except Exception as exc:
        _truncate_after_failure(table_full_name, exc, uc_helper, logger)
        raise
    return (len(rows), len(batches))


def _table_full_names(target_schema: str) -> list[str]:
    return [f"{target_schema}.{spec.name}" for spec in TABLE_SPECS]


def dump_state(
    workspace_client: WorkspaceClient,
    *,
    config_dir: Path,
    warehouse_id: str,
    target_schema: str,
    system_catalog: str = "system",
    ref_override_strategy: Literal["merge", "replace"] = "merge",
    max_parallel_tables: int = DEFAULT_MAX_PARALLEL_TABLES,
    dry_run: bool = False,
    progress_interval_seconds: float = DEFAULT_PROGRESS_INTERVAL_SECONDS,
) -> None:
    """Fetch the actual state behind the config and write it to the target schema.

    Each table in ``TABLE_SPECS`` is fully replaced (``CREATE OR REPLACE``) and
    reloaded, up to ``max_parallel_tables`` at a time. A failed table doesn't stop the
    others; all failures are raised together as ``ExecutionBatchError`` at the end.
    ``dry_run`` builds and logs every statement but executes none.
    A table still loading after ``progress_interval_seconds`` logs its rows written
    so far (at most once per interval).

    The ``WorkspaceHelper`` is built with ``manage_groups`` and
    ``manage_domain_owners`` set even when the config declares no groups: the full
    fetch needs the group and domain-owner id maps to read memberships, assumers, and
    domain owners (see ``fetch_actual_state``).
    """
    logger = DumpLogger(dry_run=dry_run)
    logger.log_banner()
    config = load_config(config_dir, ref_override_strategy)
    uc_helper = UnityCatalogHelper(
        workspace_client, warehouse_id, system_catalog=system_catalog
    )
    ws_helper = WorkspaceHelper(
        workspace_client, manage_groups=True, manage_domain_owners=True
    )
    _ensure_target_schema(workspace_client, uc_helper, target_schema, logger, dry_run)

    logger.log_fetching_state()
    state = fetch_actual_state(config, uc_helper, ws_helper)
    logger.log_fetched_state(state)
    context = build_dump_context(state, frozenset(collect_referenced_tag_keys(config)))

    def _on_complete(
        spec: TableSpec, result: tuple[int, int] | None, error: Exception | None
    ) -> None:
        table_full_name = f"{target_schema}.{spec.name}"
        if error is not None:
            logger.log_table_failed(table_full_name, error)
        elif result is not None:
            logger.log_table_written(table_full_name, *result)

    logger.log_section_header("Tables")
    parallel_for_each(
        list(TABLE_SPECS),
        partial(
            _write_table,
            target_schema=target_schema,
            state=state,
            context=context,
            uc_helper=uc_helper,
            logger=logger,
            dry_run=dry_run,
            progress_interval_seconds=progress_interval_seconds,
        ),
        max_workers=max_parallel_tables,
        on_complete=_on_complete,
    )
    logger.log_summary(_table_full_names(target_schema))
    if logger.errors:
        raise ExecutionBatchError(logger.errors)
