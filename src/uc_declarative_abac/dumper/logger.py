"""Progress logging for ``uc-abac dump``."""

from __future__ import annotations

import logging

from uc_declarative_abac.orchestrator import ActualState
from uc_declarative_abac.utils import ExecutionError

_default_logger = logging.getLogger("uc_declarative_abac")


class DumpLogger:
    """Logs dump progress in the same visual style as the deploy ChangeLogger.

    Calls that record table results (log_table_written, log_table_failed) run only
    from the main thread via parallel_for_each's on_complete callback, so no
    locking is needed for the internal state.
    """

    def __init__(
        self, *, dry_run: bool = False, logger: logging.Logger | None = None
    ) -> None:
        self._logger = logger or _default_logger
        self._dry_run = dry_run
        self._errors: list[ExecutionError] = []
        self._table_results: dict[str, int] = {}
        self._failed_tables: set[str] = set()

    @property
    def errors(self) -> list[ExecutionError]:
        """Return a copy of collected execution errors."""
        return list(self._errors)

    def log_banner(self) -> None:
        """Log the opening banner with title and underline."""
        title = (
            "UC Declarative ABAC (dump, dry run)"
            if self._dry_run
            else "UC Declarative ABAC (dump)"
        )
        self._logger.info("")
        self._logger.info(title)
        self._logger.info("=" * len(title))
        self._logger.info("")

    def log_section_header(self, name: str) -> None:
        """Log a section header with optional dry-run suffix and underline."""
        suffix = " (dry run)" if self._dry_run else ""
        header = f"{name}{suffix}"
        self._logger.info("")
        self._logger.info(header)
        self._logger.info("-" * len(header))

    def log_fetching_state(self) -> None:
        """Log that current state is being fetched."""
        self._logger.info(
            "  Fetching current state from workspace (this can take several minutes)..."
        )

    def log_fetched_state(self, state: ActualState) -> None:
        """Log fetched state summary with entity counts."""
        counts = (
            f"{len(state.securables)} securables, "
            f"{len(state.tags)} tags, "
            f"{len(state.privileges)} privileges, "
            f"{len(state.policies)} policies, "
            f"{len(state.governed_tags)} governed tags, "
            f"{len(state.domains)} domains, "
            f"{len(state.principals)} principals, "
            f"{len(state.groups)} groups"
        )
        self._logger.info(f"  Fetched current state: {counts}")

    def log_target_schema_exists(self, schema_full_name: str) -> None:
        """Log that the target schema already exists."""
        self._logger.info(f"  Using schema {schema_full_name}")

    def log_target_schema_created(self, schema_full_name: str) -> None:
        """Log that the target schema was created or would be created."""
        verb = "Would create" if self._dry_run else "Created"
        self._logger.info(f"  + {verb} target schema {schema_full_name}")

    def log_error(self, error: ExecutionError) -> None:
        """Collect an execution error and log it."""
        self._errors.append(error)
        self._logger.error(f"  ! Error: {error.context}: {error.exception}")

    def log_table_progress(
        self, table_full_name: str, rows_written: int, row_count: int
    ) -> None:
        """Log how far through a long-running table write the dump is."""
        self._logger.info(
            f"  > Writing to {table_full_name} ({rows_written} of {row_count} rows)"
        )

    def log_table_started(self, table_full_name: str, row_count: int) -> None:
        """Log that a table write has begun, as its first (zero-rows) progress line."""
        self.log_table_progress(table_full_name, 0, row_count)

    def log_batch(
        self,
        table_full_name: str,
        index: int,
        total: int,
        row_count: int,
        byte_count: int,
    ) -> None:
        """Log batch progress at DEBUG level."""
        kib = byte_count / 1024
        self._logger.debug(
            f"  {table_full_name}: batch {index}/{total} ({row_count} rows, {kib:.0f} KiB)"
        )

    def log_statement(self, statement: str) -> None:
        """Log an SQL statement at DEBUG level."""
        self._logger.debug(f"  {statement}")

    def log_table_written(
        self, table_full_name: str, row_count: int, batch_count: int
    ) -> None:
        """Log that a table was written and record the result."""
        verb = "Would write" if self._dry_run else "Wrote"
        self._logger.info(
            f"  + {verb} to {table_full_name} "
            f"({row_count} rows in {batch_count} batches)"
        )
        self._table_results[table_full_name] = row_count

    def log_table_failed(self, table_full_name: str, exception: Exception) -> None:
        """Log a table failure and record it as failed."""
        self.log_error(ExecutionError(context=table_full_name, exception=exception))
        self._failed_tables.add(table_full_name)

    def _table_result(self, name: str) -> str | None:
        if name in self._failed_tables:
            return "FAILED"
        if name in self._table_results:
            return f"{self._table_results[name]:,} rows"
        return None

    def _totals_line(self) -> str:
        written = len(self._table_results)
        rows = sum(self._table_results.values())
        verb = "would be written" if self._dry_run else "written"
        line = f"Summary: {written} tables {verb} ({rows:,} rows)"
        if self._failed_tables:
            line += f", {len(self._failed_tables)} failed"
        return line

    def log_summary(self, table_full_names: list[str]) -> None:
        """Log one aligned result line per table, then a totals line.

        Tables are listed in the given (``TABLE_SPECS``) order rather than completion
        order, so the end of the log is deterministic despite parallel writes.
        """
        self.log_section_header("Summary")
        width = max((len(name) for name in table_full_names), default=0)
        for name in table_full_names:
            result = self._table_result(name)
            if result is not None:
                self._logger.info(f"  {name.ljust(width)}  {result}")
        self._logger.info("")
        self._logger.info(self._totals_line())
