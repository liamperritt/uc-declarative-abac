"""SQL rendering for ``uc-abac dump``: table DDL and chunked INSERT statements."""

from __future__ import annotations

from dataclasses import dataclass

from uc_declarative_abac.dumper.tables import Row, RowValue, StructValue, TableSpec
from uc_declarative_abac.utils import quote_securable, sql_string_literal

INSERT_MAX_ROWS = 1000
INSERT_MAX_BYTES = 4 * 1024 * 1024
_ROW_SEPARATOR = ",\n"
_ROW_SEPARATOR_BYTES = len(_ROW_SEPARATOR.encode("utf-8"))


@dataclass(frozen=True)
class InsertBatch:
    """One INSERT statement and the number of rows it loads."""

    sql: str
    row_count: int


def _render_struct(struct: StructValue) -> str:
    fields = ", ".join(
        f"{sql_string_literal(name)}, {render_sql_literal(value)}"
        for name, value in struct.items()
    )
    return f"named_struct({fields})"


def render_sql_literal(value: RowValue, *, sql_type: str = "ARRAY<STRING>") -> str:
    """Render one row value as a Databricks SQL literal.

    ``bool`` is checked before ``int`` (it is an ``int`` subclass). A dict is a struct
    (``named_struct``) and a tuple an array. An empty array is cast to ``sql_type`` —
    the column's declared type — because a bare ``array()`` carries no element type.
    """
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return sql_string_literal(value)
    if isinstance(value, dict):
        return _render_struct(value)
    if isinstance(value, tuple):
        if not value:
            return f"CAST(array() AS {sql_type})"
        return f"array({', '.join(render_sql_literal(v) for v in value)})"
    raise TypeError(f"Unsupported row value type: {type(value).__name__}")


def build_create_table_sql(table_full_name: str, spec: TableSpec) -> str:
    """Build the ``CREATE OR REPLACE TABLE`` DDL for ``spec``, commenting the table and
    every column. Column names are always backtick-quoted (e.g. ``values`` is reserved)."""
    columns = ",\n".join(
        f"  `{col.name}` {col.sql_type} COMMENT {sql_string_literal(col.comment)}"
        for col in spec.columns
    )
    return (
        f"CREATE OR REPLACE TABLE {quote_securable(table_full_name)} (\n"
        f"{columns}\n"
        f")\n"
        f"COMMENT {sql_string_literal(spec.comment)}"
    )


def _render_row(row: Row, spec: TableSpec) -> str:
    values = ", ".join(
        render_sql_literal(row.get(col.name), sql_type=col.sql_type)
        for col in spec.columns
    )
    return f"({values})"


def _chunk_tuples(
    tuples: list[str], prefix_bytes: int, max_rows: int, max_bytes: int
) -> list[list[str]]:
    """Group rendered row tuples into batches under both limits.

    A batch is closed before adding a tuple when it already holds ``max_rows`` tuples
    or the tuple (plus its separator) would push the statement past ``max_bytes``. A
    tuple too large for any batch is emitted alone rather than dropped; if it exceeds
    the Statement Execution API's 16 MiB limit the API rejects it and that table is
    reported as failed.
    """
    batches: list[list[str]] = []
    current: list[str] = []
    size = prefix_bytes
    for rendered in tuples:
        rendered_bytes = len(rendered.encode("utf-8"))
        added = rendered_bytes + (_ROW_SEPARATOR_BYTES if current else 0)
        if current and (len(current) >= max_rows or size + added > max_bytes):
            batches.append(current)
            current, size, added = [], prefix_bytes, rendered_bytes
        current.append(rendered)
        size += added
    if current:
        batches.append(current)
    return batches


def build_insert_batches(
    table_full_name: str,
    spec: TableSpec,
    rows: list[Row],
    *,
    max_rows: int = INSERT_MAX_ROWS,
    max_bytes: int = INSERT_MAX_BYTES,
) -> list[InsertBatch]:
    """Build the INSERT statements that load ``rows``, chunked by row count and by
    UTF-8 statement size — whichever limit is hit first.

    ``INSERT_MAX_BYTES`` leaves 4x headroom under the Statement Execution API's 16 MiB
    ``statement`` limit. Each row is rendered once, in spec column order (a missing key
    is NULL), and is its own top-level ``VALUES`` tuple.
    """
    if not rows:
        return []
    columns = ", ".join(f"`{col.name}`" for col in spec.columns)
    prefix = f"INSERT INTO {quote_securable(table_full_name)} ({columns}) VALUES\n"
    tuples = [_render_row(row, spec) for row in rows]
    return [
        InsertBatch(sql=prefix + _ROW_SEPARATOR.join(batch), row_count=len(batch))
        for batch in _chunk_tuples(
            tuples, len(prefix.encode("utf-8")), max_rows, max_bytes
        )
    ]


def build_insert_statements(
    table_full_name: str,
    spec: TableSpec,
    rows: list[Row],
    *,
    max_rows: int = INSERT_MAX_ROWS,
    max_bytes: int = INSERT_MAX_BYTES,
) -> list[str]:
    """The SQL of ``build_insert_batches``."""
    return [
        batch.sql
        for batch in build_insert_batches(
            table_full_name, spec, rows, max_rows=max_rows, max_bytes=max_bytes
        )
    ]
