from __future__ import annotations

from collections.abc import Iterable

from uc_declarative_abac.principals import Principal

# Batch bounds for INSERT ... VALUES statements. A statement is flushed when it would
# exceed EITHER the row count OR the rendered-bytes budget, so neither a huge row count
# (e.g. the principals table) nor a few very wide struct-bearing rows can produce a
# statement past the Statement Execution API's size limit.
_REPORT_INSERT_MAX_ROWS = 500
_REPORT_INSERT_MAX_BYTES = 512_000


def sql_literal(value: str | None) -> str:
    """Render a string as a single-quoted SQL literal (doubling embedded quotes), or
    ``NULL`` for ``None``."""
    if value is None:
        return "NULL"
    return "'" + value.replace("'", "''") + "'"


def sql_bool(value: bool | None) -> str:
    """Render a boolean as ``TRUE`` / ``FALSE``, or ``NULL`` for ``None``."""
    if value is None:
        return "NULL"
    return "TRUE" if value else "FALSE"


def array(exprs: Iterable[str]) -> str:
    """Wrap already-rendered element expressions in an ``array(...)`` constructor."""
    return f"array({', '.join(exprs)})"


def str_array(values: Iterable[str]) -> str:
    """Render an iterable of strings as an ``array(...)`` of SQL string literals."""
    return array([sql_literal(v) for v in values])


def named_struct(fields: Iterable[tuple[str, str]]) -> str:
    """Render a ``named_struct(...)`` from ``(field_name, rendered_value_expr)`` pairs."""
    parts: list[str] = []
    for key, expr in fields:
        parts.append(sql_literal(key))
        parts.append(expr)
    return f"named_struct({', '.join(parts)})"


def principal_struct(principal: Principal | None) -> str:
    """Render a Principal as ``named_struct(principal_type, identifier, name)``, or
    ``NULL`` for ``None``."""
    if principal is None:
        return "NULL"
    return named_struct(
        [
            ("principal_type", sql_literal(principal.principal_type.value)),
            ("identifier", sql_literal(principal.identifier)),
            ("name", sql_literal(principal.name)),
        ]
    )


def principal_array(principals: Iterable[Principal]) -> str:
    """Render an iterable of Principals as an ``array(...)`` of principal structs."""
    return array([principal_struct(p) for p in principals])


def create_schema_if_not_exists(schema_fqn: str) -> str:
    """Render a ``CREATE SCHEMA IF NOT EXISTS`` for the report's ``catalog.schema``."""
    return f"CREATE SCHEMA IF NOT EXISTS {schema_fqn}"


def create_or_replace_table(fqn: str, columns: list[tuple[str, str]]) -> str:
    """Render a ``CREATE OR REPLACE TABLE`` statement from ``(name, sql_type)`` columns."""
    cols = ",\n  ".join(f"{name} {sql_type}" for name, sql_type in columns)
    return f"CREATE OR REPLACE TABLE {fqn} (\n  {cols}\n)"


def batch_inserts(
    fqn: str,
    column_names: list[str],
    rows: list[str],
    *,
    max_rows: int = _REPORT_INSERT_MAX_ROWS,
    max_bytes: int = _REPORT_INSERT_MAX_BYTES,
) -> list[str]:
    """Batch already-rendered ``VALUES`` row tuples into ``INSERT INTO`` statements.

    A new batch is started whenever appending the next row would exceed ``max_rows`` or
    ``max_bytes`` (rendered UTF-8 bytes of the accumulated rows). A single row larger than
    ``max_bytes`` still becomes its own statement rather than being dropped. Returns an
    empty list when there are no rows (the caller still issues the CREATE, yielding an
    empty table)."""
    if not rows:
        return []
    prefix = f"INSERT INTO {fqn} ({', '.join(column_names)}) VALUES "
    statements: list[str] = []
    batch: list[str] = []
    batch_bytes = 0
    for row in rows:
        row_bytes = len(row.encode("utf-8")) + 2  # + ", " separator
        exceeds = len(batch) >= max_rows or batch_bytes + row_bytes > max_bytes
        if batch and exceeds:
            statements.append(prefix + ", ".join(batch))
            batch = []
            batch_bytes = 0
        batch.append(row)
        batch_bytes += row_bytes
    if batch:
        statements.append(prefix + ", ".join(batch))
    return statements
