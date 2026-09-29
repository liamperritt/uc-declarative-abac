from __future__ import annotations

from uc_declarative_abac.principals import Principal
from uc_declarative_abac.report import sql
from uc_declarative_abac.types import PrincipalType

# ---------------------------------------------------------------------------
# Literal / struct rendering
# ---------------------------------------------------------------------------


def test_sql_literal_escapes_single_quotes_and_renders_null():
    assert sql.sql_literal("O'Brien") == "'O''Brien'"
    assert sql.sql_literal("plain") == "'plain'"
    assert sql.sql_literal(None) == "NULL"


def test_principal_struct_renders_named_struct_or_null():
    p = Principal(PrincipalType.GROUP, identifier="data_eng", name="data_eng")
    assert sql.principal_struct(p) == (
        "named_struct('principal_type', 'GROUP', "
        "'identifier', 'data_eng', 'name', 'data_eng')"
    )
    assert sql.principal_struct(None) == "NULL"


def test_str_array_renders_array_of_literals():
    assert sql.str_array(["a", "b"]) == "array('a', 'b')"
    assert sql.str_array([]) == "array()"


def test_create_schema_if_not_exists_renders_ddl():
    assert (
        sql.create_schema_if_not_exists("rep.abac")
        == "CREATE SCHEMA IF NOT EXISTS rep.abac"
    )


def test_create_or_replace_table_renders_ddl():
    ddl = sql.create_or_replace_table(
        "rep.abac.principals",
        [("principal_type", "STRING"), ("identifier", "STRING")],
    )
    assert ddl.startswith("CREATE OR REPLACE TABLE rep.abac.principals (")
    assert "principal_type STRING" in ddl
    assert "identifier STRING" in ddl


# ---------------------------------------------------------------------------
# Batching
# ---------------------------------------------------------------------------


def test_batch_inserts_empty_rows_yields_no_statements():
    assert sql.batch_inserts("rep.abac.t", ["a"], []) == []


def test_batch_inserts_splits_by_row_count():
    rows = ["(1)", "(2)", "(3)"]
    stmts = sql.batch_inserts("rep.abac.t", ["a"], rows, max_rows=2)
    assert len(stmts) == 2
    assert all(s.startswith("INSERT INTO rep.abac.t (a) VALUES ") for s in stmts)
    # All rows appear across the batches.
    joined = " ".join(stmts)
    assert "(1)" in joined and "(2)" in joined and "(3)" in joined


def test_batch_inserts_splits_by_byte_budget():
    rows = ["(" + "x" * 100 + ")" for _ in range(5)]
    stmts = sql.batch_inserts("rep.abac.t", ["a"], rows, max_bytes=250)
    assert len(stmts) > 1


def test_batch_inserts_single_over_budget_row_gets_its_own_statement():
    big = "(" + "x" * 1000 + ")"
    stmts = sql.batch_inserts("rep.abac.t", ["a"], [big, "(2)"], max_bytes=200)
    assert len(stmts) == 2
    assert big in stmts[0]
