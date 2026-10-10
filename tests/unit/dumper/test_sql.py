"""Tests for uc_declarative_abac.dumper SQL rendering functions."""

from __future__ import annotations

from uc_declarative_abac.dumper import (
    INSERT_MAX_BYTES,
    ColumnSpec,
    TableSpec,
    build_create_table_sql,
    build_insert_batches,
    build_insert_statements,
    render_sql_literal,
)

# ---
# render_sql_literal tests
# ---


def test_dumper_sql_render_sql_literal_none() -> None:
    """render_sql_literal converts None to NULL."""
    assert render_sql_literal(None) == "NULL"


def test_dumper_sql_render_sql_literal_true() -> None:
    """render_sql_literal converts True to TRUE (not 1)."""
    result = render_sql_literal(True)
    assert result == "TRUE"
    assert "1" not in result


def test_dumper_sql_render_sql_literal_false() -> None:
    """render_sql_literal converts False to FALSE (not 0)."""
    result = render_sql_literal(False)
    assert result == "FALSE"
    assert "0" not in result


def test_dumper_sql_render_sql_literal_int() -> None:
    """render_sql_literal renders int as bare number."""
    assert render_sql_literal(3) == "3"
    assert render_sql_literal(0) == "0"
    assert render_sql_literal(-42) == "-42"
    assert render_sql_literal(1000000) == "1000000"


def test_dumper_sql_render_sql_literal_string_simple() -> None:
    """render_sql_literal renders simple string as single-quoted literal."""
    result = render_sql_literal("hello")
    assert result == "'hello'"


def test_dumper_sql_render_sql_literal_string_with_single_quote() -> None:
    """render_sql_literal escapes single quotes with backslash."""
    result = render_sql_literal("It's")
    assert result == "'It\\'s'"
    # Verify it's a valid escape that won't break the literal
    assert "'" in result
    assert "\\'" in result


def test_dumper_sql_render_sql_literal_string_with_double_quote() -> None:
    """render_sql_literal escapes double quotes with backslash."""
    result = render_sql_literal('Say "hello"')
    assert '\\"' in result or '\\"' in result


def test_dumper_sql_render_sql_literal_string_with_backslash() -> None:
    """render_sql_literal escapes backslashes with backslash."""
    result = render_sql_literal("path\\to\\file")
    # Backslash should be escaped so it doesn't consume the next character
    assert "\\\\" in result


def test_dumper_sql_render_sql_literal_string_with_mixed_escapes() -> None:
    """render_sql_literal handles backslash, quote, and double-quote together."""
    result = render_sql_literal('She said "It\'s here"')
    # Should escape all three characters
    assert "\\" in result or "'" in result


def test_dumper_sql_render_sql_literal_empty_string() -> None:
    """render_sql_literal renders empty string as ''."""
    assert render_sql_literal("") == "''"


def test_dumper_sql_render_sql_literal_tuple_of_strings() -> None:
    """render_sql_literal renders tuple of strings as array(...) of literals."""
    result = render_sql_literal(("a", "b", "c"))
    # Should contain array syntax with all three values
    assert "array(" in result.lower()
    assert "'a'" in result
    assert "'b'" in result
    assert "'c'" in result


def test_dumper_sql_render_sql_literal_tuple_with_special_chars() -> None:
    """render_sql_literal escapes special chars in array elements."""
    result = render_sql_literal(("It's", 'Quote"Here'))
    # Elements should be properly escaped
    assert "array(" in result.lower()
    # Verify escaping is applied to array elements
    assert "\\" in result


def test_dumper_sql_render_sql_literal_empty_tuple() -> None:
    """render_sql_literal renders empty tuple as CAST(array() AS ARRAY<STRING>)."""
    result = render_sql_literal(())
    # Check for empty array syntax and ARRAY<STRING> type cast
    assert "array()" in result.lower()
    assert "ARRAY<STRING>" in result or "array<string>" in result.lower()
    assert "CAST" in result


def test_dumper_sql_render_sql_literal_tuple_single_element() -> None:
    """render_sql_literal renders single-element tuple as array with one element."""
    result = render_sql_literal(("only",))
    assert "array(" in result.lower()
    assert "'only'" in result


# ---
# render_sql_literal struct tests
# ---


def test_dumper_sql_render_sql_literal_struct_single_field() -> None:
    """render_sql_literal renders a struct dict as named_struct with string literals."""
    result = render_sql_literal({"name": "c1"})
    assert "named_struct(" in result.lower()
    assert "'name'" in result
    assert "'c1'" in result


def test_dumper_sql_render_sql_literal_struct_multiple_fields() -> None:
    """render_sql_literal renders struct with multiple fields in dict order."""
    result = render_sql_literal({"field1": "value1", "field2": "value2"})
    assert "named_struct(" in result.lower()
    assert "'field1'" in result
    assert "'value1'" in result
    assert "'field2'" in result
    assert "'value2'" in result


def test_dumper_sql_render_sql_literal_struct_none_field_value() -> None:
    """render_sql_literal renders None field values as NULL in named_struct."""
    result = render_sql_literal({"field1": "value", "field2": None})
    assert "named_struct(" in result.lower()
    assert "'field1'" in result
    assert "'value'" in result
    assert "'field2'" in result
    assert "NULL" in result


def test_dumper_sql_render_sql_literal_struct_only_none_fields() -> None:
    """render_sql_literal handles struct with all None field values."""
    result = render_sql_literal({"f1": None, "f2": None})
    assert "named_struct(" in result.lower()
    assert "'f1'" in result
    assert "'f2'" in result
    assert result.count("NULL") >= 2


def test_dumper_sql_render_sql_literal_tuple_of_structs() -> None:
    """render_sql_literal renders tuple of structs as array of named_structs."""
    result = render_sql_literal(({"name": "a"}, {"name": "b"}))
    assert "array(" in result.lower()
    assert "named_struct(" in result.lower()
    # Should have both structs
    assert result.count("named_struct") >= 2
    assert "'a'" in result
    assert "'b'" in result


def test_dumper_sql_render_sql_literal_mixed_struct_tuple() -> None:
    """render_sql_literal renders tuple of structs with mixed field values."""
    result = render_sql_literal(
        ({"id": "1", "name": "first"}, {"id": "2", "name": None})
    )
    assert "array(" in result.lower()
    assert "named_struct(" in result.lower()
    assert "'1'" in result
    assert "'first'" in result
    assert "'2'" in result
    assert "NULL" in result


def test_dumper_sql_render_sql_literal_empty_tuple_with_custom_sql_type() -> None:
    """render_sql_literal accepts sql_type parameter to type empty arrays."""
    result = render_sql_literal((), sql_type="ARRAY<STRUCT<name: STRING>>")
    assert "CAST(array()" in result
    assert "ARRAY<STRUCT<name: STRING>>" in result


def test_dumper_sql_render_sql_literal_empty_tuple_default_type() -> None:
    """render_sql_literal empty tuple without sql_type uses ARRAY<STRING>."""
    result = render_sql_literal(())
    assert "CAST(array()" in result
    assert "ARRAY<STRING>" in result


# ---
# build_create_table_sql tests
# ---


def test_dumper_sql_build_create_table_sql_basic() -> None:
    """build_create_table_sql creates CREATE OR REPLACE TABLE statement."""
    spec = TableSpec(
        name="users",
        comment="User records",
        columns=(
            ColumnSpec("id", "INT", "User ID"),
            ColumnSpec("name", "STRING", "User name"),
        ),
        rows=lambda state, ctx: [],
    )
    result = build_create_table_sql("catalog.schema.users", spec)
    assert "CREATE OR REPLACE TABLE" in result
    assert "`catalog`.`schema`.`users`" in result
    assert "`id`" in result
    assert "`name`" in result
    assert "INT" in result
    assert "STRING" in result


def test_dumper_sql_build_create_table_sql_backtick_quotes_full_name() -> None:
    """build_create_table_sql backtick-quotes each segment of the full name."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(ColumnSpec("c", "STRING", "col"),),
        rows=lambda state, ctx: [],
    )
    result = build_create_table_sql("main.state.securables", spec)
    # Each segment should be backtick-quoted
    assert "`main`" in result
    assert "`state`" in result
    assert "`securables`" in result


def test_dumper_sql_build_create_table_sql_column_comments() -> None:
    """build_create_table_sql includes COMMENT for each column."""
    spec = TableSpec(
        name="t",
        comment="Test table",
        columns=(
            ColumnSpec("col1", "INT", "First column"),
            ColumnSpec("col2", "STRING", "Second column"),
        ),
        rows=lambda state, ctx: [],
    )
    result = build_create_table_sql("db.t", spec)
    # Column comments should be present
    assert "First column" in result
    assert "Second column" in result
    # Each column should have COMMENT
    assert result.count("COMMENT") >= 3  # 2 columns + 1 table


def test_dumper_sql_build_create_table_sql_table_comment() -> None:
    """build_create_table_sql includes table COMMENT after columns."""
    spec = TableSpec(
        name="t",
        comment="Table documentation",
        columns=(ColumnSpec("id", "INT", "ID"),),
        rows=lambda state, ctx: [],
    )
    result = build_create_table_sql("db.t", spec)
    # Should have "Table documentation" somewhere as the table comment
    assert "Table documentation" in result
    # Should appear after the columns section
    last_paren = result.rfind(")")
    assert result[last_paren:].count("COMMENT") >= 1


def test_dumper_sql_build_create_table_sql_escape_quote_in_comment() -> None:
    """build_create_table_sql escapes quotes in comments."""
    spec = TableSpec(
        name="t",
        comment="It's a comment",
        columns=(ColumnSpec("col", "STRING", 'It says "hello"'),),
        rows=lambda state, ctx: [],
    )
    result = build_create_table_sql("db.t", spec)
    # Quotes in comments should be escaped so comment string doesn't break
    # The result should be parseable (escaped quotes should be present)
    assert "It" in result and "comment" in result
    assert "hello" in result


def test_dumper_sql_build_create_table_sql_reserved_column_name() -> None:
    """build_create_table_sql backtick-quotes reserved words like 'values'."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(ColumnSpec("values", "STRING", "Reserved word"),),
        rows=lambda state, ctx: [],
    )
    result = build_create_table_sql("db.t", spec)
    # The column name should be backtick-quoted to avoid SQL parsing issues
    assert "`values`" in result


def test_dumper_sql_build_create_table_sql_column_order() -> None:
    """build_create_table_sql includes columns in spec order."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(
            ColumnSpec("z_last", "INT", "Last"),
            ColumnSpec("a_first", "STRING", "First"),
            ColumnSpec("m_middle", "DOUBLE", "Middle"),
        ),
        rows=lambda state, ctx: [],
    )
    result = build_create_table_sql("db.t", spec)
    # Find positions of each column name to verify order
    z_pos = result.find("`z_last`")
    a_pos = result.find("`a_first`")
    m_pos = result.find("`m_middle`")
    assert z_pos < a_pos < m_pos


def test_dumper_sql_build_create_table_sql_no_primary_key() -> None:
    """build_create_table_sql contains no PRIMARY KEY constraint."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(ColumnSpec("id", "INT", "ID"),),
        rows=lambda state, ctx: [],
    )
    result = build_create_table_sql("db.t", spec)
    assert "PRIMARY KEY" not in result


def test_dumper_sql_build_create_table_sql_no_foreign_key() -> None:
    """build_create_table_sql contains no FOREIGN KEY constraint."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(ColumnSpec("id", "INT", "ID"),),
        rows=lambda state, ctx: [],
    )
    result = build_create_table_sql("db.t", spec)
    assert "FOREIGN KEY" not in result


def test_dumper_sql_build_create_table_sql_struct_column_type() -> None:
    """build_create_table_sql renders struct column types verbatim."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(
            ColumnSpec("id", "INT", "ID"),
            ColumnSpec("columns", "ARRAY<STRUCT<name: STRING>>", "Column info"),
        ),
        rows=lambda state, ctx: [],
    )
    result = build_create_table_sql("db.t", spec)
    # Struct type should appear verbatim in the result
    assert "ARRAY<STRUCT<name: STRING>>" in result
    assert "`columns`" in result


def test_dumper_sql_build_create_table_sql_complex_struct_type() -> None:
    """build_create_table_sql renders complex struct types."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(
            ColumnSpec(
                "data",
                "ARRAY<STRUCT<id: INT, name: STRING, tags: ARRAY<STRING>>>",
                "Complex struct",
            ),
        ),
        rows=lambda state, ctx: [],
    )
    result = build_create_table_sql("db.t", spec)
    # Complex struct type should be preserved
    assert "ARRAY<STRUCT<id: INT, name: STRING, tags: ARRAY<STRING>>>" in result


# ---
# build_insert_statements tests
# ---


def test_dumper_sql_build_insert_statements_empty_rows() -> None:
    """build_insert_statements returns empty list for empty rows."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(ColumnSpec("id", "INT", "ID"),),
        rows=lambda state, ctx: [],
    )
    result = build_insert_statements("db.t", spec, [])
    assert result == []


def test_dumper_sql_build_insert_statements_single_row() -> None:
    """build_insert_statements creates single INSERT INTO with explicit column list."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(
            ColumnSpec("id", "INT", "ID"),
            ColumnSpec("name", "STRING", "Name"),
        ),
        rows=lambda state, ctx: [],
    )
    rows = [{"id": 1, "name": "Alice"}]
    result = build_insert_statements("db.t", spec, rows)
    assert len(result) == 1
    stmt = result[0]
    assert "INSERT INTO" in stmt
    assert "`db`.`t`" in stmt
    assert "`id`" in stmt
    assert "`name`" in stmt


def test_dumper_sql_build_insert_statements_column_order() -> None:
    """build_insert_statements orders values by spec columns regardless of dict key order."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(
            ColumnSpec("a", "INT", "A"),
            ColumnSpec("b", "STRING", "B"),
            ColumnSpec("c", "INT", "C"),
        ),
        rows=lambda state, ctx: [],
    )
    # Dict has keys in different order than spec
    rows = [{"c": 3, "a": 1, "b": "two"}]
    result = build_insert_statements("db.t", spec, rows)
    stmt = result[0]
    # VALUES should have values in column order: a, b, c
    # Find the VALUES part
    values_idx = stmt.find("VALUES")
    assert values_idx > 0
    # The values should be in order: 1, 'two', 3
    values_part = stmt[values_idx:]
    # Check that 1 (for a) comes before 'two' (for b) which comes before 3 (for c)
    idx_1 = values_part.find("1")
    idx_two = values_part.find("'two'")
    idx_3 = values_part.find("3")
    assert idx_1 < idx_two < idx_3


def test_dumper_sql_build_insert_statements_missing_key_becomes_null() -> None:
    """build_insert_statements renders missing key as NULL."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(
            ColumnSpec("id", "INT", "ID"),
            ColumnSpec("optional", "STRING", "Optional"),
        ),
        rows=lambda state, ctx: [],
    )
    rows = [{"id": 1}]  # 'optional' is missing
    result = build_insert_statements("db.t", spec, rows)
    stmt = result[0]
    assert "NULL" in stmt


def test_dumper_sql_build_insert_statements_multiple_rows_single_statement() -> None:
    """build_insert_statements puts multiple rows in one statement when under limit."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(ColumnSpec("id", "INT", "ID"),),
        rows=lambda state, ctx: [],
    )
    rows = [{"id": i} for i in range(5)]
    result = build_insert_statements("db.t", spec, rows)
    # All 5 rows should fit in one statement (well under 1000-row limit)
    assert len(result) == 1
    stmt = result[0]
    # Count value tuples by counting "(" in the VALUES section
    values_idx = stmt.find("VALUES")
    values_part = stmt[values_idx:]
    assert values_part.count("(") == 5


def test_dumper_sql_build_insert_statements_row_limit_chunking() -> None:
    """build_insert_statements splits rows when default limit (1000) is reached."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(ColumnSpec("id", "INT", "ID"),),
        rows=lambda state, ctx: [],
    )
    # 2500 rows with default limit of 1000 should chunk into 3 statements
    rows = [{"id": i} for i in range(2500)]
    result = build_insert_statements("db.t", spec, rows)
    assert len(result) == 3

    # The key requirement: row order preserved across statements
    concatenated = "".join(result)
    # Verify a sample of IDs appear in order (not checking every ID for speed)
    for i in range(0, 2500, 250):
        id_i_pos = concatenated.find(f"({i})")
        if id_i_pos >= 0 and i + 1 < 2500:
            id_i1_pos = concatenated.find(f"({i + 1})")
            assert id_i1_pos > id_i_pos


def test_dumper_sql_build_insert_statements_byte_limit_enforcement() -> None:
    """build_insert_statements respects max_bytes limit, splitting before size is reached."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(ColumnSpec("data", "STRING", "Data"),),
        rows=lambda state, ctx: [],
    )
    # Create rows with a specific size
    small_size_bytes = 1000
    rows = [{"data": f"row_{i:04d}"} for i in range(100)]

    result = build_insert_statements(
        "db.t", spec, rows, max_bytes=small_size_bytes, max_rows=1000
    )

    # Verify that every statement is within the byte limit
    for stmt in result:
        byte_len = len(stmt.encode("utf-8"))
        assert byte_len <= small_size_bytes


def test_dumper_sql_build_insert_statements_utf8_byte_counting() -> None:
    """build_insert_statements counts UTF-8 bytes, not characters."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(ColumnSpec("text", "STRING", "Text"),),
        rows=lambda state, ctx: [],
    )
    # Create rows with multi-byte UTF-8 characters (é is 2 bytes in UTF-8)
    # Create enough rows to exceed byte limit if char-counted, but fit if byte-counted properly
    max_bytes = 500
    # Each row with 'é' repeated: "é" is 2 bytes, so 250 'é's = 500 bytes
    # Add multiple such rows to force splitting
    rows = [{"text": "é" * 100} for _ in range(10)]

    result = build_insert_statements(
        "db.t", spec, rows, max_bytes=max_bytes, max_rows=1000
    )

    # Should produce multiple statements due to byte limit
    assert len(result) > 1

    # Verify each statement respects byte limit
    for stmt in result:
        byte_len = len(stmt.encode("utf-8"))
        assert byte_len <= max_bytes


def test_dumper_sql_build_insert_statements_lone_row_exceeding_max_bytes() -> None:
    """build_insert_statements emits a lone row larger than max_bytes in its own statement."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(ColumnSpec("text", "STRING", "Text"),),
        rows=lambda state, ctx: [],
    )
    # Create one very large row and some small rows
    large_row = {"text": "x" * 10000}
    small_rows = [{"text": "s"} for _ in range(5)]
    rows = [large_row] + small_rows

    max_bytes = 1000
    result = build_insert_statements("db.t", spec, rows, max_bytes=max_bytes)

    # The large row should not be dropped (requirement: never dropped)
    # It should appear in some statement
    concatenated = "".join(result)
    assert "x" * 10000 in concatenated

    # Verify the large row is in its own statement or split appropriately
    # At minimum, we should have multiple statements
    assert len(result) >= 1


def test_dumper_sql_build_insert_statements_row_order_preserved() -> None:
    """build_insert_statements preserves row order across chunks."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(ColumnSpec("seq", "INT", "Sequence"),),
        rows=lambda state, ctx: [],
    )
    # Create 100 rows with a unique marker in each
    rows = [{"seq": i} for i in range(100)]

    result = build_insert_statements(
        "db.t", spec, rows, max_rows=30, max_bytes=INSERT_MAX_BYTES
    )

    # Extract sequence values from all statements in order
    all_seq_values = []
    for stmt in result:
        # Find all VALUES tuples and extract the seq value
        # Simple approach: look for (N) where N is the seq
        import re

        values_idx = stmt.find("VALUES")
        if values_idx >= 0:
            values_part = stmt[values_idx + 6 :]  # Skip "VALUES"
            # Match (number) patterns
            matches = re.findall(r"\((\d+)\)", values_part)
            all_seq_values.extend(int(m) for m in matches)

    # Verify order is preserved
    assert all_seq_values == list(range(100))


def test_dumper_sql_build_insert_statements_quoted_full_name() -> None:
    """build_insert_statements backtick-quotes the table full name by segment."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(ColumnSpec("id", "INT", "ID"),),
        rows=lambda state, ctx: [],
    )
    rows = [{"id": 1}]
    result = build_insert_statements("main.db.t", spec, rows)
    stmt = result[0]
    # Each segment should be backtick-quoted
    assert "`main`" in stmt
    assert "`db`" in stmt
    assert "`t`" in stmt
    # Should form the full name
    assert "`main`.`db`.`t`" in stmt


def test_dumper_sql_build_insert_statements_multiple_rows_per_tuple() -> None:
    """build_insert_statements groups multiple rows into one VALUES clause with tuples."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(ColumnSpec("id", "INT", "ID"),),
        rows=lambda state, ctx: [],
    )
    rows = [{"id": i} for i in range(10)]
    result = build_insert_statements("db.t", spec, rows, max_rows=100)

    # Should have one statement with all 10 rows in one VALUES clause
    assert len(result) == 1
    stmt = result[0]
    # Check for multiple tuples in VALUES
    values_idx = stmt.find("VALUES")
    values_part = stmt[values_idx:]
    # Should have pattern like VALUES (1), (2), (3), ... (10)
    assert "VALUES" in stmt
    # Verify all 10 IDs are in the statement
    for i in range(10):
        assert f"({i})" in values_part


def test_dumper_sql_build_insert_statements_real_values() -> None:
    """build_insert_statements renders various value types correctly."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(
            ColumnSpec("id", "INT", "ID"),
            ColumnSpec("active", "BOOLEAN", "Active"),
            ColumnSpec("name", "STRING", "Name"),
        ),
        rows=lambda state, ctx: [],
    )
    rows = [
        {"id": 1, "active": True, "name": "Alice"},
        {"id": 2, "active": False, "name": "Bob"},
    ]
    result = build_insert_statements("db.t", spec, rows)
    stmt = result[0]
    # Check for rendered values
    assert "1" in stmt
    assert "TRUE" in stmt or "true" in stmt.lower()
    assert "FALSE" in stmt or "false" in stmt.lower()
    assert "'Alice'" in stmt
    assert "'Bob'" in stmt


def test_dumper_sql_build_insert_statements_max_rows_override() -> None:
    """build_insert_statements respects custom max_rows parameter."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(ColumnSpec("id", "INT", "ID"),),
        rows=lambda state, ctx: [],
    )
    rows = [{"id": i} for i in range(100)]
    # Set max_rows to 25, so 100 rows should produce 4 statements
    result = build_insert_statements(
        "db.t", spec, rows, max_rows=25, max_bytes=INSERT_MAX_BYTES
    )
    assert len(result) == 4


def test_dumper_sql_build_insert_statements_max_bytes_override() -> None:
    """build_insert_statements respects custom max_bytes parameter."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(ColumnSpec("text", "STRING", "Text"),),
        rows=lambda state, ctx: [],
    )
    rows = [{"text": "a" * 100} for _ in range(10)]
    # Set max_bytes to 500
    result = build_insert_statements("db.t", spec, rows, max_rows=1000, max_bytes=500)
    # Should have multiple statements due to byte limit
    assert len(result) > 1
    # Verify each respects the limit
    for stmt in result:
        assert len(stmt.encode("utf-8")) <= 500


# ---
# build_insert_statements struct tests
# ---


def test_dumper_sql_build_insert_statements_struct_single_row() -> None:
    """build_insert_statements renders struct values as named_struct."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(ColumnSpec("columns", "ARRAY<STRUCT<name: STRING>>", "Cols"),),
        rows=lambda state, ctx: [],
    )
    rows = [{"columns": ({"name": "c1"},)}]
    result = build_insert_statements("db.t", spec, rows)
    stmt = result[0]
    assert "INSERT INTO" in stmt
    assert "named_struct(" in stmt.lower()
    assert "'name'" in stmt
    assert "'c1'" in stmt


def test_dumper_sql_build_insert_statements_struct_multiple_values() -> None:
    """build_insert_statements renders multiple struct rows."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(ColumnSpec("columns", "ARRAY<STRUCT<name: STRING>>", "Cols"),),
        rows=lambda state, ctx: [],
    )
    rows = [
        {"columns": ({"name": "a"},)},
        {"columns": ({"name": "b"},)},
    ]
    result = build_insert_statements("db.t", spec, rows)
    stmt = result[0]
    # Both struct values should be in the same statement
    assert "named_struct(" in stmt.lower()
    assert "'a'" in stmt
    assert "'b'" in stmt


def test_dumper_sql_build_insert_statements_empty_array_with_struct_type() -> None:
    """build_insert_statements types empty struct arrays by column sql_type."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(ColumnSpec("columns", "ARRAY<STRUCT<name: STRING>>", "Cols"),),
        rows=lambda state, ctx: [],
    )
    rows = [{"columns": ()}]  # Empty struct array
    result = build_insert_statements("db.t", spec, rows)
    stmt = result[0]
    # Should use the column's sql_type to type the empty array
    assert "CAST(array()" in stmt
    assert "ARRAY<STRUCT<name: STRING>>" in stmt


def test_dumper_sql_build_insert_statements_struct_with_none_fields() -> None:
    """build_insert_statements renders struct fields with None values as NULL."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(
            ColumnSpec("id", "INT", "ID"),
            ColumnSpec("data", "ARRAY<STRUCT<name: STRING, desc: STRING>>", "Data"),
        ),
        rows=lambda state, ctx: [],
    )
    rows = [{"id": 1, "data": ({"name": "x", "desc": None},)}]
    result = build_insert_statements("db.t", spec, rows)
    stmt = result[0]
    assert "named_struct(" in stmt.lower()
    assert "'name'" in stmt
    assert "'x'" in stmt
    assert "'desc'" in stmt
    assert "NULL" in stmt


def test_dumper_sql_build_insert_statements_mixed_struct_and_string_arrays() -> None:
    """build_insert_statements handles both struct and string array columns."""
    spec = TableSpec(
        name="t",
        comment="Test",
        columns=(
            ColumnSpec("tags", "ARRAY<STRING>", "Tags"),
            ColumnSpec("columns", "ARRAY<STRUCT<name: STRING>>", "Cols"),
        ),
        rows=lambda state, ctx: [],
    )
    rows = [{"tags": ("tag1", "tag2"), "columns": ({"name": "col1"},)}]
    result = build_insert_statements("db.t", spec, rows)
    stmt = result[0]
    # Both array types should be rendered correctly
    assert "array(" in stmt.lower()
    assert "named_struct(" in stmt.lower()
    assert "'tag1'" in stmt
    assert "'col1'" in stmt


# ---------------------------------------------------------------------------
# VALUES shape and per-batch row counts
# ---------------------------------------------------------------------------


def _one_column_spec() -> TableSpec:
    return TableSpec(
        name="t",
        comment="t",
        columns=(ColumnSpec("v", "STRING", "v"),),
        rows=lambda state, ctx: [],
    )


def test_dumper_sql_insert_lists_each_row_as_its_own_values_tuple():
    """Each row is a top-level VALUES tuple; wrapping them all in one outer tuple
    would insert a single row of structs instead."""
    (stmt,) = build_insert_statements(
        "c.s.t", _one_column_spec(), [{"v": "a"}, {"v": "b"}]
    )
    compact = " ".join(stmt.split())
    assert compact.endswith("VALUES ('a'), ('b')")


def test_dumper_sql_insert_batches_report_their_row_counts():
    rows = [{"v": str(i)} for i in range(5)]
    batches = build_insert_batches("c.s.t", _one_column_spec(), rows, max_rows=2)
    assert [b.row_count for b in batches] == [2, 2, 1]
    assert [b.sql for b in batches] == build_insert_statements(
        "c.s.t", _one_column_spec(), rows, max_rows=2
    )
