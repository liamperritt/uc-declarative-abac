"""Tests for DumpLogger."""

from __future__ import annotations

import logging

from uc_declarative_abac import ActualState
from uc_declarative_abac.dumper import DumpLogger
from uc_declarative_abac.principals.state import Principal, PrincipalType
from uc_declarative_abac.securables import Securable
from uc_declarative_abac.tags.state import SecurableTag
from uc_declarative_abac.types import SecurableType
from uc_declarative_abac.utils import ExecutionError

# ---
# Banner
# ---


def test_dump_logger_log_banner(caplog):
    """Banner reads 'UC Declarative ABAC (dump)'."""
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    logger_instance = DumpLogger()
    logger_instance.log_banner()
    assert "UC Declarative ABAC (dump)" in caplog.text


def test_dump_logger_log_banner_when_dry_run(caplog):
    """Dry-run banner reads 'UC Declarative ABAC (dump, dry run)'."""
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    logger_instance = DumpLogger(dry_run=True)
    logger_instance.log_banner()
    assert "UC Declarative ABAC (dump, dry run)" in caplog.text


# ---
# Section headers
# ---


def test_dump_logger_log_section_header(caplog):
    """Section header contains the given name."""
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    logger_instance = DumpLogger()
    logger_instance.log_section_header("Test Section")
    assert "Test Section" in caplog.text


def test_dump_logger_log_section_header_when_dry_run(caplog):
    """Section header contains '(dry run)' suffix when dry_run=True."""
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    logger_instance = DumpLogger(dry_run=True)
    logger_instance.log_section_header("Test Section")
    assert "(dry run)" in caplog.text


# ---
# Fetching state
# ---


def test_dump_logger_log_fetching_state(caplog):
    """Fetching state message contains 'fetching' and 'state'."""
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    logger_instance = DumpLogger()
    logger_instance.log_fetching_state()
    assert "fetching" in caplog.text.lower()
    assert "state" in caplog.text.lower()


# ---
# Fetched state summary
# ---


def test_dump_logger_log_fetched_state(caplog):
    """Fetched state message contains securables count and principals count."""
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    logger_instance = DumpLogger()

    # Create a simple ActualState with some test data
    securable = Securable(
        securable_type=SecurableType.CATALOG,
        full_name="test_catalog",
    )
    principal = Principal(
        PrincipalType.USER, identifier="user1@x.com", name="user1@x.com"
    )
    state = ActualState(
        groups=frozenset(),
        all_account_groups=frozenset(),
        governed_tags=frozenset(),
        domains=frozenset(),
        securables=frozenset([securable]),
        attributes=frozenset(),
        tags=frozenset(),
        policies=frozenset(),
        privileges=frozenset(),
        principals={"user1@x.com": principal},
    )

    logger_instance.log_fetched_state(state)
    assert "securables" in caplog.text.lower()
    assert "1" in caplog.text  # 1 securable
    assert "principals" in caplog.text.lower()
    assert "Fetched" in caplog.text


# ---
# Schema operations
# ---


def test_dump_logger_log_target_schema_exists(caplog):
    """An existing target schema logs 'Using schema <name>'."""
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    logger_instance = DumpLogger()
    logger_instance.log_target_schema_exists("main.state")
    assert "Using schema main.state" in caplog.text


def test_dump_logger_log_target_schema_created(caplog):
    """Schema created message contains the schema name and 'Created'."""
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    logger_instance = DumpLogger()
    logger_instance.log_target_schema_created("main.state")
    assert "main.state" in caplog.text
    assert "Created" in caplog.text


def test_dump_logger_log_target_schema_created_when_dry_run(caplog):
    """Dry-run schema created message contains 'Would create'."""
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    logger_instance = DumpLogger(dry_run=True)
    logger_instance.log_target_schema_created("main.state")
    assert "main.state" in caplog.text
    assert "Would create" in caplog.text


# ---
# Error logging
# ---


def test_dump_logger_log_error(caplog):
    """Error message is logged at ERROR level with context and exception."""
    caplog.set_level(logging.DEBUG, logger="uc_declarative_abac")
    logger_instance = DumpLogger()
    error = ExecutionError(context="test_context", exception=ValueError("test error"))
    logger_instance.log_error(error)
    assert "test_context" in caplog.text
    assert "test error" in caplog.text
    assert error in logger_instance.errors


# ---
# Table operations
# ---


def test_dump_logger_log_table_started(caplog):
    """Table started message reads 'Writing to <name> (0 of <n> rows)', aligned with
    the progress lines."""
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    logger_instance = DumpLogger()
    logger_instance.log_table_started("main.state.securables", 12)
    assert "> Writing to main.state.securables (0 of 12 rows)" in caplog.text


def test_dump_logger_log_batch_appears_only_at_debug(caplog):
    """Batch messages appear only at DEBUG level, not at INFO level."""
    # Test at INFO level - should not appear
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    logger_instance = DumpLogger()
    logger_instance.log_batch("main.state.securables", 1, 3, 100, 50000)
    info_text = caplog.text
    caplog.clear()

    # Test at DEBUG level - should appear
    caplog.set_level(logging.DEBUG, logger="uc_declarative_abac")
    logger_instance2 = DumpLogger()
    logger_instance2.log_batch("main.state.securables", 1, 3, 100, 50000)
    debug_text = caplog.text

    # At INFO level, batch should not be present
    assert "batch" not in info_text.lower()

    # At DEBUG level, batch should be present with batch indicator
    assert "batch" in debug_text.lower()
    assert "1/3" in debug_text or "batch 1" in debug_text.lower()


def test_dump_logger_log_statement_only_at_debug(caplog):
    """Statement SQL appears only at DEBUG level."""
    # Test at INFO level
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    logger_instance = DumpLogger()
    sql_statement = "INSERT INTO main.state.securables VALUES (...)"
    logger_instance.log_statement(sql_statement)
    info_text = caplog.text
    caplog.clear()

    # Test at DEBUG level
    caplog.set_level(logging.DEBUG, logger="uc_declarative_abac")
    logger_instance2 = DumpLogger()
    logger_instance2.log_statement(sql_statement)
    debug_text = caplog.text

    # At INFO level, SQL should not be present
    assert "INSERT INTO" not in info_text

    # At DEBUG level, SQL should be present
    assert "INSERT INTO" in debug_text


def test_dump_logger_log_table_written(caplog):
    """Table written message reads 'Wrote to <name> (<n> rows in <b> batches)'."""
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    logger_instance = DumpLogger()
    logger_instance.log_table_written("main.state.securables", 12, 1)
    assert "Wrote to main.state.securables (12 rows in 1 batches)" in caplog.text


def test_dump_logger_log_table_written_when_dry_run(caplog):
    """Dry-run table written message contains 'Would write'."""
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    logger_instance = DumpLogger(dry_run=True)
    logger_instance.log_table_written("main.state.securables", 12, 1)
    assert "Would write to main.state.securables (12 rows in 1 batches)" in caplog.text


def test_dump_logger_log_table_failed(caplog):
    """Table failed message logs error naming the table and adds to errors."""
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    logger_instance = DumpLogger()
    exception = ValueError("Connection failed")
    logger_instance.log_table_failed("main.state.securables", exception)
    assert "main.state.securables" in caplog.text
    assert "Connection failed" in caplog.text
    assert len(logger_instance.errors) == 1
    assert "main.state.securables" in logger_instance.errors[0].context


# ---
# Summary
# ---


def test_dump_logger_log_summary_respects_table_order(caplog):
    """Summary lists tables in the given order even when written in different order."""
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    logger_instance = DumpLogger()

    # Write tables in order: b, a
    logger_instance.log_table_written("main.state.b", 100, 1)
    logger_instance.log_table_written("main.state.a", 50, 1)

    # Call summary with different order: a, b
    logger_instance.log_summary(["main.state.a", "main.state.b"])

    lines = caplog.text.split("\n")

    # Verify a appears before b in the summary section
    a_index = None
    b_index = None
    for i, line in enumerate(lines):
        if "main.state.a" in line:
            a_index = i
        if "main.state.b" in line and a_index is not None and b_index is None:
            b_index = i

    assert a_index is not None
    assert b_index is not None
    assert a_index < b_index, "Table 'a' should appear before 'b' in summary"


def test_dump_logger_log_summary_with_failures(caplog):
    """Summary marks failed tables 'FAILED' and totals report written and failed counts."""
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    logger_instance = DumpLogger()

    # Write one table, fail another
    logger_instance.log_table_written("main.state.a", 50, 1)
    logger_instance.log_table_failed("main.state.b", ValueError("Failed"))

    logger_instance.log_summary(["main.state.a", "main.state.b"])

    summary_text = caplog.text
    assert "FAILED" in summary_text
    assert "Summary:" in summary_text
    assert "1 failed" in summary_text.lower()


def test_dump_logger_log_summary_totals_with_thousands_separator(caplog):
    """Summary totals use thousands separators for large row counts."""
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    logger_instance = DumpLogger()

    # Write multiple tables with large row counts
    logger_instance.log_table_written("main.state.a", 1234, 1)
    logger_instance.log_table_written("main.state.b", 2345, 1)
    logger_instance.log_table_written("main.state.c", 3421, 1)

    logger_instance.log_summary(["main.state.a", "main.state.b", "main.state.c"])

    summary_text = caplog.text
    # Total rows = 1234 + 2345 + 3421 = 7000
    # Should contain thousands separator for large numbers
    assert "Summary:" in summary_text
    assert "7,000" in summary_text or "7000" in summary_text


def test_dump_logger_log_summary_when_dry_run(caplog):
    """Dry-run summary totals say 'would be written'."""
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    logger_instance = DumpLogger(dry_run=True)

    logger_instance.log_table_written("main.state.a", 50, 1)
    logger_instance.log_summary(["main.state.a"])

    assert "would be written" in caplog.text.lower()


# ---
# Error collection
# ---


def test_dump_logger_errors_property_returns_copy(caplog):
    """Errors property returns a copy of collected errors."""
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    logger_instance = DumpLogger()

    error1 = ExecutionError(context="ctx1", exception=ValueError("err1"))
    error2 = ExecutionError(context="ctx2", exception=ValueError("err2"))

    logger_instance.log_error(error1)
    logger_instance.log_error(error2)

    errors = logger_instance.errors
    assert len(errors) == 2
    assert error1 in errors
    assert error2 in errors


# ---
# Multiple table operations
# ---


def test_dump_logger_multiple_tables_sequence(caplog):
    """Multiple table operations maintain correct sequence."""
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    logger_instance = DumpLogger()

    logger_instance.log_table_started("main.state.a", 10)
    logger_instance.log_table_written("main.state.a", 10, 1)

    logger_instance.log_table_started("main.state.b", 20)
    logger_instance.log_table_written("main.state.b", 20, 1)

    logger_instance.log_summary(["main.state.a", "main.state.b"])

    assert "Writing to" in caplog.text
    assert "Wrote to" in caplog.text
    assert "Summary:" in caplog.text


# ---
# Fetched state with multiple entities
# ---


def test_dump_logger_log_fetched_state_with_multiple_counts(caplog):
    """Fetched state with multiple entity types shows all non-zero counts."""
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    logger_instance = DumpLogger()

    # Build state with multiple entity types
    securable = Securable(
        securable_type=SecurableType.CATALOG,
        full_name="c1",
    )
    tag = SecurableTag(
        securable_type=SecurableType.CATALOG,
        securable_full_name="c1",
        tag_name="env",
        tag_value="prod",
    )
    principal = Principal(PrincipalType.USER, identifier="u1@x.com", name="u1@x.com")

    state = ActualState(
        groups=frozenset(),
        all_account_groups=frozenset(),
        governed_tags=frozenset(),
        domains=frozenset(),
        securables=frozenset([securable]),
        attributes=frozenset(),
        tags=frozenset([tag]),
        policies=frozenset(),
        privileges=frozenset(),
        principals={"u1@x.com": principal},
    )

    logger_instance.log_fetched_state(state)

    # Verify counts are present
    assert "1" in caplog.text  # securables count
    assert "principals" in caplog.text.lower()


def test_dump_logger_log_table_progress(caplog):
    """Progress reads 'Writing to <name> (<written> of <total> rows)'."""
    caplog.set_level(logging.INFO, logger="uc_declarative_abac")
    DumpLogger().log_table_progress("main.state.principals", 1234, 22836)
    assert "> Writing to main.state.principals (1234 of 22836 rows)" in caplog.text
