from __future__ import annotations

import pytest

from uc_declarative_abac.utils import catalog_of, parse_catalog_filter


# ---------------------------------------------------------------------------
# catalog_of
# ---------------------------------------------------------------------------


def test_utils_catalog_of_returns_first_segment_for_full_name():
    assert catalog_of("my_cat.my_schema.my_table") == "my_cat"


def test_utils_catalog_of_returns_input_when_no_dot():
    assert catalog_of("my_cat") == "my_cat"


def test_utils_catalog_of_returns_first_segment_for_column_full_name():
    assert catalog_of("cat.sch.tbl.col") == "cat"


# ---------------------------------------------------------------------------
# parse_catalog_filter
# ---------------------------------------------------------------------------


def test_utils_parse_catalog_filter_expands_star_to_all_configured():
    result = parse_catalog_filter("*", ["cat_a", "cat_b", "cat_c"])
    assert result == frozenset({"cat_a", "cat_b", "cat_c"})


def test_utils_parse_catalog_filter_returns_subset_for_comma_list():
    result = parse_catalog_filter("cat_a,cat_c", ["cat_a", "cat_b", "cat_c"])
    assert result == frozenset({"cat_a", "cat_c"})


def test_utils_parse_catalog_filter_trims_whitespace_around_names():
    result = parse_catalog_filter(" cat_a , cat_b ", ["cat_a", "cat_b"])
    assert result == frozenset({"cat_a", "cat_b"})


def test_utils_parse_catalog_filter_raises_for_unknown_catalog():
    with pytest.raises(ValueError) as exc_info:
        parse_catalog_filter("cat_a,typo_cat", ["cat_a", "cat_b"])
    assert "typo_cat" in str(exc_info.value)


def test_utils_parse_catalog_filter_lists_every_unknown_in_one_error():
    with pytest.raises(ValueError) as exc_info:
        parse_catalog_filter("typo_one,typo_two", ["cat_a"])
    msg = str(exc_info.value)
    assert "typo_one" in msg
    assert "typo_two" in msg


def test_utils_parse_catalog_filter_returns_frozenset():
    result = parse_catalog_filter("cat_a", ["cat_a"])
    assert isinstance(result, frozenset)


def test_utils_parse_catalog_filter_empty_spec_returns_empty_set():
    # An empty comma list (e.g. "") with no names yields an empty filter —
    # callers can rely on `frozenset()` semantics.
    result = parse_catalog_filter("", ["cat_a"])
    assert result == frozenset()
