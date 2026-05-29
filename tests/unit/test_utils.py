from __future__ import annotations

import pytest

from uc_declarative_abac.utils import (
    catalog_of,
    classify_rfa_destination,
    parse_catalog_filter,
    validate_rfa_destinations,
)


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


# ---------------------------------------------------------------------------
# classify_rfa_destination
# ---------------------------------------------------------------------------


def test_utils_classify_rfa_destination_returns_email_for_email_address():
    assert classify_rfa_destination("data-gov@example.com") == "EMAIL"


def test_utils_classify_rfa_destination_returns_email_for_plus_addressed_email():
    assert classify_rfa_destination("foo+bar@baz.co.uk") == "EMAIL"


def test_utils_classify_rfa_destination_returns_url_for_https_url():
    assert classify_rfa_destination("https://example.com/request") == "URL"


def test_utils_classify_rfa_destination_returns_url_for_http_url():
    assert classify_rfa_destination("http://example.com") == "URL"


def test_utils_classify_rfa_destination_returns_guid_for_lowercase_uuid():
    assert classify_rfa_destination("550e8400-e29b-41d4-a716-446655440000") == "GUID"


def test_utils_classify_rfa_destination_returns_guid_for_uppercase_uuid():
    assert classify_rfa_destination("550E8400-E29B-41D4-A716-446655440000") == "GUID"


def test_utils_classify_rfa_destination_raises_for_unrecognised_string():
    with pytest.raises(ValueError):
        classify_rfa_destination("hello")


def test_utils_classify_rfa_destination_raises_for_plain_word():
    with pytest.raises(ValueError):
        classify_rfa_destination("not-an-email")


def test_utils_classify_rfa_destination_raises_for_non_http_scheme():
    with pytest.raises(ValueError):
        classify_rfa_destination("ftp://example.com")


def test_utils_classify_rfa_destination_raises_for_partial_uuid():
    with pytest.raises(ValueError):
        classify_rfa_destination("550e8400-e29b-41d4-a716")


def test_utils_classify_rfa_destination_includes_offending_value_in_message():
    with pytest.raises(ValueError) as exc_info:
        classify_rfa_destination("nonsense-value")
    assert "nonsense-value" in str(exc_info.value)


# ---------------------------------------------------------------------------
# validate_rfa_destinations
# ---------------------------------------------------------------------------


def test_utils_validate_rfa_destinations_returns_input_when_all_valid():
    values = [
        "data-gov@example.com",
        "https://example.com/request",
        "550e8400-e29b-41d4-a716-446655440000",
    ]
    result = validate_rfa_destinations(values)
    assert result == values


def test_utils_validate_rfa_destinations_accepts_empty_list():
    assert validate_rfa_destinations([]) == []


def test_utils_validate_rfa_destinations_raises_with_every_offender_listed():
    with pytest.raises(ValueError) as exc_info:
        validate_rfa_destinations(
            [
                "data-gov@example.com",
                "hello",
                "ftp://example.com",
                "https://example.com",
            ]
        )
    msg = str(exc_info.value)
    assert "hello" in msg
    assert "ftp://example.com" in msg


def test_utils_validate_rfa_destinations_raises_single_error_for_multiple_offenders():
    with pytest.raises(ValueError) as exc_info:
        validate_rfa_destinations(["bad-one", "bad-two"])
    msg = str(exc_info.value)
    assert "bad-one" in msg
    assert "bad-two" in msg
