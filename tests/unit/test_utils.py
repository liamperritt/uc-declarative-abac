from __future__ import annotations

import pytest

import threading
import time

from uc_declarative_abac.utils import (
    catalog_of,
    classify_rfa_destination,
    parallel_for_each,
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


# ---------------------------------------------------------------------------
# parallel_for_each
# ---------------------------------------------------------------------------


def test_utils_parallel_for_each_returns_result_for_success():
    """A successful work_fn produces (item, result, None) triples."""
    results = parallel_for_each([1, 2, 3], lambda x: x * 10, max_workers=4)
    assert results == [(1, 10, None), (2, 20, None), (3, 30, None)]


def test_utils_parallel_for_each_preserves_input_order():
    """Output order matches input order even when faster work_fn calls finish first."""
    # Earlier items sleep longer; output should still be in input order.
    def work(x: int) -> int:
        time.sleep(0.05 * (5 - x))
        return x

    results = parallel_for_each([1, 2, 3, 4], work, max_workers=4)
    assert [item for item, _, _ in results] == [1, 2, 3, 4]
    assert [result for _, result, _ in results] == [1, 2, 3, 4]


def test_utils_parallel_for_each_captures_exception_per_item():
    """One failing work_fn doesn't abort the batch; failure surfaces as (item, None, exc)."""
    boom = RuntimeError("boom")

    def work(x: int) -> int:
        if x == 2:
            raise boom
        return x * 10

    results = parallel_for_each([1, 2, 3], work, max_workers=4)
    assert results[0] == (1, 10, None)
    assert results[1][0] == 2
    assert results[1][1] is None
    assert isinstance(results[1][2], RuntimeError)
    assert str(results[1][2]) == "boom"
    assert results[2] == (3, 30, None)


def test_utils_parallel_for_each_runs_sequentially_when_max_workers_is_one():
    """max_workers=1 runs in the calling thread (no pool spawned)."""
    main_thread = threading.get_ident()
    seen_threads: list[int] = []

    def work(x: int) -> int:
        seen_threads.append(threading.get_ident())
        return x

    results = parallel_for_each([1, 2, 3], work, max_workers=1)
    assert [r for _, r, _ in results] == [1, 2, 3]
    assert all(t == main_thread for t in seen_threads)


def test_utils_parallel_for_each_handles_empty_input():
    """An empty input list returns an empty result list."""
    assert parallel_for_each([], lambda x: x, max_workers=4) == []


# ---------------------------------------------------------------------------
# parallel_for_each — on_complete streaming callback
# ---------------------------------------------------------------------------


def test_utils_parallel_for_each_on_complete_fires_per_item():
    """on_complete fires exactly once per item with the matching (item, result, error) triple."""
    seen: list[tuple] = []

    def cb(item, result, error):
        seen.append((item, result, error))

    results = parallel_for_each([1, 2, 3], lambda x: x * 10, max_workers=4, on_complete=cb)

    assert len(seen) == 3
    assert sorted(seen, key=lambda t: t[0]) == sorted(results, key=lambda t: t[0])


def test_utils_parallel_for_each_on_complete_fires_in_completion_order():
    """Earlier items that sleep longer complete later — callback order tracks completion, not input."""
    completion_order: list[int] = []

    def work(x: int) -> int:
        # x=1 sleeps the longest; x=4 sleeps the shortest.
        time.sleep(0.05 * (5 - x))
        return x

    def cb(item, _r, _e):
        completion_order.append(item)

    parallel_for_each([1, 2, 3, 4], work, max_workers=4, on_complete=cb)

    # Fast item completes first, slow item completes last.
    assert completion_order[0] == 4
    assert completion_order[-1] == 1


def test_utils_parallel_for_each_on_complete_runs_on_main_thread():
    """on_complete must run on the calling thread, so ChangeLogger stays single-threaded."""
    main_thread = threading.get_ident()
    cb_threads: list[int] = []

    parallel_for_each(
        [1, 2, 3, 4, 5],
        lambda x: x,
        max_workers=4,
        on_complete=lambda _i, _r, _e: cb_threads.append(threading.get_ident()),
    )

    assert all(t == main_thread for t in cb_threads)
    assert len(cb_threads) == 5


def test_utils_parallel_for_each_on_complete_fires_before_helper_returns():
    """At least one callback must fire while later workers are still running — proves streaming."""
    fast_done_at: list[float] = []
    slow_started_at: list[float] = []

    def work(x: int) -> int:
        if x == "slow":
            slow_started_at.append(time.monotonic())
            time.sleep(0.3)
        return x

    def cb(item, _r, _e):
        if item == "fast":
            fast_done_at.append(time.monotonic())

    parallel_for_each(["slow", "fast"], work, max_workers=2, on_complete=cb)

    # The "fast" callback must fire while the "slow" worker is still mid-sleep,
    # i.e. fast_done < slow_started + 0.3s sleep.
    assert fast_done_at and slow_started_at
    assert fast_done_at[0] < slow_started_at[0] + 0.25


def test_utils_parallel_for_each_returns_list_in_input_order_with_callback():
    """Even when callbacks fire in completion order, the returned list stays in input order."""
    def work(x: int) -> int:
        time.sleep(0.05 * (5 - x))
        return x

    results = parallel_for_each(
        [1, 2, 3, 4], work, max_workers=4, on_complete=lambda _i, _r, _e: None,
    )

    assert [item for item, _, _ in results] == [1, 2, 3, 4]


def test_utils_parallel_for_each_on_complete_receives_exceptions():
    """A worker exception surfaces to on_complete as (item, None, exc); other items unaffected."""
    boom = RuntimeError("boom")

    def work(x: int) -> int:
        if x == 2:
            raise boom
        return x * 10

    seen: list[tuple] = []
    parallel_for_each(
        [1, 2, 3], work, max_workers=4,
        on_complete=lambda i, r, e: seen.append((i, r, e)),
    )

    by_item = {triple[0]: triple for triple in seen}
    assert by_item[1] == (1, 10, None)
    assert by_item[2][0] == 2 and by_item[2][1] is None and isinstance(by_item[2][2], RuntimeError)
    assert by_item[3] == (3, 30, None)
