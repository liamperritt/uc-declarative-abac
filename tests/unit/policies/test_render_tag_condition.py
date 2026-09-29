from __future__ import annotations

from uc_declarative_abac.policies import render_tag_condition


def test_render_tag_condition_renders_has_tags_as_has_tag_value():
    """A concrete has_tags entry renders as has_tag_value(k, v)."""
    assert (
        render_tag_condition({"domain": "sales"}, None)
        == "has_tag_value('domain', 'sales')"
    )


def test_render_tag_condition_wildcard_renders_presence_only():
    """A '*' value renders as the presence-only has_tag(k)."""
    assert render_tag_condition({"domain": "*"}, None) == "has_tag('domain')"


def test_render_tag_condition_combines_has_tags_and_has_any_of_tags():
    """has_tags AND-join first (sorted); has_any_of_tags OR-group parenthesised when >1."""
    result = render_tag_condition({"a": "1"}, {"b": "2", "c": "3"})
    assert (
        result
        == "has_tag_value('a', '1') AND (has_tag_value('b', '2') OR has_tag_value('c', '3'))"
    )


def test_render_tag_condition_returns_none_when_empty():
    """No predicates ⇒ None (no WHEN clause)."""
    assert render_tag_condition(None, None) is None
    assert render_tag_condition({}, {}) is None
