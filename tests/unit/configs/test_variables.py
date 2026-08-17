from __future__ import annotations

import pytest

from uc_declarative_abac.configs.variables import (
    check_no_unbound,
    check_no_unused,
    check_signature_complete,
    check_string_vars,
    collect_placeholders,
    finalise,
    find_placeholders,
    substitute,
    substitute_in_body,
    unescape,
)
from uc_declarative_abac.utils import TemplateVariableError

# ---------------------------------------------------------------------------
# find_placeholders
# ---------------------------------------------------------------------------


def test_find_placeholders_finds_spaced_and_unspaced():
    """Both `{{ env }}` and `{{env}}` are recognised; inner whitespace is insignificant."""
    assert find_placeholders("a_{{ env }}_{{layer}}") == {"env", "layer"}


def test_find_placeholders_ignores_non_identifier_braces():
    """Braces around non-identifier content are not placeholders."""
    assert find_placeholders('{{"a":1}}') == set()
    assert find_placeholders("{{ SELECT 1 }}") == set()


def test_find_placeholders_ignores_escaped_double_braces():
    """Escaped `{{{{ name }}}}` is a literal, not a placeholder."""
    assert find_placeholders("{{{{ env }}}}") == set()


def test_find_placeholders_returns_empty_for_plain_text():
    """A string with no tokens yields no names."""
    assert find_placeholders("just_a_plain_name") == set()


# ---------------------------------------------------------------------------
# substitute
# ---------------------------------------------------------------------------


def test_substitute_replaces_single_placeholder():
    """A bound placeholder is replaced by its value."""
    assert substitute("ingestion_{{ env }}", {"env": "prod"}) == "ingestion_prod"


def test_substitute_replaces_multiple_placeholders():
    """Several placeholders in one string are all replaced."""
    result = substitute("{{ env }}_{{ layer }}", {"env": "prod", "layer": "bronze"})
    assert result == "prod_bronze"


def test_substitute_inserts_string_value_verbatim():
    """The bound value is inserted exactly as given (no coercion, values are strings)."""
    assert substitute("q_{{ tier }}", {"tier": ""}) == "q_"


def test_substitute_leaves_unbound_placeholder_intact():
    """A placeholder with no matching variable is left for later validation."""
    assert substitute("{{ env }}", {"other": "x"}) == "{{ env }}"


def test_substitute_does_not_unescape_double_braces():
    """substitute leaves escaped braces alone (unescaping happens in finalise)."""
    assert substitute("{{{{ env }}}}", {"env": "prod"}) == "{{{{ env }}}}"


# ---------------------------------------------------------------------------
# unescape / finalise
# ---------------------------------------------------------------------------


def test_unescape_collapses_double_braces():
    """`{{{{`/`}}}}` collapse to literal `{{`/`}}`."""
    assert unescape("a {{{{ x }}}} b") == "a {{ x }} b"


def test_finalise_unescapes_and_returns_tree():
    """finalise collapses escaped braces across a nested structure."""
    result = finalise({"return": "CONCAT('{{{{', v, '}}}}')"})
    assert result == {"return": "CONCAT('{{', v, '}}')"}


def test_finalise_raises_on_leftover_placeholder():
    """A live placeholder that survived resolution is a hard error."""
    with pytest.raises(TemplateVariableError, match="[Uu]nbound"):
        finalise({"name": "ingestion_{{ env }}"})


def test_finalise_allows_escaped_braces_without_error():
    """Escaped braces are not treated as unbound placeholders."""
    # Would raise if the escaped form were mis-read as a live placeholder.
    assert finalise("{{{{ env }}}}") == "{{ env }}"


# ---------------------------------------------------------------------------
# collect_placeholders (structure-aware)
# ---------------------------------------------------------------------------


def test_collect_placeholders_scans_plain_values():
    """Placeholders in ordinary string values are collected."""
    body = {"name": "s_{{ env }}", "tags": {"tier": "{{ layer }}"}}
    assert collect_placeholders(body) == {"env", "layer"}


def test_collect_placeholders_skips_dict_keys():
    """Only values are scanned; keys are never placeholder positions."""
    body = {"{{ env }}": "literal"}
    assert collect_placeholders(body) == set()


def test_collect_placeholders_counts_forwarded_nested_ref_vars():
    """A placeholder used only as a nested $ref's $vars value counts as used."""
    body = {
        "tables": [
            {"$ref": "$defs/tables/x", "$vars": {"env": "{{ env }}"}},
        ],
    }
    assert collect_placeholders(body) == {"env"}


def test_collect_placeholders_ignores_nested_ref_target_and_overrides():
    """A nested $ref's target and its override values belong to the child, not here."""
    body = {
        "tables": [
            {
                "$ref": "$defs/tables/{{ x }}",  # target — child scope, ignored
                "name": "{{ y }}",  # override value — child scope, ignored
                "$vars": {"env": "{{ env }}"},  # forwarding — counted
            },
        ],
    }
    assert collect_placeholders(body) == {"env"}


# ---------------------------------------------------------------------------
# substitute_in_body (structure-aware)
# ---------------------------------------------------------------------------


def test_substitute_in_body_substitutes_plain_values():
    """Plain string values are substituted."""
    body = {"name": "s_{{ env }}"}
    assert substitute_in_body(body, {"env": "prod"}) == {"name": "s_prod"}


def test_substitute_in_body_substitutes_forwarded_nested_vars():
    """A nested $ref's $vars values are substituted (forwarding to the child)."""
    body = {"tables": [{"$ref": "$defs/tables/x", "$vars": {"env": "{{ env }}"}}]}
    result = substitute_in_body(body, {"env": "prod"})
    assert result["tables"][0]["$vars"]["env"] == "prod"


def test_substitute_in_body_leaves_nested_ref_target_and_overrides():
    """A nested $ref's target and override values are not substituted by the parent."""
    body = {
        "tables": [
            {
                "$ref": "$defs/tables/x",
                "name": "{{ env }}",
                "$vars": {"env": "{{ env }}"},
            },
        ],
    }
    result = substitute_in_body(body, {"env": "prod"})
    entry = result["tables"][0]
    assert entry["$ref"] == "$defs/tables/x"  # untouched
    assert entry["name"] == "{{ env }}"  # untouched (child's scope)
    assert entry["$vars"]["env"] == "prod"  # forwarded → substituted


def test_substitute_in_body_does_not_mutate_input():
    """The original body is not modified in place."""
    body = {"name": "s_{{ env }}"}
    substitute_in_body(body, {"env": "prod"})
    assert body == {"name": "s_{{ env }}"}


# ---------------------------------------------------------------------------
# check_string_vars
# ---------------------------------------------------------------------------


def test_check_string_vars_accepts_strings_and_null():
    """Strings (including empty) and None pass."""
    check_string_vars({"a": "x", "b": "", "c": None}, context="test")


@pytest.mark.parametrize("value", [3, 1.5, True, ["a"], {"k": "v"}])
def test_check_string_vars_rejects_non_strings(value):
    """Numbers, booleans, lists, and maps are rejected with a hint."""
    with pytest.raises(TemplateVariableError, match="must be a string"):
        check_string_vars({"p": value}, context="test")


# ---------------------------------------------------------------------------
# check_no_unbound / check_no_unused
# ---------------------------------------------------------------------------


def test_check_no_unbound_passes_when_all_available():
    """No error when every used placeholder has a value."""
    check_no_unbound({"env"}, {"env", "layer"}, ref="$defs/x")


def test_check_no_unbound_raises_on_missing():
    """A used placeholder with no value raises."""
    with pytest.raises(TemplateVariableError, match="[Mm]issing"):
        check_no_unbound({"env"}, set(), ref="$defs/x")


def test_check_no_unbound_single_quotes_names():
    """Missing placeholder names are wrapped in single quotes in the message."""
    with pytest.raises(TemplateVariableError, match="'env', 'team'"):
        check_no_unbound({"team", "env"}, set(), ref="$defs/x")


def test_check_no_unused_passes_when_all_used():
    """No error when every supplied variable is used."""
    check_no_unused({"env"}, {"env"}, ref="$defs/x")


def test_check_no_unused_raises_on_extra():
    """A supplied variable the template does not use raises."""
    with pytest.raises(TemplateVariableError, match="[Uu]nused"):
        check_no_unused({"env", "typo"}, {"env"}, ref="$defs/x")


# ---------------------------------------------------------------------------
# check_signature_complete
# ---------------------------------------------------------------------------


def test_check_signature_complete_accepts_exact_match():
    """A signature listing exactly the body's placeholders (default + null) passes."""
    body = {
        "$vars": {"env": None, "medallion": "bronze"},
        "name": "s",
        "tags": {"e": "{{ env }}", "m": "{{ medallion }}"},
    }
    check_signature_complete("s", body, body["$vars"])


def test_check_signature_complete_raises_on_undeclared_placeholder():
    """A body placeholder missing from the declared signature raises (name single-quoted)."""
    body = {"$vars": {"env": None}, "name": "{{ env }}_{{ region }}"}
    with pytest.raises(
        TemplateVariableError, match="undeclared placeholder\\(s\\) 'region'"
    ):
        check_signature_complete("s", body, body["$vars"])


def test_check_signature_complete_raises_on_unused_declaration():
    """A declared variable the body never uses raises."""
    body = {"$vars": {"env": None, "extra": "x"}, "name": "{{ env }}"}
    with pytest.raises(TemplateVariableError, match="never uses"):
        check_signature_complete("s", body, body["$vars"])


def test_check_signature_complete_counts_forwarded_var_as_used():
    """A variable used only as a forwarded nested-$ref $vars value is 'used'."""
    body = {
        "$vars": {"env": None},
        "tables": [{"$ref": "$defs/tables/x", "$vars": {"env": "{{ env }}"}}],
    }
    check_signature_complete("s", body, body["$vars"])


def test_check_signature_complete_rejects_placeholder_default():
    """A default value may not itself be a placeholder (literal-only defaults)."""
    body = {"$vars": {"env": "{{ other }}"}, "name": "{{ env }}"}
    with pytest.raises(TemplateVariableError, match="literal-only"):
        check_signature_complete("s", body, body["$vars"])


def test_check_signature_complete_rejects_non_string_default():
    """A non-string default value is rejected."""
    body = {"$vars": {"env": None, "n": 3}, "name": "{{ env }}_{{ n }}"}
    with pytest.raises(TemplateVariableError, match="must be a string"):
        check_signature_complete("s", body, body["$vars"])
