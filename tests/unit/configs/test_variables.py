from __future__ import annotations

import pytest

from uc_declarative_abac.configs.variables import (
    TEMPLATABLE_KEY_FIELDS,
    accepted_vars,
    check_no_placeholders_in_resources,
    check_no_unbound,
    check_no_unused,
    check_signature_complete,
    check_string_vars,
    collect_placeholders,
    finalise,
    find_malformed_placeholders,
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
# find_malformed_placeholders
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        ("{{ my-var }}", {"my-var"}),  # hyphen
        ("{{ a.b }}", {"a.b"}),  # dot
        ("{{ 1x }}", {"1x"}),  # leading digit
        ("prefix_{{ env-1 }}_suffix", {"env-1"}),
    ],
)
def test_find_malformed_placeholders_flags_identifier_shaped_invalid(text, expected):
    """A `{{ token }}` that is identifier-shaped but not a valid identifier is flagged."""
    assert find_malformed_placeholders(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "{{ env }}",  # valid — handled by substitution, not malformed
        "{{env}}",  # valid, unspaced
        '{{"a":1}}',  # literal JSON braces
        "{{ SELECT 1 }}",  # literal SQL (multi-token)
        "{{ f(x) }}",  # literal SQL (parens)
        "{{{{ my-var }}}}",  # escaped literal braces — inner not captured
        "finance-team",  # hyphen but no braces
        "plain text",
    ],
)
def test_find_malformed_placeholders_ignores_valid_literal_and_escaped(text):
    """Valid placeholders, literal SQL/JSON braces, and escaped braces are not flagged."""
    assert find_malformed_placeholders(text) == set()


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


def test_finalise_raises_on_malformed_placeholder():
    """An identifier-shaped-but-invalid placeholder surviving resolution is a hard error."""
    with pytest.raises(TemplateVariableError, match="[Mm]alformed"):
        finalise({"name": "ingestion_{{ my-var }}"})


def test_finalise_allows_escaped_invalid_identifier_braces():
    """Escaped braces around a non-identifier are literal, not a malformed placeholder."""
    assert finalise("{{{{ my-var }}}}") == "{{ my-var }}"


# ---------------------------------------------------------------------------
# collect_placeholders (structure-aware)
# ---------------------------------------------------------------------------


def test_collect_placeholders_scans_plain_values():
    """Placeholders in ordinary string values are collected."""
    body = {"name": "s_{{ env }}", "tags": {"tier": "{{ layer }}"}}
    assert collect_placeholders(body) == {"env", "layer"}


def test_collect_placeholders_skips_non_tag_dict_keys():
    """A placeholder in an ordinary (non-tag) dict key is not a variable position."""
    body = {"{{ env }}": "literal"}
    assert collect_placeholders(body) == set()


def test_collect_placeholders_counts_tag_map_keys():
    """A placeholder in a tag-name map key (tags / has_tags / has_any_of_tags) counts as used."""
    body = {
        "tags": {"uc_gov_{{ env }}_owner": "platform"},
        "has_any_of_tags": {"finance_{{ region }}": "*"},
    }
    assert collect_placeholders(body) == {"env", "region"}


def test_collect_placeholders_skips_ref_and_vars_keys_in_tag_map():
    """Inside a tag map, the structural $ref / $vars keys are never treated as tag names."""
    body = {
        "tags": {
            "$ref": "$defs/tags/base",
            "env_{{ e }}": "{{ e }}",  # a real tag name — counted
        },
    }
    assert collect_placeholders(body) == {"e"}


def test_collect_placeholders_counts_forwarded_nested_ref_vars():
    """A placeholder used only as a nested $ref's $vars value counts as used."""
    body = {
        "tables": [
            {"$ref": "$defs/tables/x", "$vars": {"env": "{{ env }}"}},
        ],
    }
    assert collect_placeholders(body) == {"env"}


def test_collect_placeholders_counts_nested_ref_overrides_ignores_target():
    """A nested $ref's $vars and override values are the enclosing scope's; only the target is not."""
    body = {
        "tables": [
            {
                "$ref": "$defs/tables/{{ x }}",  # target — structural, not counted
                "name": "{{ y }}",  # override value — enclosing scope, counted
                "$vars": {"env": "{{ env }}"},  # forwarding — counted
            },
        ],
    }
    assert collect_placeholders(body) == {"env", "y"}


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


def test_substitute_in_body_substitutes_nested_ref_overrides_leaves_target():
    """The parent substitutes a nested $ref's $vars and override values; the target is untouched."""
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
    assert entry["$ref"] == "$defs/tables/x"  # target untouched (structural)
    assert entry["name"] == "prod"  # override value → bound by enclosing scope
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


def test_check_string_vars_rejects_defs_reference_value():
    """A $vars value that looks like a $defs/ reference is rejected with a clear message."""
    with pytest.raises(TemplateVariableError, match="reference"):
        check_string_vars({"x": "$defs/columns/region"}, context="test")


def test_check_string_vars_accepts_forwarding_placeholder_value():
    """A forwarding `{{ ... }}` value is a valid (string) $vars value."""
    check_string_vars({"env": "{{ env }}"}, context="test")


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


def test_check_signature_complete_counts_child_ref_override_var_as_used():
    """A variable used only in an override the definition writes onto a child $ref is 'used'."""
    body = {
        "$vars": {"env": None},
        "tables": [{"$ref": "$defs/tables/x", "comment": "created in {{ env }}"}],
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


# ---------------------------------------------------------------------------
# check_no_placeholders_in_resources
# ---------------------------------------------------------------------------


def test_check_no_placeholders_in_resources_allows_clean_tree():
    """A resource tree with no placeholders (and $ref/$vars literals) passes."""
    resources = {
        "catalogs": {
            "c": {
                "name": "c",
                "schemas": [
                    {"$ref": "$defs/schemas/s", "$vars": {"env": "prod"}},
                ],
            },
        },
    }
    check_no_placeholders_in_resources(resources)  # no raise


def test_check_no_placeholders_in_resources_raises_on_plain_value():
    """A placeholder in a plain resource value is rejected, with the path in the message."""
    resources = {"catalogs": {"c": {"name": "ingestion_{{ env }}"}}}
    with pytest.raises(TemplateVariableError, match="catalogs.c.name"):
        check_no_placeholders_in_resources(resources)


def test_check_no_placeholders_in_resources_raises_on_ref_override_value():
    """A placeholder in a $ref override value at the resource level is rejected."""
    resources = {
        "catalogs": {
            "c": {
                "schemas": [
                    {"$ref": "$defs/schemas/s", "name": "{{ env }}_raw"},
                ],
            },
        },
    }
    with pytest.raises(TemplateVariableError, match="'env'"):
        check_no_placeholders_in_resources(resources)


def test_check_no_placeholders_in_resources_raises_on_vars_value():
    """A placeholder in a resource $vars value is rejected (resource $vars are literals)."""
    resources = {
        "catalogs": {
            "c": {
                "schemas": [
                    {"$ref": "$defs/schemas/s", "$vars": {"env": "{{ env }}"}},
                ],
            },
        },
    }
    with pytest.raises(TemplateVariableError, match="'env'"):
        check_no_placeholders_in_resources(resources)


def test_check_no_placeholders_in_resources_allows_escaped_braces():
    """Escaped {{{{ }}}} in a resource value is not a placeholder and is allowed."""
    resources = {
        "catalogs": {
            "c": {
                "functions": [
                    {"name": "f", "return": "CONCAT('{{{{', val, '}}}}')"},
                ],
            },
        },
    }
    check_no_placeholders_in_resources(resources)  # no raise


# ---------------------------------------------------------------------------
# accepted_vars
# ---------------------------------------------------------------------------


def test_accepted_vars_unions_declared_and_body_placeholders():
    """A definition accepts its declared $vars names plus placeholders its body writes."""
    body = {
        "$vars": {"env": None, "medallion": "bronze"},
        "name": "{{ env }}",
        "tags": {"tier": "{{ medallion }}"},
    }
    assert accepted_vars(body) == {"env", "medallion"}


def test_accepted_vars_counts_forwarded_placeholder():
    """A placeholder used only as a nested $ref's forwarding $vars value is accepted."""
    body = {
        "$vars": {"env": None},
        "tables": [{"$ref": "$defs/tables/t", "$vars": {"env": "{{ env }}"}}],
    }
    assert accepted_vars(body) == {"env"}


def test_accepted_vars_empty_for_non_dict():
    """A non-dict body (e.g. a bare column list) has no $vars scope."""
    assert accepted_vars(["a", "b"]) == set()


# ---------------------------------------------------------------------------
# check_signature_complete with inherited (forwarded-to-base) uses
# ---------------------------------------------------------------------------


def test_check_signature_complete_inherited_use_allows_pass_through_var():
    """A variable declared only to forward to a base counts as used when the base accepts it."""
    body = {"$ref": "$defs/schemas/base", "name": "default"}
    # `env` appears nowhere in the body, but the base accepts it (inherited use).
    check_signature_complete(
        "default", body, {"env": None}, inherited_uses={"env"}
    )  # no raise


def test_check_signature_complete_without_inherited_use_rejects_unused_var():
    """Without an inherited use, a declared-but-unused variable is still rejected."""
    body = {"$ref": "$defs/schemas/base", "name": "default"}
    with pytest.raises(TemplateVariableError, match="never uses"):
        check_signature_complete("default", body, {"env": None})


def test_check_signature_complete_inherited_use_does_not_excuse_body_typo():
    """Inherited uses relax only the unused direction — a body placeholder must still be declared."""
    body = {"$ref": "$defs/schemas/base", "name": "{{ environmnet }}"}
    with pytest.raises(TemplateVariableError, match="undeclared"):
        check_signature_complete(
            "default", body, {"env": None}, inherited_uses={"env"}
        )


# ---------------------------------------------------------------------------
# Tag-name map KEY templating
# ---------------------------------------------------------------------------


def test_substitute_in_body_substitutes_tag_map_key():
    """A placeholder in a tag-map key is substituted; a non-tag key is left literal."""
    body = {
        "name": "s_{{ env }}",
        "tags": {"uc_gov_{{ env }}_owner": "platform"},
    }
    result = substitute_in_body(body, {"env": "test"})
    assert result == {
        "name": "s_test",
        "tags": {"uc_gov_test_owner": "platform"},
    }


def test_substitute_in_body_leaves_ref_key_in_tag_map():
    """A $ref inside a tag map keeps its structural key; a sibling tag name is substituted."""
    body = {"tags": {"$ref": "$defs/tags/base", "env_{{ e }}": "{{ e }}"}}
    result = substitute_in_body(body, {"e": "prod"})
    assert result == {"tags": {"$ref": "$defs/tags/base", "env_prod": "prod"}}


def test_substitute_in_body_leaves_non_tag_key_literal():
    """A placeholder in a non-tag key is not substituted (only values / tag keys are)."""
    body = {"weird_{{ env }}_field": "{{ env }}"}
    assert substitute_in_body(body, {"env": "test"}) == {"weird_{{ env }}_field": "test"}


def test_finalise_raises_on_unbound_tag_map_key():
    """A tag-map key placeholder nothing bound is a hard error at finalise."""
    with pytest.raises(TemplateVariableError, match="[Uu]nbound"):
        finalise({"tags": {"uc_gov_{{ env }}_owner": "platform"}})


def test_finalise_raises_on_placeholder_in_non_tag_key():
    """A placeholder wrongly placed in a non-tag key surfaces as a hard error at finalise."""
    with pytest.raises(TemplateVariableError, match="[Uu]nbound"):
        finalise({"weird_{{ env }}_field": "x"})


def test_finalise_unescapes_tag_map_key():
    """Escaped braces in a tag-map key collapse to literals, like a value would."""
    assert finalise({"tags": {"lit_{{{{ x }}}}": "v"}}) == {"tags": {"lit_{{ x }}": "v"}}


def test_check_no_placeholders_in_resources_raises_on_tag_key():
    """A placeholder in a resource tag-map key is rejected — resources are concrete."""
    resources = {
        "catalogs": {
            "c": {"name": "c", "tags": {"uc_gov_{{ env }}_owner": "platform"}},
        },
    }
    with pytest.raises(TemplateVariableError, match="'env'"):
        check_no_placeholders_in_resources(resources)


# ---------------------------------------------------------------------------
# TEMPLATABLE_KEY_FIELDS drift guard
# ---------------------------------------------------------------------------


def test_templatable_key_fields_are_real_model_fields():
    """Every templatable-key field name must be an actual model field, so a rename fails loudly."""
    from uc_declarative_abac.configs.models import (
        BasePolicyConfig,
        BaseTaggableConfig,
        PolicyColumnAliasConfig,
    )

    assert "tags" in BaseTaggableConfig.model_fields
    for field in ("has_tags", "has_any_of_tags"):
        assert field in BasePolicyConfig.model_fields
        assert field in PolicyColumnAliasConfig.model_fields

    # And the constant lists exactly those tag-name maps — nothing stale, nothing missing.
    assert TEMPLATABLE_KEY_FIELDS == frozenset({"tags", "has_tags", "has_any_of_tags"})
