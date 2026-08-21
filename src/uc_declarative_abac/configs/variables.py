"""Template-variable helpers for the config resolver.

A ``definitions`` entry may be a *template* containing ``{{ placeholder }}`` tokens;
a ``$ref`` that instantiates it supplies concrete values via a sibling ``$vars``
block, and a definition may declare per-variable defaults via its own ``$vars``
block. This module is the single source of truth for detecting, validating, and
substituting those tokens. It is dependency-light and imported by ``resolver.py``
(never the reverse).

Delimiter: ``{{ name }}`` wraps a bare variable name (optional inner whitespace).
Literal double braces are escaped by doubling — ``{{{{`` renders a literal ``{{``
and ``}}}}`` a literal ``}}`` — so genuine ``{{ }}`` in SQL function bodies survives.

Structure-awareness (see ``collect_placeholders`` / ``substitute_in_body``): within a
template body, every string value — plain values, a nested ``$ref``'s ``$vars`` values
(forwarding), and a nested ``$ref``'s override values — belongs to the enclosing
template's variable scope and is bound here. Only a nested ``$ref``'s target string is
left untouched (it is resolved structurally and may never hold a placeholder). In short:
the definition that *writes* a placeholder is the one that binds it.

Dict *keys* are literal by default, with one exception: the keys of a **user-data map**
(the fields in ``TEMPLATABLE_KEY_FIELDS`` — the tag-name maps ``tags``, ``has_tags``,
``has_any_of_tags``, plus the identity-attribute maps ``has_identity_attributes`` and friends)
are user data, so a placeholder in such a key is bound and substituted like a value. Every other
key — config field names, ``$ref``/``$defs`` targets, resource identity keys — stays literal;
a placeholder there is a hard error at ``finalise``.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from uc_declarative_abac.utils import TemplateVariableError

# A single token scanner. Order matters: the escaped four-brace sequences are matched
# before the two-brace placeholder, so `{{{{ env }}}}` is read as literal braces around
# ` env `, never as a placeholder. Only the third alternative captures a name (group 1).
_TOKEN_RE = re.compile(
    r"\{\{\{\{"  # escaped literal "{{"
    r"|\}\}\}\}"  # escaped literal "}}"
    r"|\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}"  # a {{ placeholder }}
)

# A validation-only scanner for *malformed* placeholders — a `{{ token }}` whose token is
# identifier-shaped but not a valid bare identifier (e.g. `{{ my-var }}`, `{{ a.b }}`,
# `{{ 1x }}`), which `_TOKEN_RE` never matches and so would otherwise pass through as literal
# text. Order matters: escapes are consumed first (so `{{{{ my-var }}}}` is a literal, not a
# hit), then a valid placeholder (non-capturing — handled by substitution), and only then the
# malformed alternative (group 1). The single-token, word-chars-plus-`.`/`-` shape deliberately
# does NOT match legitimate literal SQL/JSON braces (`{{"a":1}}`, `{{ SELECT 1 }}`, `{{ f(x) }}`),
# preserving the delimiter's collision-safety.
_MALFORMED_RE = re.compile(
    r"\{\{\{\{"  # escaped literal "{{"
    r"|\}\}\}\}"  # escaped literal "}}"
    r"|\{\{\s*[A-Za-z_][A-Za-z0-9_]*\s*\}\}"  # a VALID {{ placeholder }} — ignored
    r"|\{\{\s*([A-Za-z0-9_][\w.\-]*)\s*\}\}"  # identifier-shaped but INVALID -> group 1
)

_REF_KEY = "$ref"
_VARS_KEY = "$vars"

# Fields whose child-dict KEYS are user data, so a ``{{ placeholder }}`` may appear in those keys
# and is bound like any value placeholder. Every other key — config field names, ``$ref``/``$defs``
# targets, and resource identity keys (catalogs/governed_tags/groups) — stays literal. Mirrors the
# user-data maps in ``configs/models.py``: ``tags`` on taggables, ``has_tags``/``has_any_of_tags``
# on policies and column aliases, and the identity-attribute maps on FGAC policies (whose keys are
# identity-attribute names). A drift-guard test asserts these names are real model fields, so this
# stays dependency-light (no runtime import of the model layer).
TEMPLATABLE_KEY_FIELDS = frozenset(
    {
        "tags",
        "has_tags",
        "has_any_of_tags",
        "has_identity_attributes",
        "has_any_of_identity_attributes",
        "has_identity_attribute_tag_matches",
        "has_any_of_identity_attribute_tag_matches",
    }
)


def _quote_names(names) -> str:
    """Render an iterable of variable names as a sorted, single-quoted, comma list."""
    return ", ".join(f"'{name}'" for name in sorted(names))


def find_placeholders(text: str) -> set[str]:
    """Return the set of variable names referenced by ``{{ name }}`` tokens in ``text``.

    Escaped ``{{{{ ... }}}}`` sequences are not placeholders and contribute nothing.
    """
    return {m.group(1) for m in _TOKEN_RE.finditer(text) if m.group(1) is not None}


def find_malformed_placeholders(text: str) -> set[str]:
    """Return identifier-shaped-but-invalid ``{{ token }}`` names in ``text``.

    These are tokens a user likely intended as a placeholder but whose name is not a valid
    bare identifier (``{{ my-var }}``, ``{{ a.b }}``, ``{{ 1x }}``). ``_TOKEN_RE`` never
    matches them, so without this they would pass through as literal text. Escaped
    ``{{{{ ... }}}}`` sequences and legitimate literal braces (``{{"a":1}}``, ``{{ SELECT 1 }}``)
    are not reported. See ``_MALFORMED_RE``.
    """
    return {
        m.group(1) for m in _MALFORMED_RE.finditer(text) if m.group(1) is not None
    }


def substitute(text: str, variables: dict[str, str]) -> str:
    """Replace each ``{{ name }}`` token in ``text`` with ``variables[name]``.

    Only tokens whose name is present in ``variables`` are replaced; any other token is
    left intact (an unbound placeholder is caught elsewhere). Escaped ``{{{{``/``}}}}``
    sequences are **not** unescaped here — that happens once, at the end of resolution,
    via ``finalise`` — so a substituted string is never re-scanned as if its escaped
    braces were live placeholders.
    """

    def _replace(match: re.Match) -> str:
        name = match.group(1)
        if name is None:
            return match.group(0)  # an escaped {{{{ or }}}} — leave for finalise()
        if name not in variables:
            return match.group(0)  # unbound here — reported elsewhere
        return variables[name]

    return _TOKEN_RE.sub(_replace, text)


def unescape(text: str) -> str:
    """Collapse escaped double-braces: ``{{{{`` -> ``{{`` and ``}}}}`` -> ``}}``."""
    return text.replace("{{{{", "{{").replace("}}}}", "}}")


def collect_placeholders(node: Any) -> set[str]:
    """Collect every variable name referenced within a template body, structure-aware.

    Scans string *values*, plus the keys of tag-name maps (``TEMPLATABLE_KEY_FIELDS``) — a
    placeholder in a tag name counts as used. All other dict keys are literal and skipped. At a
    nested ``$ref`` dict, every value except the ``$ref`` target — its ``$vars`` values
    (forwarding) and its override values alike — is in the enclosing template's scope and is
    counted here; only the ``$ref`` target string is skipped. So both a forwarding-only variable
    (used solely as a nested ``$ref``'s ``$vars`` value) and a variable used only in an override
    the enclosing template writes onto a child ``$ref`` count as used.
    """
    found: set[str] = set()
    _collect(node, found)
    return found


def _collect(node: Any, found: set[str], keys_templatable: bool = False) -> None:
    if isinstance(node, dict):
        # ``keys_templatable`` is set by the parent when this dict sits under a tag-map field
        # (see ``TEMPLATABLE_KEY_FIELDS``): its keys are tag names, so their placeholders count
        # as used. The $ref/$vars structural keys are never tag names, so they are skipped.
        if keys_templatable:
            for key in node:
                if isinstance(key, str) and key not in (_REF_KEY, _VARS_KEY):
                    found |= find_placeholders(key)
        ref_site = _REF_KEY in node
        for key, value in node.items():
            # At a nested $ref site only the $ref target is excluded (resolved structurally,
            # never templated); every other value — $vars forwarding and overrides alike — is
            # the enclosing template's text. A child's keys are templatable iff its field is a
            # tag map.
            if ref_site and key == _REF_KEY:
                continue
            _collect(value, found, key in TEMPLATABLE_KEY_FIELDS)
    elif isinstance(node, list):
        for item in node:
            _collect(item, found, keys_templatable)
    elif isinstance(node, str):
        found |= find_placeholders(node)


def substitute_in_body(body: Any, variables: dict[str, str]) -> Any:
    """Return a copy of ``body`` with placeholders substituted, structure-aware.

    Substitutes every string value except a nested ``$ref``'s target: plain values, a
    nested ``$ref``'s ``$vars`` values (forwarding), and a nested ``$ref``'s override
    values are all bound in the enclosing template's scope, so they become literals before
    that child ``$ref`` is expanded. Only the ``$ref`` target string is left untouched (it
    is resolved structurally). Tag-name map keys (``TEMPLATABLE_KEY_FIELDS``) are substituted
    too; all other dict keys are left literal. The enclosing definition binds every placeholder
    it writes.
    """
    return _substitute(copy.deepcopy(body), variables)


def _substitute(node: Any, variables: dict[str, str], keys_templatable: bool = False) -> Any:
    if isinstance(node, dict):
        ref_site = _REF_KEY in node
        result: dict = {}
        for key, value in node.items():
            # A tag-map key (parent set ``keys_templatable``) is substituted like a value; the
            # $ref/$vars structural keys never are. Only the $ref target value is left untouched
            # (resolved structurally); every other value is substituted, and a child's keys are
            # templatable iff its field is a tag map.
            new_key = (
                substitute(key, variables)
                if keys_templatable and isinstance(key, str) and key not in (_REF_KEY, _VARS_KEY)
                else key
            )
            if ref_site and key == _REF_KEY:
                result[new_key] = value
            else:
                result[new_key] = _substitute(value, variables, key in TEMPLATABLE_KEY_FIELDS)
        return result
    if isinstance(node, list):
        return [_substitute(item, variables, keys_templatable) for item in node]
    if isinstance(node, str):
        return substitute(node, variables)
    return node


def finalise(node: Any) -> Any:
    """Final placeholder pass over a fully-resolved tree.

    Any remaining live ``{{ name }}`` token is a placeholder that nothing bound — a hard
    error, wherever it sits. In practice these are caught earlier (an unbound definition
    placeholder by ``check_no_unbound`` at its ``$ref``; a resource placeholder by
    ``check_no_placeholders_in_resources``), so this is a defensive backstop. It also
    rejects any *malformed* placeholder (an identifier-shaped ``{{ token }}`` whose name is
    not a valid bare identifier), which no earlier check sees because ``_TOKEN_RE`` never
    matched it. Escaped ``{{{{ ... }}}}`` sequences are not placeholders and are collapsed
    to their literal braces. Runs once, after all ``$ref`` expansion.
    """
    return _finalise(node)


def _finalise(node: Any) -> Any:
    if isinstance(node, dict):
        # Keys are finalised too: a live placeholder in a key is either an unbound tag-map key
        # or a placeholder wrongly placed in a non-templatable key — both hard errors here (a
        # tag-map key is the only key that is ever templated, and it is bound during resolution).
        return {
            (_finalise_str(key) if isinstance(key, str) else key): _finalise(value)
            for key, value in node.items()
        }
    if isinstance(node, list):
        return [_finalise(item) for item in node]
    if isinstance(node, str):
        return _finalise_str(node)
    return node


def _finalise_str(text: str) -> str:
    """Finalise one string (a value or a tag-map key): any surviving placeholder is a hard
    error, a malformed placeholder is a hard error, and escaped braces collapse to literals."""
    unresolved = find_placeholders(text)
    if unresolved:
        raise TemplateVariableError(
            f"Unbound template variable(s) {_quote_names(unresolved)} in "
            f"{text!r}: a '{{{{ ... }}}}' placeholder is bound by the enclosing "
            f"definition's $vars and may appear only inside a definition (in a value, or a "
            f"tag-name map key), never in a resource, which must be concrete."
        )
    malformed = find_malformed_placeholders(text)
    if malformed:
        raise TemplateVariableError(
            f"Malformed template placeholder(s) {_quote_names(malformed)} in "
            f"{text!r}: a '{{{{ ... }}}}' variable reference must be a bare identifier "
            f"(letters, digits, and underscore, not starting with a digit). Rename the "
            f"variable, or if the braces are literal escape them by doubling."
        )
    return unescape(text)


def check_no_placeholders_in_resources(resources: Any) -> None:
    """Assert no ``{{ placeholder }}`` appears anywhere in the authored resources tree.

    Placeholders are a *definition* facility, bound by the enclosing definition's
    ``$vars``. Resources are the concrete instance layer and carry no ``$vars`` scope, so
    a placeholder anywhere under ``resources`` (a plain value, a ``$ref`` override value,
    a ``$vars`` value, or a dict key — tag-name keys included) has nothing to bind it and is
    a hard error. This scans the raw
    resources — before any ``$ref`` expansion inlines definition bodies — so it never sees
    (and never faults) the placeholders that legitimately live inside definitions. Escaped
    ``{{{{ ... }}}}`` sequences are not placeholders and are ignored (they survive to
    ``finalise``, which collapses them to literal braces).
    """
    _check_no_placeholders(resources, path="resources")


def _check_no_placeholders(node: Any, *, path: str) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str) and find_placeholders(key):
                names = find_placeholders(key)
                raise TemplateVariableError(
                    f"Template placeholder(s) {_quote_names(names)} found in a resource "
                    f"key at {path}.{key!r}. Placeholders are bound by the enclosing "
                    f"definition's $vars; a resource is the concrete instance layer and must "
                    f"not contain '{{{{ ... }}}}' — supply the literal key, or move the "
                    f"templating into a definition and instantiate it via $ref + $vars."
                )
            _check_no_placeholders(value, path=f"{path}.{key}")
    elif isinstance(node, list):
        for index, item in enumerate(node):
            _check_no_placeholders(item, path=f"{path}[{index}]")
    elif isinstance(node, str):
        names = find_placeholders(node)
        if names:
            raise TemplateVariableError(
                f"Template placeholder(s) {_quote_names(names)} found in a resource "
                f"value at {path}: {node!r}. Placeholders are bound by the enclosing "
                f"definition's $vars; a resource is the concrete instance layer and must "
                f"not contain '{{{{ ... }}}}' — supply the literal value, or move the "
                f"templating into a definition and instantiate it via $ref + $vars."
            )


def check_string_vars(variables: dict[str, Any], *, context: str) -> None:
    """Assert every ``$vars`` value is a plain string (or ``None`` = not supplied).

    ``None`` is permitted: on a definition it declares a required variable; on a ``$ref``
    it is dropped before this check. Numbers, booleans, lists, and maps are rejected —
    a placeholder interpolates into a string, and quoting keeps the rendering explicit. A
    string that looks like a reference (``$defs/...``) is rejected too: ``$vars`` values are
    literal strings (or a forwarding ``{{ ... }}`` placeholder), never definition references.
    """
    for name, value in variables.items():
        if value is None:
            continue
        if not isinstance(value, str):
            raise TemplateVariableError(
                f"Template variable '{name}' in {context} must be a string, got "
                f'{type(value).__name__} ({value!r}); quote it (e.g. "{value}").'
            )
        if value.startswith("$defs/"):
            raise TemplateVariableError(
                f"Template variable '{name}' in {context} has a reference-like value "
                f"{value!r}: $vars values are literal strings (or a forwarding "
                f"'{{{{ ... }}}}' placeholder), not '$defs/...' references."
            )


def check_no_unbound(required: set[str], available: set[str], *, ref: str) -> None:
    """Assert every variable a referenced template requires has a value at the ``$ref``.

    ``required`` is the template's parameter set — the placeholders its body uses plus the
    variables it declares in its own ``$vars`` signature (a null-declared variable is
    required even if the caller overrides away the field that referenced it).
    """
    missing = required - available
    if missing:
        raise TemplateVariableError(
            f"Missing template variable(s) {_quote_names(missing)} for $ref '{ref}': "
            f"the template requires these variables (used in its body, or declared as a "
            f"required — null — $vars entry) but neither $vars nor a definition default "
            f"supplies a value."
        )


def check_no_unused(supplied: set[str], used: set[str], *, ref: str) -> None:
    """Assert every variable supplied at a ``$ref`` is actually used by the template."""
    unused = supplied - used
    if unused:
        raise TemplateVariableError(
            f"Unused template variable(s) {_quote_names(unused)} supplied to $ref "
            f"'{ref}': the template has no matching '{{{{ ... }}}}' placeholder (check "
            f"for a name mismatch)."
        )


def check_signature_complete(
    def_key: str,
    body: dict,
    declared_variables: dict[str, Any],
    *,
    inherited_uses: frozenset[str] | set[str] = frozenset(),
) -> None:
    """Enforce the "declared => complete" rule for a definition's ``$vars`` signature.

    If a definition declares a ``$vars`` block, it must be a complete signature: the
    declared names and the placeholders the body actually uses must match exactly, in
    both directions. Declared values must be strings (defaults) or ``None`` (required),
    and a default value may not itself contain a placeholder (literal-only defaults).

    ``inherited_uses`` are variables the definition forwards to a base definition it
    extends via a root ``$ref`` (see ``accepted_vars``). A definition whose body root is
    a ``$ref`` implicitly forwards its own variables into that base by name, so a declared
    variable that the base accepts counts as *used* even when the body writes no
    ``{{ placeholder }}`` for it — this is what lets a variable be declared purely to pass
    through to the base. Inherited uses relax only the "unused declared variable" direction;
    they never force a base's internally-defaulted variable into this definition's signature.
    """
    check_string_vars(declared_variables, context=f"definition '{def_key}'")

    for name, value in declared_variables.items():
        if isinstance(value, str) and find_placeholders(value):
            raise TemplateVariableError(
                f"Default for variable '{name}' in definition '{def_key}' may not "
                f"contain a placeholder (defaults are literal-only): {value!r}."
            )

    declared = set(declared_variables)
    used = collect_placeholders(_body_without_vars(body))

    undeclared = used - declared
    if undeclared:
        raise TemplateVariableError(
            f"Definition '{def_key}' declares a $vars signature but its body uses "
            f"undeclared placeholder(s) {_quote_names(undeclared)}; add them to $vars "
            f"(with a default or as null for required)."
        )

    unused = declared - (used | set(inherited_uses))
    if unused:
        raise TemplateVariableError(
            f"Definition '{def_key}' declares variable(s) {_quote_names(unused)} in "
            f"$vars that its body never uses; remove them or reference them via "
            f"'{{{{ ... }}}}'."
        )


def accepted_vars(body: Any) -> set[str]:
    """The variables a definition accepts: its declared ``$vars`` names plus every
    placeholder its body writes.

    This is the definition's parameter surface — what a caller (or a definition that
    extends it via a root ``$ref``) may supply without tripping the "unused argument"
    check. Empty for a non-dict body (e.g. a bare list of columns), which has no ``$vars``
    scope. Reuses ``collect_placeholders`` so token detection stays single-sourced.
    """
    if not isinstance(body, dict):
        return set()
    declared = set(body.get(_VARS_KEY) or {})
    return declared | collect_placeholders(_body_without_vars(body))


def _body_without_vars(body: dict) -> dict:
    """A shallow view of a definition body with its own top-level ``$vars`` removed."""
    return {key: value for key, value in body.items() if key != _VARS_KEY}
