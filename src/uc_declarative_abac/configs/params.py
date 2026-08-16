"""Template-parameter helpers for the config resolver.

A ``definitions`` entry may be a *template* containing ``{{ placeholder }}`` tokens;
a ``$ref`` that instantiates it supplies concrete values via a sibling ``$params``
block, and a definition may declare per-parameter defaults via its own ``$params``
block. This module is the single source of truth for detecting, validating, and
substituting those tokens. It is dependency-light and imported by ``resolver.py``
(never the reverse).

Delimiter: ``{{ name }}`` wraps a bare parameter name (optional inner whitespace).
Literal double braces are escaped by doubling — ``{{{{`` renders a literal ``{{``
and ``}}}}`` a literal ``}}`` — so genuine ``{{ }}`` in SQL function bodies survives.

Structure-awareness (see ``collect_placeholders`` / ``substitute_in_body``): within a
template body, plain values and a nested ``$ref``'s ``$params`` *values* (forwarding)
belong to the enclosing template's parameter scope; a nested ``$ref``'s target string
and its other override values belong to that child ``$ref`` and are left untouched.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from uc_declarative_abac.utils import TemplateParameterError

# A single token scanner. Order matters: the escaped four-brace sequences are matched
# before the two-brace placeholder, so `{{{{ env }}}}` is read as literal braces around
# ` env `, never as a placeholder. Only the third alternative captures a name (group 1).
_TOKEN_RE = re.compile(
    r"\{\{\{\{"  # escaped literal "{{"
    r"|\}\}\}\}"  # escaped literal "}}"
    r"|\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}"  # a {{ placeholder }}
)

_REF_KEY = "$ref"
_PARAMS_KEY = "$params"


def _quote_names(names) -> str:
    """Render an iterable of parameter names as a sorted, single-quoted, comma list."""
    return ", ".join(f"'{name}'" for name in sorted(names))


def find_placeholders(text: str) -> set[str]:
    """Return the set of parameter names referenced by ``{{ name }}`` tokens in ``text``.

    Escaped ``{{{{ ... }}}}`` sequences are not placeholders and contribute nothing.
    """
    return {m.group(1) for m in _TOKEN_RE.finditer(text) if m.group(1) is not None}


def substitute(text: str, params: dict[str, str]) -> str:
    """Replace each ``{{ name }}`` token in ``text`` with ``params[name]``.

    Only tokens whose name is present in ``params`` are replaced; any other token is
    left intact (an unbound placeholder is caught elsewhere). Escaped ``{{{{``/``}}}}``
    sequences are **not** unescaped here — that happens once, at the end of resolution,
    via ``finalise`` — so a substituted string is never re-scanned as if its escaped
    braces were live placeholders.
    """

    def _replace(match: re.Match) -> str:
        name = match.group(1)
        if name is None:
            return match.group(0)  # an escaped {{{{ or }}}} — leave for finalise()
        if name not in params:
            return match.group(0)  # unbound here — reported elsewhere
        return params[name]

    return _TOKEN_RE.sub(_replace, text)


def unescape(text: str) -> str:
    """Collapse escaped double-braces: ``{{{{`` -> ``{{`` and ``}}}}`` -> ``}}``."""
    return text.replace("{{{{", "{{").replace("}}}}", "}}")


def collect_placeholders(node: Any) -> set[str]:
    """Collect every parameter name referenced within a template body, structure-aware.

    Scans string *values* only (never dict keys). At a nested ``$ref`` dict, only the
    ``$params`` values are in the enclosing template's scope (forwarding); the ``$ref``
    target and the ``$ref``'s other override values belong to that child and are skipped.
    A forwarding-only parameter — used solely as a nested ``$ref``'s ``$params`` value —
    therefore counts as used.
    """
    found: set[str] = set()
    _collect(node, found)
    return found


def _collect(node: Any, found: set[str]) -> None:
    if isinstance(node, dict):
        if _REF_KEY in node:
            for value in (node.get(_PARAMS_KEY) or {}).values():
                _collect(value, found)
            return
        for value in node.values():
            _collect(value, found)
    elif isinstance(node, list):
        for item in node:
            _collect(item, found)
    elif isinstance(node, str):
        found |= find_placeholders(node)


def substitute_in_body(body: Any, params: dict[str, str]) -> Any:
    """Return a copy of ``body`` with placeholders substituted, structure-aware.

    Substitutes plain string values and a nested ``$ref``'s ``$params`` values (so a
    forwarded value becomes a literal before that child ``$ref`` is expanded). A nested
    ``$ref``'s target and its other override values are left untouched — they are bound
    by that child ``$ref``'s own ``$params`` when it expands.
    """
    return _substitute(copy.deepcopy(body), params)


def _substitute(node: Any, params: dict[str, str]) -> Any:
    if isinstance(node, dict):
        if _REF_KEY in node:
            ref_params = node.get(_PARAMS_KEY)
            if isinstance(ref_params, dict):
                node[_PARAMS_KEY] = {
                    key: _substitute(value, params) for key, value in ref_params.items()
                }
            return node
        return {key: _substitute(value, params) for key, value in node.items()}
    if isinstance(node, list):
        return [_substitute(item, params) for item in node]
    if isinstance(node, str):
        return substitute(node, params)
    return node


def finalise(node: Any) -> Any:
    """Final placeholder pass over a fully-resolved tree.

    Any remaining live ``{{ name }}`` token is a placeholder that no ``$ref`` bound —
    a hard error, wherever it sits (a plain resource value, or a forwarded value with
    nothing to bind it). Escaped ``{{{{ ... }}}}`` sequences are not placeholders and
    are collapsed to their literal braces. Runs once, after all ``$ref`` expansion.
    """
    return _finalise(node)


def _finalise(node: Any) -> Any:
    if isinstance(node, dict):
        return {key: _finalise(value) for key, value in node.items()}
    if isinstance(node, list):
        return [_finalise(item) for item in node]
    if isinstance(node, str):
        unresolved = find_placeholders(node)
        if unresolved:
            raise TemplateParameterError(
                f"Unbound template parameter(s) {_quote_names(unresolved)} in value "
                f"{node!r}: a '{{{{ ... }}}}' placeholder can only appear in a value "
                f"bound by a $ref's $params (a definition body or a $ref override value)."
            )
        return unescape(node)
    return node


def check_string_params(params: dict[str, Any], *, context: str) -> None:
    """Assert every ``$params`` value is a string (or ``None`` = not supplied).

    ``None`` is permitted: on a definition it declares a required parameter; on a ``$ref``
    it is dropped before this check. Numbers, booleans, lists, and maps are rejected —
    a placeholder interpolates into a string, and quoting keeps the rendering explicit.
    """
    for name, value in params.items():
        if value is None or isinstance(value, str):
            continue
        raise TemplateParameterError(
            f"Template parameter '{name}' in {context} must be a string, got "
            f'{type(value).__name__} ({value!r}); quote it (e.g. "{value}").'
        )


def check_no_unbound(used: set[str], available: set[str], *, ref: str) -> None:
    """Assert every placeholder used by a referenced template has a value at the ``$ref``."""
    missing = used - available
    if missing:
        raise TemplateParameterError(
            f"Missing template parameter(s) {_quote_names(missing)} for $ref '{ref}': "
            f"the template uses these placeholders but neither $params nor a definition "
            f"default supplies a value."
        )


def check_no_unused(supplied: set[str], used: set[str], *, ref: str) -> None:
    """Assert every parameter supplied at a ``$ref`` is actually used by the template."""
    unused = supplied - used
    if unused:
        raise TemplateParameterError(
            f"Unused template parameter(s) {_quote_names(unused)} supplied to $ref "
            f"'{ref}': the template has no matching '{{{{ ... }}}}' placeholder (check "
            f"for a name mismatch)."
        )


def check_signature_complete(
    def_key: str, body: dict, declared_params: dict[str, Any]
) -> None:
    """Enforce the "declared => complete" rule for a definition's ``$params`` signature.

    If a definition declares a ``$params`` block, it must be a complete signature: the
    declared names and the placeholders the body actually uses must match exactly, in
    both directions. Declared values must be strings (defaults) or ``None`` (required),
    and a default value may not itself contain a placeholder (literal-only defaults).
    """
    check_string_params(declared_params, context=f"definition '{def_key}'")

    for name, value in declared_params.items():
        if isinstance(value, str) and find_placeholders(value):
            raise TemplateParameterError(
                f"Default for parameter '{name}' in definition '{def_key}' may not "
                f"contain a placeholder (defaults are literal-only): {value!r}."
            )

    declared = set(declared_params)
    used = collect_placeholders(_body_without_params(body))

    undeclared = used - declared
    if undeclared:
        raise TemplateParameterError(
            f"Definition '{def_key}' declares a $params signature but its body uses "
            f"undeclared placeholder(s) {_quote_names(undeclared)}; add them to $params "
            f"(with a default or as null for required)."
        )

    unused = declared - used
    if unused:
        raise TemplateParameterError(
            f"Definition '{def_key}' declares parameter(s) {_quote_names(unused)} in "
            f"$params that its body never uses; remove them or reference them via "
            f"'{{{{ ... }}}}'."
        )


def _body_without_params(body: dict) -> dict:
    """A shallow view of a definition body with its own top-level ``$params`` removed."""
    return {key: value for key, value in body.items() if key != _PARAMS_KEY}
