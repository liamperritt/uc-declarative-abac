from __future__ import annotations

import copy
from typing import Any

from uc_declarative_abac.types import ResolutionError, UnreferencedDefinitionError


def resolve_refs(definitions: dict, resources: dict) -> dict:
    """Resolve all $ref entries and inline $defs/... string values using the definitions registry.

    Walks the resources dict recursively and resolves two forms of reference:

    1. **$ref dicts** — ``{"$ref": "$defs/<type>/<key>", ...}`` — the definition is
       looked up, deep-copied, sibling keys are applied as overrides, and nested
       refs are resolved recursively.
    2. **Inline $defs strings** — any string value matching ``$defs/<type>/<key>``
       is replaced with the deep-copied definition content and resolved recursively
       (no overrides, since there are no sibling keys on a plain string value).

    Returns a flat dict ready for ResourcesConfig.model_validate(),
    i.e. {"catalogs": {...}} with all refs resolved and definitions stripped.

    Raises UnreferencedDefinitionError if any definitions are not referenced.
    """
    referenced: set[str] = set()
    visited: set[str] = set()
    result = _resolve_node(definitions, resources, referenced, visited)

    all_refs = {
        f"$defs/{def_type}/{def_key}"
        for def_type, entries in definitions.items()
        if isinstance(entries, dict)
        for def_key in entries
    }
    unreferenced = all_refs - referenced
    if unreferenced:
        keys = sorted(unreferenced)
        raise UnreferencedDefinitionError(
            f"Unreferenced definitions: {', '.join(keys)}"
        )

    return result


def _resolve_node(definitions: dict, node: Any, referenced: set[str], visited: set[str]) -> Any:
    """Recursively resolve $ref entries within an arbitrary node."""
    if isinstance(node, dict):
        return _resolve_dict(definitions, node, referenced, visited)
    if isinstance(node, list):
        return [_resolve_node(definitions, item, referenced, visited) for item in node]
    if isinstance(node, str) and node.startswith("$defs/"):
        return _resolve_inline_defs_string(definitions, node, referenced, visited)
    return node


def _resolve_dict(definitions: dict, node: dict, referenced: set[str], visited: set[str]) -> dict:
    """Resolve a single dict node, handling $ref if present."""
    if "$ref" in node:
        return _resolve_ref(definitions, node, referenced, visited)
    return {key: _resolve_node(definitions, value, referenced, visited) for key, value in node.items()}


def _resolve_ref(definitions: dict, node: dict, referenced: set[str], visited: set[str]) -> dict:
    """Look up a $ref, apply overrides, and recursively resolve the result."""
    ref_path = node["$ref"]
    if ref_path in visited:
        raise ResolutionError(f"Circular $ref detected: {ref_path}")
    visited.add(ref_path)
    referenced.add(ref_path)
    definition = _lookup_definition(definitions, ref_path)
    resolved = copy.deepcopy(definition)

    # Apply overrides — top-level replacement, no deep merge
    overrides = {k: v for k, v in node.items() if k != "$ref"}
    resolved.update(overrides)

    # Recursively resolve any nested $ref entries
    result = _resolve_node(definitions, resolved, referenced, visited)
    visited.discard(ref_path)
    return result


def _resolve_inline_defs_string(definitions: dict, ref_path: str, referenced: set[str], visited: set[str]) -> Any:
    """Resolve a bare $defs/... string value the same way a $ref dict is resolved."""
    if ref_path in visited:
        raise ResolutionError(f"Circular $ref detected: {ref_path}")
    visited.add(ref_path)
    referenced.add(ref_path)
    definition = _lookup_definition(definitions, ref_path)
    resolved = copy.deepcopy(definition)
    result = _resolve_node(definitions, resolved, referenced, visited)
    visited.discard(ref_path)
    return result


def _lookup_definition(definitions: dict, ref: str) -> dict:
    """Parse a $ref string and look up the definition.

    Expected format: $defs/<type>/<key>
    """
    prefix = "$defs/"
    if not ref.startswith(prefix):
        raise ResolutionError(f"Invalid $ref format: {ref}")

    remainder = ref[len(prefix):]
    try:
        slash_idx = remainder.index("/")
    except ValueError:
        raise ResolutionError(f"Invalid $ref format (missing type/key separator): {ref}")
    def_type = remainder[:slash_idx]
    def_key = remainder[slash_idx + 1:]

    type_defs = definitions.get(def_type, {})
    if def_key not in type_defs:
        raise ResolutionError(f"Unresolved $ref: {ref} (key '{def_key}' not found in '{def_type}')")

    return type_defs[def_key]
