from __future__ import annotations

import copy
from typing import Any

from uc_abac_governor.types import ResolutionError


def resolve_refs(definitions: dict, resources: dict) -> dict:
    """Resolve all $ref entries in the resources dict using the definitions registry.

    Walks the resources dict recursively. For each dict with a $ref key:
    1. Parse the ref: $defs/<type>/<key> -> look up in definitions
    2. Deep-copy the definition
    3. Apply overrides (top-level replacement, no deep merge)
    4. Recursively resolve nested $ref entries

    Returns a flat dict ready for ConfigFile.model_validate(),
    i.e. {"catalogs": {...}} with all refs resolved and definitions stripped.
    """
    return _resolve_node(definitions, resources)


def _resolve_node(definitions: dict, node: Any) -> Any:
    """Recursively resolve $ref entries within an arbitrary node."""
    if isinstance(node, dict):
        return _resolve_dict(definitions, node)
    if isinstance(node, list):
        return [_resolve_node(definitions, item) for item in node]
    return node


def _resolve_dict(definitions: dict, node: dict) -> dict:
    """Resolve a single dict node, handling $ref if present."""
    if "$ref" in node:
        return _resolve_ref(definitions, node)
    return {key: _resolve_node(definitions, value) for key, value in node.items()}


def _resolve_ref(definitions: dict, node: dict) -> dict:
    """Look up a $ref, apply overrides, and recursively resolve the result."""
    ref_path = node["$ref"]
    definition = _lookup_definition(definitions, ref_path)
    resolved = copy.deepcopy(definition)

    # Apply overrides — top-level replacement, no deep merge
    overrides = {k: v for k, v in node.items() if k != "$ref"}
    resolved.update(overrides)

    # Recursively resolve any nested $ref entries
    return _resolve_node(definitions, resolved)


def _lookup_definition(definitions: dict, ref: str) -> dict:
    """Parse a $ref string and look up the definition.

    Expected format: $defs/<type>/<key>
    """
    prefix = "$defs/"
    if not ref.startswith(prefix):
        raise ResolutionError(f"Invalid $ref format: {ref}")

    remainder = ref[len(prefix):]
    slash_idx = remainder.index("/")
    def_type = remainder[:slash_idx]
    def_key = remainder[slash_idx + 1:]

    type_defs = definitions.get(def_type, {})
    if def_key not in type_defs:
        raise ResolutionError(f"Unresolved $ref: {ref} (key '{def_key}' not found in '{def_type}')")

    return type_defs[def_key]
