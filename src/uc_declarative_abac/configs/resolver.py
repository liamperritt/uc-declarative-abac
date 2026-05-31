from __future__ import annotations

from uc_declarative_abac.utils import (
    ResolutionError,
    UnreferencedDefinitionError,
)
import copy
from typing import Any, Literal


OverrideStrategy = Literal["merge", "replace"]


_PRIMITIVE_TYPES = (str, int, float, bool)
_IDENTIFIER_KEYS = ("name", "alias", "$ref")


def _is_primitive(value: Any) -> bool:
    """A scalar leaf for merge purposes: str/int/float/bool or None."""
    return value is None or isinstance(value, _PRIMITIVE_TYPES)


def _identifier_of(item: dict) -> tuple[str, Any] | None:
    """Return a hashable identifier for a list item, or None if it has none.

    Checks 'name', then 'alias', then '$ref'. Used to align items between definition
    and override lists.
    """
    for key in _IDENTIFIER_KEYS:
        if key in item:
            return (key, item[key])
    return None


def _all_have_identifiers(items: list) -> bool:
    """True if every item in the list is a dict carrying 'name' or '$ref'.

    Vacuously true for an empty list — empty lists are shape-neutral and compatible
    with any merge strategy chosen by the other side.
    """
    return all(isinstance(i, dict) and _identifier_of(i) is not None for i in items)


def _all_primitives(items: list) -> bool:
    """True if every item in the list is a primitive scalar.

    Vacuously true for an empty list.
    """
    return all(_is_primitive(i) for i in items)


def _union_primitives(definition: list, override: list) -> list:
    """Concatenate definition + override, deduping by value. Definition order preserved."""
    result = list(definition)
    for item in override:
        if item not in result:
            result.append(item)
    return result


def _merge_lists_by_identifier(definition: list, override: list) -> list:
    """Align list items by identifier, recursively merge matched items, append the rest.

    Matched items: items from definition whose identifier appears in override are recursively
    deep-merged with the matching override item.
    Unmatched definition items: preserved in definition order.
    Unmatched override items: appended after, in override order.
    """
    override_by_id = {_identifier_of(item): item for item in override}
    consumed: set = set()
    result: list = []
    for def_item in definition:
        def_id = _identifier_of(def_item)
        if def_id in override_by_id:
            result.append(_deep_merge(def_item, override_by_id[def_id]))
            consumed.add(def_id)
        else:
            result.append(copy.deepcopy(def_item))
    for ov_item in override:
        ov_id = _identifier_of(ov_item)
        if ov_id not in consumed:
            result.append(copy.deepcopy(ov_item))
    return result


def _merge_lists(definition: list, override: list) -> list:
    """Merge two lists. Strategy depends on item shape; see module docstring."""
    if _all_have_identifiers(definition) and _all_have_identifiers(override):
        return _merge_lists_by_identifier(definition, override)
    if _all_primitives(definition) and _all_primitives(override):
        return _union_primitives(definition, override)
    return copy.deepcopy(override)


def _merge_dicts(definition: dict, override: dict) -> dict:
    """Recursively merge two dicts. Override keys win; definition-only keys are preserved."""
    result: dict = {}
    for key, def_value in definition.items():
        if key in override:
            result[key] = _deep_merge(def_value, override[key])
        else:
            result[key] = copy.deepcopy(def_value)
    for key, ov_value in override.items():
        if key not in definition:
            result[key] = copy.deepcopy(ov_value)
    return result


def _deep_merge(definition: Any, override: Any) -> Any:
    """Recursively merge override into definition, returning a new value.

    - dict + dict → recursive key-wise merge
    - list + list → see _merge_lists for the per-shape strategy
    - anything else (scalar / type mismatch) → override wins
    """
    if isinstance(definition, dict) and isinstance(override, dict):
        return _merge_dicts(definition, override)
    if isinstance(definition, list) and isinstance(override, list):
        return _merge_lists(definition, override)
    return copy.deepcopy(override)


def resolve_refs(
    definitions: dict,
    resources: dict,
    *,
    override_strategy: OverrideStrategy = "merge",
) -> dict:
    """Resolve all $ref entries and inline $defs/... string values using the definitions registry.

    Walks the resources dict recursively and resolves two forms of reference:

    1. **$ref dicts** — ``{"$ref": "$defs/<type>/<key>", ...}`` — the definition is
       looked up, deep-copied, sibling keys are applied as overrides, and nested
       refs are resolved recursively.
    2. **Inline $defs strings** — any string value matching ``$defs/<type>/<key>``
       is replaced with the deep-copied definition content and resolved recursively
       (no overrides, since there are no sibling keys on a plain string value).

    Override merge strategies (controlled by ``override_strategy``):

    - ``"merge"`` (default) — sibling fields recursively deep-merge into the
      definition. Dicts merge key-wise; lists of identifier-bearing dicts merge by
      ``name`` (or ``$ref``); lists of primitives are unioned with dedupe. Other
      shapes fall back to replace.
    - ``"replace"`` — sibling fields shallowly replace top-level keys in the
      definition (legacy behaviour, preserved for backwards compatibility).

    Returns a flat dict ready for ResourcesConfig.model_validate(),
    i.e. {"catalogs": {...}} with all refs resolved and definitions stripped.

    Raises UnreferencedDefinitionError if any definitions are not referenced.
    """
    referenced: set[str] = set()
    visited: set[str] = set()
    result = _resolve_node(definitions, resources, referenced, visited, override_strategy)

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


def _resolve_node(
    definitions: dict,
    node: Any,
    referenced: set[str],
    visited: set[str],
    override_strategy: OverrideStrategy,
) -> Any:
    """Recursively resolve $ref entries within an arbitrary node."""
    if isinstance(node, dict):
        return _resolve_dict(definitions, node, referenced, visited, override_strategy)
    if isinstance(node, list):
        return [
            _resolve_node(definitions, item, referenced, visited, override_strategy)
            for item in node
        ]
    if isinstance(node, str) and node.startswith("$defs/"):
        return _resolve_inline_defs_string(definitions, node, referenced, visited, override_strategy)
    return node


def _resolve_dict(
    definitions: dict,
    node: dict,
    referenced: set[str],
    visited: set[str],
    override_strategy: OverrideStrategy,
) -> dict:
    """Resolve a single dict node, handling $ref if present."""
    if "$ref" in node:
        return _resolve_ref(definitions, node, referenced, visited, override_strategy)
    return {
        key: _resolve_node(definitions, value, referenced, visited, override_strategy)
        for key, value in node.items()
    }


def _resolve_inline_defs_strings(
    definitions: dict,
    node: Any,
    referenced: set[str],
    visited: set[str],
    override_strategy: OverrideStrategy,
) -> Any:
    """Recursively resolve only inline ``$defs/...`` strings; leave ``$ref`` dicts intact.

    A bare ``$defs/...`` string carries no sibling identifier keys, so its merge
    identity can only come from the dict it resolves to. Pre-resolving these strings
    on both sides of a merge lets ``_merge_lists`` see concrete dicts and align
    items by ``name`` / ``alias`` as intended — without this, an override like
    ``columns: [$defs/columns/region]`` against a definition list of dicts would
    hit the shape-mismatch fallback in ``_merge_lists`` and replace the whole list.

    ``$ref`` dicts are intentionally NOT pre-resolved here: their sibling keys
    (``alias``, ``name``) are the *intended* merge identifier as written in YAML,
    so the merge must see them before the ``$ref`` is expanded.
    """
    if isinstance(node, dict):
        if "$ref" in node:
            return node
        return {
            key: _resolve_inline_defs_strings(definitions, value, referenced, visited, override_strategy)
            for key, value in node.items()
        }
    if isinstance(node, list):
        return [
            _resolve_inline_defs_strings(definitions, item, referenced, visited, override_strategy)
            for item in node
        ]
    if isinstance(node, str) and node.startswith("$defs/"):
        return _resolve_inline_defs_string(definitions, node, referenced, visited, override_strategy)
    return node


def _resolve_ref(
    definitions: dict,
    node: dict,
    referenced: set[str],
    visited: set[str],
    override_strategy: OverrideStrategy,
) -> dict:
    """Look up a $ref, apply overrides, and recursively resolve the result.

    Inline ``$defs/...`` strings on both sides are pre-resolved before merging so
    that list fields using the catalog-style shorthand still merge by identifier
    (e.g. ``columns: [$defs/columns/region]`` appends to the definition's column
    list instead of replacing it). ``$ref`` dicts with sibling keys are deferred
    to the post-merge resolution pass so explicit ``alias`` / ``name`` siblings
    drive identifier matching as intended.
    """
    ref_path = node["$ref"]
    if ref_path in visited:
        raise ResolutionError(f"Circular $ref detected: {ref_path}")
    visited.add(ref_path)
    referenced.add(ref_path)
    definition = _lookup_definition(definitions, ref_path)
    resolved = copy.deepcopy(definition)
    resolved = _resolve_inline_defs_strings(definitions, resolved, referenced, visited, override_strategy)

    overrides = {k: v for k, v in node.items() if k != "$ref"}
    overrides = _resolve_inline_defs_strings(definitions, overrides, referenced, visited, override_strategy)

    if override_strategy == "replace":
        resolved.update(overrides)
    else:
        resolved = _merge_dicts(resolved, overrides)

    result = _resolve_node(definitions, resolved, referenced, visited, override_strategy)
    visited.discard(ref_path)
    return result


def _resolve_inline_defs_string(
    definitions: dict,
    ref_path: str,
    referenced: set[str],
    visited: set[str],
    override_strategy: OverrideStrategy,
) -> Any:
    """Resolve a bare $defs/... string value the same way a $ref dict is resolved."""
    if ref_path in visited:
        raise ResolutionError(f"Circular $ref detected: {ref_path}")
    visited.add(ref_path)
    referenced.add(ref_path)
    definition = _lookup_definition(definitions, ref_path)
    resolved = copy.deepcopy(definition)
    result = _resolve_node(definitions, resolved, referenced, visited, override_strategy)
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
