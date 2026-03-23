from __future__ import annotations


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
    raise NotImplementedError
