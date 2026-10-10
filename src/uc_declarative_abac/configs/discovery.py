from __future__ import annotations

from pathlib import Path
from typing import Any

from uc_declarative_abac.configs.models import with_file_path
from uc_declarative_abac.utils import (
    DuplicateKeyError,
    DuplicateResourceError,
    load_yaml_file,
)


def discover_yaml_files(root: Path) -> list[Path]:
    """Recursively find all .yaml and .yml files under root."""
    return sorted(
        p for p in root.rglob("*") if p.is_file() and p.suffix in (".yaml", ".yml")
    )


def _parse_yaml_file(path: Path) -> dict | None:
    """Parse a YAML file, returning None if it doesn't contain a dict.

    Uses a strict loader that raises ``DuplicateKeyError`` on a repeated mapping
    key rather than silently keeping the last value (see ``load_yaml_file``)."""
    data = load_yaml_file(path)
    return data if isinstance(data, dict) else None


def _stamp_list_items(node: Any, path: Path) -> Any:
    """Return a copy of ``node`` with every dict that is a list element, at any depth, stamped
    with ``path`` (keeping any user-written value)."""
    if isinstance(node, dict):
        return {key: _stamp_list_items(value, path) for key, value in node.items()}
    if isinstance(node, list):
        return [
            _stamp_list_items(
                with_file_path(item, path) if isinstance(item, dict) else item, path
            )
            for item in node
        ]
    return node


def _stamp_file_path(entries: dict, path: Path) -> dict:
    """Return a copy of a definitions/resources sub-block with each entry — and every
    list-element dict within it — stamped with the file it was read from.

    Stamping everything here, once, means every piece of content carries the file it was
    literally written in before ``$ref`` resolution mixes files together, so the resolver only
    has to decide which stamp wins a merge (the definition's). Only top-level entries and list
    elements are stamped: every list-of-dicts field in the config schema is a list of child
    configs, whereas a nested dict value may be plain data (``tags``) that must not gain a key;
    single nested child configs (``icon``, ``arguments``) inherit theirs from the parent model.

    The value is a ``Path``, so the template-variable machinery (which only inspects ``str``
    leaves) never scans it and it is distinguishable from a user-written ``file_path`` — which is
    kept in place, for model validation to reject.
    """
    return {
        key: _stamp_list_items(
            with_file_path(entry, path) if isinstance(entry, dict) else entry, path
        )
        for key, entry in entries.items()
    }


def _merge_block(namespace: str, block: dict, registry: dict, path: Path) -> dict:
    """Merge a single definitions/resources block into a registry, returning the updated registry."""
    merged = {**registry}
    for sub_key, entries in block.items():
        if not isinstance(entries, dict):
            continue
        stamped_entries = _stamp_file_path(entries, path)
        existing = {**merged.get(sub_key, {})}
        for entry_key, entry_val in stamped_entries.items():
            if entry_key in existing:
                exc_cls = (
                    DuplicateResourceError
                    if namespace == "resources"
                    else DuplicateKeyError
                )
                raise exc_cls(f"Duplicate key '{entry_key}' in {namespace}.{sub_key}")
            existing[entry_key] = entry_val
        merged[sub_key] = existing
    return merged


def load_raw_configs(paths: list[Path]) -> tuple[dict, dict]:
    """Parse YAML files and merge all definitions and resources blocks.

    Returns:
        A tuple of (definitions_dict, resources_dict) where each is a merged
        registry across all files. Raises DuplicateKeyError on conflicts.
    """
    definitions: dict = {}
    resources: dict = {}

    for path in paths:
        data = _parse_yaml_file(path)
        if data is None:
            continue

        if "definitions" in data:
            definitions = _merge_block(
                "definitions", data["definitions"], definitions, path
            )
        if "resources" in data:
            resources = _merge_block("resources", data["resources"], resources, path)

    return definitions, resources
