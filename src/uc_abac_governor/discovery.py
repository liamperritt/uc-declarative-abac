from __future__ import annotations

from pathlib import Path

import yaml

from uc_abac_governor.types import DuplicateKeyError, DuplicateResourceError


def discover_yaml_files(root: Path) -> list[Path]:
    """Recursively find all .yaml and .yml files under root."""
    return sorted(
        p for p in root.rglob("*") if p.is_file() and p.suffix in (".yaml", ".yml")
    )


def _parse_yaml_file(path: Path) -> dict | None:
    """Parse a YAML file, returning None if it doesn't contain a dict."""
    with open(path) as f:
        data = yaml.safe_load(f)
    return data if isinstance(data, dict) else None


def _merge_block(namespace: str, block: dict, registry: dict) -> dict:
    """Merge a single definitions/resources block into a registry, returning the updated registry."""
    merged = {**registry}
    for sub_key, entries in block.items():
        if not isinstance(entries, dict):
            continue
        existing = {**merged.get(sub_key, {})}
        for entry_key, entry_val in entries.items():
            if entry_key in existing:
                exc_cls = DuplicateResourceError if namespace == "resources" else DuplicateKeyError
                raise exc_cls(
                    f"Duplicate key '{entry_key}' in {namespace}.{sub_key}"
                )
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
            definitions = _merge_block("definitions", data["definitions"], definitions)
        if "resources" in data:
            resources = _merge_block("resources", data["resources"], resources)

    return definitions, resources
