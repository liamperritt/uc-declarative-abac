from __future__ import annotations

from pathlib import Path


def discover_yaml_files(root: Path) -> list[Path]:
    """Recursively find all .yaml and .yml files under root."""
    raise NotImplementedError


def load_raw_configs(paths: list[Path]) -> tuple[dict, dict]:
    """Parse YAML files and merge all definitions and resources blocks.

    Returns:
        A tuple of (definitions_dict, resources_dict) where each is a merged
        registry across all files. Raises DuplicateKeyError on conflicts.
    """
    raise NotImplementedError
