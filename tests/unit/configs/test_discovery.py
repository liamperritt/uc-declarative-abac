from __future__ import annotations

import pytest

from uc_declarative_abac.configs import (
    discover_yaml_files,
    load_raw_configs,
)
from uc_declarative_abac.utils import (
    DuplicateKeyError,
    DuplicateResourceError,
)

# ---------------------------------------------------------------------------
# discover_yaml_files
# ---------------------------------------------------------------------------


def test_discovery_finds_yaml_and_yml(tmp_yaml_dir):
    """Given a directory with .yaml, .yml, and .txt files, returns only YAML files."""
    root = tmp_yaml_dir(
        {
            "a.yaml": {"key": "value"},
            "b.yml": {"key": "value"},
            "c.txt": "not yaml",
        }
    )
    (root / "c.txt").write_text("plain text")

    result = discover_yaml_files(root)

    result_names = sorted(p.name for p in result)
    assert result_names == ["a.yaml", "b.yml"]


def test_discovery_finds_files_in_nested_directories(tmp_yaml_dir):
    """Given nested subdirectories, recursively discovers all YAML files."""
    root = tmp_yaml_dir(
        {
            "top.yaml": {"key": "value"},
            "level1/mid.yml": {"key": "value"},
            "level1/level2/deep.yaml": {"key": "value"},
        }
    )

    result = discover_yaml_files(root)

    result_names = sorted(p.name for p in result)
    assert result_names == ["deep.yaml", "mid.yml", "top.yaml"]


def test_discovery_returns_empty_given_no_yaml_files(tmp_path):
    """Given a directory with no YAML files, returns an empty list."""
    (tmp_path / "readme.txt").write_text("hello")
    (tmp_path / "data.json").write_text("{}")

    result = discover_yaml_files(tmp_path)

    assert result == []


# ---------------------------------------------------------------------------
# load_raw_configs
# ---------------------------------------------------------------------------


def test_discovery_merges_definitions_across_files(tmp_yaml_dir):
    """Given two files each contributing different definition types, merges them."""
    root = tmp_yaml_dir(
        {
            "definitions/schemas.yaml": {
                "definitions": {
                    "schemas": {
                        "ops|sales": {"name": "sales"},
                    },
                },
            },
            "definitions/tables.yaml": {
                "definitions": {
                    "tables": {
                        "ops|sales|orders": {"name": "orders"},
                    },
                },
            },
        }
    )

    paths = discover_yaml_files(root)
    definitions, resources = load_raw_configs(paths)

    assert "schemas" in definitions
    assert "ops|sales" in definitions["schemas"]
    assert definitions["schemas"]["ops|sales"]["name"] == "sales"

    assert "tables" in definitions
    assert "ops|sales|orders" in definitions["tables"]
    assert definitions["tables"]["ops|sales|orders"]["name"] == "orders"

    assert resources == {} or all(v == {} for v in resources.values())


def test_discovery_merges_resources_across_files(tmp_yaml_dir):
    """Given two files with different catalog resources, merges them."""
    root = tmp_yaml_dir(
        {
            "resources/prod.yaml": {
                "resources": {
                    "catalogs": {
                        "operations_prod": {"tags": {"env": "prod"}},
                    },
                },
            },
            "resources/dev.yaml": {
                "resources": {
                    "catalogs": {
                        "operations_dev": {"tags": {"env": "dev"}},
                    },
                },
            },
        }
    )

    paths = discover_yaml_files(root)
    _definitions, resources = load_raw_configs(paths)

    assert "catalogs" in resources
    assert "operations_prod" in resources["catalogs"]
    assert "operations_dev" in resources["catalogs"]
    assert resources["catalogs"]["operations_prod"]["tags"]["env"] == "prod"
    assert resources["catalogs"]["operations_dev"]["tags"]["env"] == "dev"


def test_discovery_raises_on_duplicate_definition_key(tmp_yaml_dir):
    """Given two files defining the same definition key, raises DuplicateKeyError."""
    root = tmp_yaml_dir(
        {
            "definitions/schemas_a.yaml": {
                "definitions": {
                    "schemas": {
                        "ops|sales": {"name": "sales"},
                    },
                },
            },
            "definitions/schemas_b.yaml": {
                "definitions": {
                    "schemas": {
                        "ops|sales": {"name": "sales_duplicate"},
                    },
                },
            },
        }
    )

    paths = discover_yaml_files(root)

    with pytest.raises(DuplicateKeyError):
        load_raw_configs(paths)


def test_discovery_ignores_files_with_no_definitions_or_resources(tmp_yaml_dir):
    """Given a YAML file with unrelated content, it is silently skipped."""
    root = tmp_yaml_dir(
        {
            "definitions/schemas.yaml": {
                "definitions": {
                    "schemas": {
                        "ops|sales": {"name": "sales"},
                    },
                },
            },
            "other/config.yaml": {
                "settings": {"debug": True},
            },
        }
    )

    paths = discover_yaml_files(root)
    definitions, _resources = load_raw_configs(paths)

    assert "schemas" in definitions
    assert "ops|sales" in definitions["schemas"]


# ---------------------------------------------------------------------------
# Duplicate catalog resource keys
# ---------------------------------------------------------------------------


def test_discovery_rejects_duplicate_catalog_resource_keys(tmp_yaml_dir):
    """Given two files defining the same catalog resource key, raises DuplicateResourceError."""
    root = tmp_yaml_dir(
        {
            "file1.yaml": {
                "resources": {"catalogs": {"my_catalog": {"tags": {"env": "prod"}}}}
            },
            "file2.yaml": {
                "resources": {"catalogs": {"my_catalog": {"tags": {"env": "test"}}}}
            },
        }
    )
    paths = discover_yaml_files(root)
    with pytest.raises(DuplicateResourceError):
        load_raw_configs(paths)


# ---------------------------------------------------------------------------
# Within-file duplicate mapping keys (strict loader)
# ---------------------------------------------------------------------------
#
# These write raw YAML text rather than using the tmp_yaml_dir fixture, which
# dumps Python dicts and so can never produce a duplicate key.


def test_discovery_raises_on_within_file_duplicate_top_level_key(tmp_path):
    """A repeated top-level key in a single file raises DuplicateKeyError."""
    path = tmp_path / "dup.yaml"
    path.write_text(
        "definitions:\n"
        "  schemas:\n"
        "    ops|sales:\n"
        "      name: sales\n"
        "definitions:\n"
        "  schemas:\n"
        "    ops|other:\n"
        "      name: other\n"
    )
    with pytest.raises(DuplicateKeyError):
        load_raw_configs([path])


def test_discovery_raises_on_within_file_duplicate_definition_key(tmp_path):
    """Two entries in the same file sharing a definition id raise DuplicateKeyError
    (previously silently collapsed by safe_load before the cross-file merge)."""
    path = tmp_path / "dup.yaml"
    path.write_text(
        "definitions:\n"
        "  policies:\n"
        "    pii|mask:\n"
        "      name: mask_a\n"
        "    pii|mask:\n"
        "      name: mask_b\n"
    )
    with pytest.raises(DuplicateKeyError):
        load_raw_configs([path])


def test_discovery_raises_on_deeply_nested_duplicate_key(tmp_path):
    """A duplicate key nested well below definitions/resources (here a repeated tag
    key on a policy) is still caught."""
    path = tmp_path / "dup.yaml"
    path.write_text(
        "definitions:\n"
        "  policies:\n"
        "    pii|mask:\n"
        "      name: mask\n"
        "      type: mask\n"
        "      has_tags:\n"
        "        pii: email\n"
        "        pii: ssn\n"
    )
    with pytest.raises(DuplicateKeyError):
        load_raw_configs([path])


def test_within_file_duplicate_key_error_names_file_and_line(tmp_path):
    """The raised error names the offending file and a line number."""
    path = tmp_path / "dup.yaml"
    path.write_text(
        "resources:\n"
        "  catalogs:\n"
        "    my_catalog:\n"
        "      comment: first\n"
        "    my_catalog:\n"
        "      comment: second\n"
    )
    with pytest.raises(DuplicateKeyError) as exc_info:
        load_raw_configs([path])
    message = str(exc_info.value)
    assert "my_catalog" in message
    assert "line" in message
    assert str(path) in message


def test_discovery_accepts_valid_yaml_without_duplicates(tmp_path):
    """Regression: a duplicate-free file with repeated *values* (not keys) parses fine."""
    path = tmp_path / "ok.yaml"
    path.write_text(
        "definitions:\n"
        "  schemas:\n"
        "    ops|a:\n"
        "      name: shared\n"
        "    ops|b:\n"
        "      name: shared\n"  # same value, different key — allowed
    )
    definitions, _resources = load_raw_configs([path])
    assert set(definitions["schemas"]) == {"ops|a", "ops|b"}
