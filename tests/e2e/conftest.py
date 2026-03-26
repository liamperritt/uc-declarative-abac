from __future__ import annotations

from pathlib import Path

import pytest

from databricks.sdk import WorkspaceClient


PROFILE = "field-eng-east"
WAREHOUSE_ID = "e9a9c8bab075bb70"
CONFIG_DIR = Path(__file__).parent / "configs"


@pytest.fixture(scope="session")
def workspace_client() -> WorkspaceClient:
    """Create a real WorkspaceClient using the field-eng-east profile."""
    return WorkspaceClient(profile=PROFILE)


@pytest.fixture(scope="session")
def warehouse_id() -> str:
    return WAREHOUSE_ID


@pytest.fixture(scope="session")
def config_dir() -> Path:
    return CONFIG_DIR
