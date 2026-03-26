from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, PropertyMock

import pytest
import yaml
from databricks.sdk.service.sql import StatementState


# ---------------------------------------------------------------------------
# WorkspaceClient mock
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_workspace_client() -> MagicMock:
    """A mock WorkspaceClient with a stub statement_execution.execute_statement().

    The mock captures all SQL calls made via execute_statement() and allows
    configuring fake results via mock_workspace_client.fake_results.
    """
    client = MagicMock()

    # Track all SQL statements passed to execute_statement
    client.executed_sql: list[str] = []

    original_execute = client.statement_execution.execute_statement

    def _capture_sql(*args: Any, **kwargs: Any) -> MagicMock:
        statement = kwargs.get("statement", args[0] if args else None)
        if statement:
            client.executed_sql.append(statement)
        response = MagicMock()
        response.status.state = StatementState.SUCCEEDED
        return response

    client.statement_execution.execute_statement.side_effect = _capture_sql

    return client


# ---------------------------------------------------------------------------
# AccountClient mock
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_account_client() -> MagicMock:
    """A mock AccountClient with stub users/groups/service_principals list methods.

    By default returns empty lists. Tests can override:
        mock_account_client.users.list.return_value = [...]
        mock_account_client.groups.list.return_value = [...]
        mock_account_client.service_principals.list.return_value = [...]

    Service principal mocks should have display_name and application_id attributes.
    """
    client = MagicMock()
    client.users.list.return_value = []
    client.groups.list.return_value = []
    client.service_principals.list.return_value = []
    return client


def make_mock_user(user_name: str) -> MagicMock:
    """Create a mock user object with a user_name attribute."""
    user = MagicMock()
    user.user_name = user_name
    return user


def make_mock_group(display_name: str) -> MagicMock:
    """Create a mock group object with a display_name attribute."""
    group = MagicMock()
    group.display_name = display_name
    return group


def make_mock_service_principal(display_name: str, application_id: str) -> MagicMock:
    """Create a mock service principal with display_name and application_id."""
    sp = MagicMock()
    sp.display_name = display_name
    sp.application_id = application_id
    return sp


# ---------------------------------------------------------------------------
# YAML temp directory helper
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_yaml_dir(tmp_path: Path):
    """Factory fixture that writes YAML content to files in a temp directory.

    Usage:
        def test_something(tmp_yaml_dir):
            root = tmp_yaml_dir({
                "definitions/schemas.yaml": {"definitions": {"schemas": {...}}},
                "resources/catalogs.yaml": {"resources": {"catalogs": {...}}},
            })
    """

    def _write(files: dict[str, Any]) -> Path:
        for relative_path, content in files.items():
            file_path = tmp_path / relative_path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(yaml.dump(content, default_flow_style=False))
        return tmp_path

    return _write


# ---------------------------------------------------------------------------
# Sample config fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_definitions() -> dict:
    """A minimal definitions dict with one schema and one table definition."""
    return {
        "schemas": {
            "ops|sales": {
                "name": "sales",
                "tags": {"operations": None},
                "tables": [
                    {"$ref": "$defs/tables/ops|sales|orders"},
                ],
            },
        },
        "tables": {
            "ops|sales|orders": {
                "name": "orders",
                "tags": {"classification": "internal", "sales": None},
            },
        },
        "volumes": {
            "platform|landing|files": {
                "name": "files",
                "tags": {"landing": None},
            },
        },
    }


@pytest.fixture
def sample_resources() -> dict:
    """A minimal resources dict with one catalog referencing definitions."""
    return {
        "catalogs": {
            "operations_prod": {
                "tags": {"env": "prod", "operations": None},
                "policies": [
                    {
                        "name": "grant_read_on_sales",
                        "type": "grant",
                        "privileges": ["select"],
                        "to": ["data_engineers"],
                        "tags": {"sales": None},
                    },
                ],
                "schemas": [
                    {"$ref": "$defs/schemas/ops|sales"},
                ],
            },
        },
    }
