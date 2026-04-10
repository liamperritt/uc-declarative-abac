from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from uc_abac_governor.helpers.workspace import WorkspaceHelper
from uc_abac_governor.types import DuplicateServicePrincipalError, PrincipalValidationError


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------


def _make_user(user_name: str) -> dict:
    return {"userName": user_name}


def _make_group(display_name: str) -> dict:
    return {"displayName": display_name}


def _make_sp(display_name: str, application_id: str) -> dict:
    return {"displayName": display_name, "applicationId": application_id}


def _make_workspace_client(
    users: list[dict] | None = None,
    groups: list[dict] | None = None,
    service_principals: list[dict] | None = None,
) -> MagicMock:
    client = MagicMock()

    def _do(method, path, **kwargs):
        if "/Users" in path:
            resources = users or []
        elif "/Groups" in path:
            resources = groups or []
        elif "/ServicePrincipals" in path:
            resources = service_principals or []
        else:
            resources = []
        return {
            "totalResults": len(resources),
            "startIndex": 1,
            "itemsPerPage": 100,
            "Resources": resources,
        }

    client.api_client.do.side_effect = _do
    return client


# ---------------------------------------------------------------------------
# WorkspaceHelper.fetch_principals
# ---------------------------------------------------------------------------


def test_workspace_helper_fetches_and_caches_users() -> None:
    """After fetch_principals, user emails are available and the API is only called once."""
    client = _make_workspace_client(
        users=[_make_user("alice@example.com"), _make_user("bob@example.com")],
    )
    helper = WorkspaceHelper(client)
    helper.fetch_principals()
    helper.fetch_principals()  # second call should use cache

    assert helper.validate_principal("alice@example.com") is True
    assert helper.validate_principal("bob@example.com") is True
    # SCIM endpoint should only be called once per principal type (3 types, 1 call each)
    # but the second fetch_principals should be cached so total = 3
    assert client.api_client.do.call_count == 3


def test_workspace_helper_fetches_and_caches_groups() -> None:
    """After fetch_principals, group display names are available and the API is only called once."""
    client = _make_workspace_client(
        groups=[_make_group("data_engineers"), _make_group("analysts")],
    )
    helper = WorkspaceHelper(client)
    helper.fetch_principals()
    helper.fetch_principals()  # second call should use cache

    assert helper.validate_principal("data_engineers") is True
    assert helper.validate_principal("analysts") is True
    assert client.api_client.do.call_count == 3


def test_workspace_helper_fetches_and_caches_service_principals() -> None:
    """After fetch_principals, SP display names are available and the API is only called once."""
    client = _make_workspace_client(
        service_principals=[_make_sp("my-sp", "app-id-123")],
    )
    helper = WorkspaceHelper(client)
    helper.fetch_principals()
    helper.fetch_principals()  # second call should use cache

    assert helper.validate_principal("my-sp") is True
    assert client.api_client.do.call_count == 3


def test_workspace_helper_warns_on_duplicate_sp_display_names() -> None:
    """Two SPs with same display_name -> fetch_principals succeeds but logs warning."""
    client = _make_workspace_client(
        service_principals=[
            _make_sp("duplicate-sp", "app-001"),
            _make_sp("duplicate-sp", "app-002"),
        ],
    )
    helper = WorkspaceHelper(client)
    helper.fetch_principals()

    # The SP is still recognized as valid
    assert helper.validate_principal("duplicate-sp") is True


def test_workspace_helper_raises_on_get_application_id_for_duplicate_sp() -> None:
    """get_sp_application_id raises DuplicateServicePrincipalError for ambiguous SPs."""
    client = _make_workspace_client(
        service_principals=[
            _make_sp("duplicate-sp", "app-001"),
            _make_sp("duplicate-sp", "app-002"),
        ],
    )
    helper = WorkspaceHelper(client)
    helper.fetch_principals()

    with pytest.raises(DuplicateServicePrincipalError):
        helper.get_sp_application_id("duplicate-sp")


# ---------------------------------------------------------------------------
# WorkspaceHelper.validate_principal
# ---------------------------------------------------------------------------


def test_workspace_helper_validates_known_principal() -> None:
    """Returns True for a user, group, or SP in cache."""
    client = _make_workspace_client(
        users=[_make_user("alice@example.com")],
        groups=[_make_group("data_engineers")],
        service_principals=[_make_sp("etl-runner", "app-001")],
    )
    helper = WorkspaceHelper(client)
    helper.fetch_principals()

    assert helper.validate_principal("alice@example.com") is True
    assert helper.validate_principal("data_engineers") is True
    assert helper.validate_principal("etl-runner") is True


def test_workspace_helper_invalidates_unknown_principal() -> None:
    """Returns False for unknown name."""
    client = _make_workspace_client(
        users=[_make_user("alice@example.com")],
    )
    helper = WorkspaceHelper(client)
    helper.fetch_principals()

    assert helper.validate_principal("nobody@example.com") is False


def test_workspace_helper_invalidates_principals_with_invalid_names() -> None:
    """Given a list with bad names, raises PrincipalValidationError listing all bad names."""
    client = _make_workspace_client(
        users=[_make_user("alice@example.com")],
        groups=[_make_group("data_engineers")],
    )
    helper = WorkspaceHelper(client)
    helper.fetch_principals()

    with pytest.raises(PrincipalValidationError) as exc_info:
        helper.validate_principals(
            ["alice@example.com", "ghost_user", "data_engineers", "phantom_group"]
        )

    error_message = str(exc_info.value)
    # Invalid names must appear in the error
    assert "ghost_user" in error_message
    assert "phantom_group" in error_message
    # Valid names must NOT appear in the error
    assert "alice@example.com" not in error_message
    assert "data_engineers" not in error_message


# ---------------------------------------------------------------------------
# WorkspaceHelper.get_sp_application_id
# ---------------------------------------------------------------------------


def test_workspace_helper_gets_sp_application_id_for_known_sp() -> None:
    """Returns the application_id for a known SP."""
    client = _make_workspace_client(
        service_principals=[_make_sp("etl-runner", "app-42")],
    )
    helper = WorkspaceHelper(client)
    helper.fetch_principals()

    assert helper.get_sp_application_id("etl-runner") == "app-42"


def test_workspace_helper_fails_to_get_sp_application_id_for_unknown_sp() -> None:
    """Raises PrincipalValidationError for unknown SP display name."""
    client = _make_workspace_client(
        service_principals=[_make_sp("etl-runner", "app-42")],
    )
    helper = WorkspaceHelper(client)
    helper.fetch_principals()

    with pytest.raises(PrincipalValidationError):
        helper.get_sp_application_id("nonexistent-sp")


# ---------------------------------------------------------------------------
# find_unknown_principals
# ---------------------------------------------------------------------------


def test_workspace_helper_find_unknown_principals_returns_unknown_names() -> None:
    """Returns only the names that do not exist in the account."""
    client = _make_workspace_client(
        groups=[_make_group("data_engineers")],
    )
    helper = WorkspaceHelper(client)
    helper.fetch_principals()

    result = helper.find_unknown_principals(["data_engineers", "ghost_team"])

    assert result == ["ghost_team"]


def test_workspace_helper_find_unknown_principals_returns_empty_when_all_valid() -> None:
    """Returns an empty list when every principal exists in the account."""
    client = _make_workspace_client(
        users=[_make_user("alice@example.com")],
        groups=[_make_group("data_engineers")],
    )
    helper = WorkspaceHelper(client)
    helper.fetch_principals()

    result = helper.find_unknown_principals(["alice@example.com", "data_engineers"])

    assert result == []


# ---------------------------------------------------------------------------
# Principal resolution
# ---------------------------------------------------------------------------


def test_workspace_helper_resolves_user_by_name() -> None:
    """resolve_by_name returns a Principal with USER type for a known user."""
    from uc_abac_governor.types import Principal, PrincipalType

    client = _make_workspace_client(users=[_make_user("jane@co.com")])
    helper = WorkspaceHelper(client)
    helper.fetch_principals()

    result = helper.resolve_by_name("jane@co.com")

    assert result == Principal(PrincipalType.USER, "jane@co.com", "jane@co.com")


def test_workspace_helper_resolves_group_by_name() -> None:
    """resolve_by_name returns a Principal with GROUP type for a known group."""
    from uc_abac_governor.types import Principal, PrincipalType

    client = _make_workspace_client(groups=[_make_group("data_engineers")])
    helper = WorkspaceHelper(client)
    helper.fetch_principals()

    result = helper.resolve_by_name("data_engineers")

    assert result == Principal(PrincipalType.GROUP, "data_engineers", "data_engineers")


def test_workspace_helper_resolves_sp_by_name() -> None:
    """resolve_by_name returns a Principal with SP type, using application_id as identifier."""
    from uc_abac_governor.types import Principal, PrincipalType

    client = _make_workspace_client(
        service_principals=[_make_sp("my-sp", "app-123")],
    )
    helper = WorkspaceHelper(client)
    helper.fetch_principals()

    result = helper.resolve_by_name("my-sp")

    assert result == Principal(PrincipalType.SERVICE_PRINCIPAL, "app-123", "my-sp")


def test_workspace_helper_resolves_sp_by_identifier() -> None:
    """resolve_by_identifier returns a Principal for a known SP application_id."""
    from uc_abac_governor.types import Principal, PrincipalType

    client = _make_workspace_client(
        service_principals=[_make_sp("my-sp", "app-123")],
    )
    helper = WorkspaceHelper(client)
    helper.fetch_principals()

    result = helper.resolve_by_identifier("app-123")

    assert result == Principal(PrincipalType.SERVICE_PRINCIPAL, "app-123", "my-sp")


def test_workspace_helper_resolves_user_by_identifier() -> None:
    """resolve_by_identifier returns a Principal for a known user email."""
    from uc_abac_governor.types import Principal, PrincipalType

    client = _make_workspace_client(users=[_make_user("jane@co.com")])
    helper = WorkspaceHelper(client)
    helper.fetch_principals()

    result = helper.resolve_by_identifier("jane@co.com")

    assert result == Principal(PrincipalType.USER, "jane@co.com", "jane@co.com")


# ---------------------------------------------------------------------------
# Principal dict
# ---------------------------------------------------------------------------


def test_workspace_helper_returns_principals_dict() -> None:
    """get_principals returns a dict mapping display name to Principal."""
    from uc_abac_governor.types import Principal, PrincipalType

    client = _make_workspace_client(
        users=[_make_user("jane@co.com")],
        groups=[_make_group("data_engineers")],
        service_principals=[_make_sp("my-sp", "app-123")],
    )
    helper = WorkspaceHelper(client)
    helper.fetch_principals()

    result = helper.get_principals()

    assert result["jane@co.com"] == Principal(
        PrincipalType.USER, "jane@co.com", "jane@co.com"
    )
    assert result["data_engineers"] == Principal(
        PrincipalType.GROUP, "data_engineers", "data_engineers"
    )
    assert result["my-sp"] == Principal(
        PrincipalType.SERVICE_PRINCIPAL, "app-123", "my-sp"
    )


# ---------------------------------------------------------------------------
# Account SCIM proxy
# ---------------------------------------------------------------------------


def test_workspace_helper_paginates_scim_results() -> None:
    """fetch_principals paginates through SCIM results when totalResults > itemsPerPage."""
    client = MagicMock()

    call_count = {"n": 0}

    def _paginated_do(method, path, **kwargs):
        call_count["n"] += 1
        query = kwargs.get("query", {})
        start = query.get("startIndex", 1)
        if "/Users" in path:
            if start == 1:
                return {
                    "totalResults": 3,
                    "startIndex": 1,
                    "itemsPerPage": 2,
                    "Resources": [
                        {"userName": "a@co.com"},
                        {"userName": "b@co.com"},
                    ],
                }
            else:
                return {
                    "totalResults": 3,
                    "startIndex": 3,
                    "itemsPerPage": 2,
                    "Resources": [{"userName": "c@co.com"}],
                }
        return {
            "totalResults": 0,
            "startIndex": 1,
            "itemsPerPage": 100,
            "Resources": [],
        }

    client.api_client.do.side_effect = _paginated_do

    helper = WorkspaceHelper(client)
    helper.fetch_principals()

    assert helper.validate_principal("a@co.com") is True
    assert helper.validate_principal("b@co.com") is True
    assert helper.validate_principal("c@co.com") is True


# ---------------------------------------------------------------------------
# use_workspace_scim
# ---------------------------------------------------------------------------


def test_workspace_helper_uses_account_scim_by_default() -> None:
    """Default scope uses account SCIM proxy (api_client.do)."""
    client = _make_workspace_client(users=[{"userName": "jane@co.com"}])
    helper = WorkspaceHelper(client)
    helper.fetch_principals()

    assert client.api_client.do.called
    assert helper.validate_principal("jane@co.com")


def test_workspace_helper_uses_sdk_list_when_scope_is_workspace() -> None:
    """use_workspace_scim=True uses SDK .list() instead of account SCIM proxy."""
    client = MagicMock()

    user = MagicMock()
    user.user_name = "jane@co.com"
    client.users.list.return_value = [user]

    group = MagicMock()
    group.display_name = "data_engineers"
    client.groups.list.return_value = [group]

    client.service_principals.list.return_value = []

    helper = WorkspaceHelper(client, use_workspace_scim=True)
    helper.fetch_principals()

    # SDK list methods should be called
    assert client.users.list.called
    assert client.groups.list.called
    assert client.service_principals.list.called
    # Account SCIM proxy should NOT be called
    assert not client.api_client.do.called
    # Principals should be found
    assert helper.validate_principal("jane@co.com")
    assert helper.validate_principal("data_engineers")
