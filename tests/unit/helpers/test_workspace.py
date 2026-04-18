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
    from uc_abac_governor.principals.state import Principal
    from uc_abac_governor.types import PrincipalType

    client = _make_workspace_client(users=[_make_user("jane@co.com")])
    helper = WorkspaceHelper(client)
    helper.fetch_principals()

    result = helper.resolve_by_name("jane@co.com")

    assert result == Principal(PrincipalType.USER, "jane@co.com", "jane@co.com")


def test_workspace_helper_resolves_group_by_name() -> None:
    """resolve_by_name returns a Principal with GROUP type for a known group."""
    from uc_abac_governor.principals.state import Principal
    from uc_abac_governor.types import PrincipalType

    client = _make_workspace_client(groups=[_make_group("data_engineers")])
    helper = WorkspaceHelper(client)
    helper.fetch_principals()

    result = helper.resolve_by_name("data_engineers")

    assert result == Principal(PrincipalType.GROUP, "data_engineers", "data_engineers")


def test_workspace_helper_resolves_sp_by_name() -> None:
    """resolve_by_name returns a Principal with SP type, using application_id as identifier."""
    from uc_abac_governor.principals.state import Principal
    from uc_abac_governor.types import PrincipalType

    client = _make_workspace_client(
        service_principals=[_make_sp("my-sp", "app-123")],
    )
    helper = WorkspaceHelper(client)
    helper.fetch_principals()

    result = helper.resolve_by_name("my-sp")

    assert result == Principal(PrincipalType.SERVICE_PRINCIPAL, "app-123", "my-sp")


def test_workspace_helper_resolves_sp_by_identifier() -> None:
    """resolve_by_identifier returns a Principal for a known SP application_id."""
    from uc_abac_governor.principals.state import Principal
    from uc_abac_governor.types import PrincipalType

    client = _make_workspace_client(
        service_principals=[_make_sp("my-sp", "app-123")],
    )
    helper = WorkspaceHelper(client)
    helper.fetch_principals()

    result = helper.resolve_by_identifier("app-123")

    assert result == Principal(PrincipalType.SERVICE_PRINCIPAL, "app-123", "my-sp")


def test_workspace_helper_resolves_user_by_identifier() -> None:
    """resolve_by_identifier returns a Principal for a known user email."""
    from uc_abac_governor.principals.state import Principal
    from uc_abac_governor.types import PrincipalType

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
    from uc_abac_governor.principals.state import Principal
    from uc_abac_governor.types import PrincipalType

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


# ---------------------------------------------------------------------------
# Parallel principal fetch
# ---------------------------------------------------------------------------


def test_workspace_helper_fetches_account_principal_types_in_parallel() -> None:
    """Users, groups, and service principals are fetched concurrently — total wall
    time should be close to one delay, not three."""
    import time
    client = MagicMock()

    delay_seconds = 0.3

    def _slow_do(method, path, **kwargs):
        time.sleep(delay_seconds)
        return {"totalResults": 0, "startIndex": 1, "itemsPerPage": 100, "Resources": []}

    client.api_client.do.side_effect = _slow_do

    helper = WorkspaceHelper(client)
    start = time.monotonic()
    helper.fetch_principals()
    elapsed = time.monotonic() - start

    # With sequential fetch: 3 * delay; with parallel: ~1 * delay.
    # Allow slack for thread scheduling.
    assert elapsed < delay_seconds * 2, (
        f"Expected parallel fetch (~{delay_seconds}s) but elapsed {elapsed:.2f}s "
        f"suggests sequential execution ({delay_seconds * 3:.2f}s)"
    )


def test_workspace_helper_fetches_workspace_principal_types_in_parallel() -> None:
    """Same parallelism check for the use_workspace_scim=True code path."""
    import time
    client = MagicMock()

    delay_seconds = 0.3

    def _slow_list(*args, **kwargs):
        time.sleep(delay_seconds)
        return iter([])

    client.users.list.side_effect = _slow_list
    client.groups.list.side_effect = _slow_list
    client.service_principals.list.side_effect = _slow_list

    helper = WorkspaceHelper(client, use_workspace_scim=True)
    start = time.monotonic()
    helper.fetch_principals()
    elapsed = time.monotonic() - start

    assert elapsed < delay_seconds * 2, (
        f"Expected parallel fetch (~{delay_seconds}s) but elapsed {elapsed:.2f}s "
        f"suggests sequential execution ({delay_seconds * 3:.2f}s)"
    )


# ---------------------------------------------------------------------------
# WorkspaceHelper.fetch_actual_governed_tags / create_tag_policy / update_tag_policy
# ---------------------------------------------------------------------------


def _make_tag_policy_mock(tag_key: str, description: str | None = None, values: list[str] | None = None) -> MagicMock:
    """Build a mock TagPolicy with the fields the helper consumes."""
    policy = MagicMock()
    policy.tag_key = tag_key
    policy.description = description
    if values is None:
        policy.values = None
    else:
        mock_values = []
        for v in values:
            mv = MagicMock()
            mv.name = v
            mock_values.append(mv)
        policy.values = mock_values
    return policy


def test_workspace_helper_fetch_actual_governed_tags_returns_policies() -> None:
    """fetch_actual_governed_tags iterates the SDK list and returns a GovernedTag per policy."""
    from uc_abac_governor.governed_tags.state import GovernedTag

    client = MagicMock()
    client.tag_policies.list_tag_policies.return_value = iter([
        _make_tag_policy_mock("pii", "PII data", ["name", "email"]),
        _make_tag_policy_mock("classification", "Data classification", ["public", "internal"]),
    ])

    helper = WorkspaceHelper(client)
    result = helper.fetch_actual_governed_tags()

    assert GovernedTag(
        name="pii", comment="PII data", allowed_values=frozenset({"name", "email"}),
    ) in result
    assert GovernedTag(
        name="classification",
        comment="Data classification",
        allowed_values=frozenset({"public", "internal"}),
    ) in result


def test_workspace_helper_fetch_actual_governed_tags_is_empty_when_no_policies() -> None:
    """When the account has no tag policies, fetch returns an empty set."""
    client = MagicMock()
    client.tag_policies.list_tag_policies.return_value = iter([])

    helper = WorkspaceHelper(client)

    assert helper.fetch_actual_governed_tags() == set()


def test_workspace_helper_fetch_actual_governed_tags_parses_description_and_values() -> None:
    """Null description becomes empty string; absent values becomes empty frozenset."""
    from uc_abac_governor.governed_tags.state import GovernedTag

    client = MagicMock()
    client.tag_policies.list_tag_policies.return_value = iter([
        _make_tag_policy_mock("bare", None, None),
    ])

    helper = WorkspaceHelper(client)
    result = helper.fetch_actual_governed_tags()

    assert GovernedTag(name="bare", comment="", allowed_values=frozenset()) in result


def test_workspace_helper_create_tag_policy_passes_sdk_args() -> None:
    """create_tag_policy forwards the TagPolicy object to the SDK create method."""
    from databricks.sdk.service.tags import TagPolicy, Value

    client = MagicMock()
    helper = WorkspaceHelper(client)

    policy = TagPolicy(tag_key="pii", description="PII", values=[Value(name="name")])
    helper.create_tag_policy(policy)

    client.tag_policies.create_tag_policy.assert_called_once_with(policy)


def test_workspace_helper_update_tag_policy_uses_provided_update_mask() -> None:
    """update_tag_policy forwards the tag_key, TagPolicy body, and update_mask verbatim to the SDK."""
    from databricks.sdk.service.tags import TagPolicy, Value

    client = MagicMock()
    helper = WorkspaceHelper(client)

    policy = TagPolicy(tag_key="pii", description="New desc", values=[Value(name="email")])
    helper.update_tag_policy("pii", policy, update_mask="description,values")

    client.tag_policies.update_tag_policy.assert_called_once_with(
        tag_key="pii", tag_policy=policy, update_mask="description,values",
    )
