from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from uc_abac_governor.helpers.account import AccountHelper
from uc_abac_governor.types import DuplicateServicePrincipalError, PrincipalValidationError


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------


def _make_user(user_name: str) -> MagicMock:
    user = MagicMock()
    user.user_name = user_name
    return user


def _make_group(display_name: str) -> MagicMock:
    group = MagicMock()
    group.display_name = display_name
    return group


def _make_sp(display_name: str, application_id: str) -> MagicMock:
    sp = MagicMock()
    sp.display_name = display_name
    sp.application_id = application_id
    return sp


def _make_account_client(
    users: list[MagicMock] | None = None,
    groups: list[MagicMock] | None = None,
    service_principals: list[MagicMock] | None = None,
) -> MagicMock:
    client = MagicMock()
    client.users.list.return_value = users or []
    client.groups.list.return_value = groups or []
    client.service_principals.list.return_value = service_principals or []
    return client


# ---------------------------------------------------------------------------
# AccountHelper.fetch_principals
# ---------------------------------------------------------------------------


def test_account_helper_fetches_and_caches_users() -> None:
    """After fetch_principals, user emails are available and the API is only called once."""
    client = _make_account_client(
        users=[_make_user("alice@example.com"), _make_user("bob@example.com")],
    )
    helper = AccountHelper(client)
    helper.fetch_principals()
    helper.fetch_principals()  # second call should use cache

    assert helper.validate_principal("alice@example.com") is True
    assert helper.validate_principal("bob@example.com") is True
    assert client.users.list.call_count == 1


def test_account_helper_fetches_and_caches_groups() -> None:
    """After fetch_principals, group display names are available and the API is only called once."""
    client = _make_account_client(
        groups=[_make_group("data_engineers"), _make_group("analysts")],
    )
    helper = AccountHelper(client)
    helper.fetch_principals()
    helper.fetch_principals()  # second call should use cache

    assert helper.validate_principal("data_engineers") is True
    assert helper.validate_principal("analysts") is True
    assert client.groups.list.call_count == 1


def test_account_helper_fetches_and_caches_service_principals() -> None:
    """After fetch_principals, SP display names are available and the API is only called once."""
    client = _make_account_client(
        service_principals=[_make_sp("my-sp", "app-id-123")],
    )
    helper = AccountHelper(client)
    helper.fetch_principals()
    helper.fetch_principals()  # second call should use cache

    assert helper.validate_principal("my-sp") is True
    assert client.service_principals.list.call_count == 1


def test_account_helper_fails_to_get_sp_application_id_on_duplicate_display_names() -> None:
    """Two SPs with same display_name -> fetch_principals raises DuplicateServicePrincipalError."""
    client = _make_account_client(
        service_principals=[
            _make_sp("duplicate-sp", "app-001"),
            _make_sp("duplicate-sp", "app-002"),
        ],
    )
    helper = AccountHelper(client)

    with pytest.raises(DuplicateServicePrincipalError):
        helper.fetch_principals()


# ---------------------------------------------------------------------------
# AccountHelper.validate_principal
# ---------------------------------------------------------------------------


def test_account_helper_validates_known_principal() -> None:
    """Returns True for a user, group, or SP in cache."""
    client = _make_account_client(
        users=[_make_user("alice@example.com")],
        groups=[_make_group("data_engineers")],
        service_principals=[_make_sp("etl-runner", "app-001")],
    )
    helper = AccountHelper(client)
    helper.fetch_principals()

    assert helper.validate_principal("alice@example.com") is True
    assert helper.validate_principal("data_engineers") is True
    assert helper.validate_principal("etl-runner") is True


def test_account_helper_invalidates_unknown_principal() -> None:
    """Returns False for unknown name."""
    client = _make_account_client(
        users=[_make_user("alice@example.com")],
    )
    helper = AccountHelper(client)
    helper.fetch_principals()

    assert helper.validate_principal("nobody@example.com") is False


def test_account_helper_invalidates_principals_with_invalid_names() -> None:
    """Given a list with bad names, raises PrincipalValidationError listing all bad names."""
    client = _make_account_client(
        users=[_make_user("alice@example.com")],
        groups=[_make_group("data_engineers")],
    )
    helper = AccountHelper(client)
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
# AccountHelper.get_sp_application_id
# ---------------------------------------------------------------------------


def test_account_helper_gets_sp_application_id_for_known_sp() -> None:
    """Returns the application_id for a known SP."""
    client = _make_account_client(
        service_principals=[_make_sp("etl-runner", "app-42")],
    )
    helper = AccountHelper(client)
    helper.fetch_principals()

    assert helper.get_sp_application_id("etl-runner") == "app-42"


def test_account_helper_fails_to_get_sp_application_id_for_unknown_sp() -> None:
    """Raises PrincipalValidationError for unknown SP display name."""
    client = _make_account_client(
        service_principals=[_make_sp("etl-runner", "app-42")],
    )
    helper = AccountHelper(client)
    helper.fetch_principals()

    with pytest.raises(PrincipalValidationError):
        helper.get_sp_application_id("nonexistent-sp")
