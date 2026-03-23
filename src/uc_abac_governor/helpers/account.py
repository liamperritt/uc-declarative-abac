from __future__ import annotations

from databricks.sdk import AccountClient


class AccountHelper:
    """Wraps AccountClient for fetching and validating account-level principals.

    Caches users, groups, and service principals after initial fetch.
    """

    def __init__(self, account_client: AccountClient) -> None:
        self._client = account_client
        self._users: set[str] | None = None
        self._groups: set[str] | None = None
        self._service_principals: dict[str, str] | None = None  # display_name -> application_id

    def fetch_principals(self) -> None:
        """Fetch and cache all users, groups, and service principals from the account.

        Raises DuplicateServicePrincipalError if two SPs share the same display name.
        """
        raise NotImplementedError

    def validate_principal(self, name: str) -> bool:
        """Check if a principal name exists in any of the cached principal sets."""
        raise NotImplementedError

    def validate_principals(self, names: list[str]) -> None:
        """Validate a list of principal names. Raises PrincipalValidationError listing all unknown names."""
        raise NotImplementedError

    def get_sp_application_id(self, display_name: str) -> str:
        """Return the application_id for a service principal given its display name.

        Raises PrincipalValidationError if the display name is not a known service principal.
        """
        raise NotImplementedError
