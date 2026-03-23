from __future__ import annotations

from databricks.sdk import AccountClient

from uc_abac_governor.types import DuplicateServicePrincipalError, PrincipalValidationError


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
        Results are cached after the first call.
        """
        if self._users is not None:
            return
        self._users = {user.user_name for user in self._client.users.list()}
        self._groups = {group.display_name for group in self._client.groups.list()}

        sp_map: dict[str, str] = {}
        for sp in self._client.service_principals.list():
            if sp.display_name in sp_map:
                raise DuplicateServicePrincipalError(
                    f"Duplicate service principal display name: {sp.display_name}"
                )
            sp_map[sp.display_name] = sp.application_id
        self._service_principals = sp_map

    def validate_principal(self, name: str) -> bool:
        """Check if a principal name exists in any of the cached principal sets."""
        return (
            name in (self._users or set())
            or name in (self._groups or set())
            or name in (self._service_principals or {})
        )

    def validate_principals(self, names: list[str]) -> None:
        """Validate a list of principal names. Raises PrincipalValidationError listing all unknown names."""
        unknown = [name for name in names if not self.validate_principal(name)]
        if unknown:
            raise PrincipalValidationError(
                f"Unknown principals: {', '.join(unknown)}"
            )

    def get_sp_application_id(self, display_name: str) -> str:
        """Return the application_id for a service principal given its display name.

        Raises PrincipalValidationError if the display name is not a known service principal.
        """
        if self._service_principals and display_name in self._service_principals:
            return self._service_principals[display_name]
        raise PrincipalValidationError(
            f"Service principal not found: {display_name}"
        )
