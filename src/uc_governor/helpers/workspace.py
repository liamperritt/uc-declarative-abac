from __future__ import annotations

import logging

from databricks.sdk import WorkspaceClient

from uc_governor.types import (
    DuplicateServicePrincipalError,
    Principal,
    PrincipalType,
    PrincipalValidationError,
)

_logger = logging.getLogger("uc_governor")


class WorkspaceHelper:
    """Wraps WorkspaceClient for fetching and validating workspace principals.

    Uses the workspace-level SCIM API to list users, groups, and service principals.
    Caches results after initial fetch.
    """

    def __init__(self, workspace_client: WorkspaceClient) -> None:
        self._client = workspace_client
        self._users: set[str] | None = None
        self._groups: set[str] | None = None
        self._service_principals: dict[str, str] | None = None  # display_name -> application_id
        self._duplicate_sps: set[str] = set()

    def fetch_principals(self) -> None:
        """Fetch and cache all users, groups, and service principals from the workspace.

        Duplicate service principal display names are logged as warnings and
        tracked. The first application_id is kept; subsequent duplicates are
        skipped. Callers using a duplicate SP in a policy will get an error
        at resolve time via get_sp_application_id.
        Results are cached after the first call.
        """
        if self._users is not None:
            return
        self._users = {user.user_name for user in self._client.users.list(attributes="userName")}
        self._groups = {group.display_name for group in self._client.groups.list(attributes="displayName")}

        sp_map: dict[str, str] = {}
        for sp in self._client.service_principals.list(attributes="displayName,applicationId"):
            if sp.display_name in sp_map:
                self._duplicate_sps.add(sp.display_name)
                continue
            sp_map[sp.display_name] = sp.application_id
        self._service_principals = sp_map
        self._sp_app_id_to_name: dict[str, str] = {v: k for k, v in sp_map.items()}

    def get_principals(self) -> dict[str, Principal]:
        """Return a mapping of principal names to Principal objects.

        Includes all cached users, groups, and service principals.
        Must be called after fetch_principals().
        """
        result: dict[str, Principal] = {}
        for username in self._users or set():
            result[username] = Principal(PrincipalType.USER, username, username)
        for group_name in self._groups or set():
            result[group_name] = Principal(PrincipalType.GROUP, group_name, group_name)
        for sp_name, app_id in (self._service_principals or {}).items():
            result[sp_name] = Principal(PrincipalType.SERVICE_PRINCIPAL, app_id, sp_name)
        return result

    def validate_principal(self, name: str) -> bool:
        """Check if a principal name exists in any of the cached principal sets."""
        return (
            name in (self._users or set())
            or name in (self._groups or set())
            or name in (self._service_principals or {})
        )

    def validate_principals(self, names: list[str]) -> None:
        """Validate a list of principal names. Raises PrincipalValidationError listing all unknown names."""
        unknown = self.find_unknown_principals(names)
        if unknown:
            raise PrincipalValidationError(
                f"Unknown principals: {', '.join(unknown)}"
            )

    def find_unknown_principals(self, names: list[str]) -> list[str]:
        """Return the subset of principal names that do not exist in the workspace."""
        return [name for name in names if not self.validate_principal(name)]

    def get_sp_application_id(self, display_name: str) -> str:
        """Return the application_id for a service principal given its display name.

        Raises DuplicateServicePrincipalError if the display name is ambiguous.
        Raises PrincipalValidationError if the display name is not a known service principal.
        """
        if display_name in self._duplicate_sps:
            raise DuplicateServicePrincipalError(
                f"Ambiguous service principal: '{display_name}' has duplicate display names"
            )
        if self._service_principals and display_name in self._service_principals:
            return self._service_principals[display_name]
        raise PrincipalValidationError(
            f"Service principal not found: {display_name}"
        )

    def resolve_by_name(self, name: str) -> Principal:
        """Resolve a principal display name to a Principal object.

        Checks users, groups, then service principals in order.
        Raises PrincipalValidationError if the name is not found.
        """
        if self._users and name in self._users:
            return Principal(PrincipalType.USER, name, name)
        if self._groups and name in self._groups:
            return Principal(PrincipalType.GROUP, name, name)
        if self._service_principals and name in self._service_principals:
            return Principal(
                PrincipalType.SERVICE_PRINCIPAL,
                self._service_principals[name],
                name,
            )
        raise PrincipalValidationError(f"Principal not found: {name}")

    def resolve_by_identifier(self, identifier: str) -> Principal:
        """Resolve a system-table identifier back to a Principal object.

        For users, identifier is the username. For groups, identifier is
        the display name. For SPs, identifier is the application_id.
        Raises PrincipalValidationError if the identifier is not found.
        """
        if self._users and identifier in self._users:
            return Principal(PrincipalType.USER, identifier, identifier)
        if self._groups and identifier in self._groups:
            return Principal(PrincipalType.GROUP, identifier, identifier)
        sp_reverse = getattr(self, "_sp_app_id_to_name", {})
        if identifier in sp_reverse:
            return Principal(
                PrincipalType.SERVICE_PRINCIPAL,
                identifier,
                sp_reverse[identifier],
            )
        raise PrincipalValidationError(f"Principal not found by identifier: {identifier}")
