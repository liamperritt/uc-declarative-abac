from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from databricks.sdk import WorkspaceClient
from databricks.sdk.service.tags import TagPolicy

from uc_abac_governor.governed_tags.state import GovernedTag
from uc_abac_governor.principals.state import Principal
from uc_abac_governor.types import (
    DuplicateServicePrincipalError,
    PrincipalType,
    PrincipalValidationError,
)

_logger = logging.getLogger("uc_abac_governor")


_SCIM_PAGE_SIZE = 100


class WorkspaceHelper:
    """Wraps WorkspaceClient for fetching and validating principals.

    Supports two modes controlled by use_workspace_scim:
    - use_workspace_scim=False (default): uses the workspace account SCIM proxy endpoints to
      list all users, groups, and service principals in the account.
    - use_workspace_scim=True: uses the SDK's SCIM API to list only workspace-level principals.

    Caches results after initial fetch.
    """

    def __init__(self, workspace_client: WorkspaceClient, use_workspace_scim: bool = False) -> None:
        self._client = workspace_client
        self._use_workspace_scim = use_workspace_scim
        self._users: set[str] | None = None
        self._groups: set[str] | None = None
        self._service_principals: dict[str, str] | None = None  # display_name -> application_id
        self._duplicate_sps: set[str] = set()

    def _scim_list_all(self, endpoint: str, attributes: str) -> list[dict]:
        """Paginate through an account SCIM proxy endpoint, returning all resources."""
        results: list[dict] = []
        start_index = 1
        while True:
            resp = self._client.api_client.do(
                "GET", endpoint,
                query={"startIndex": start_index, "count": _SCIM_PAGE_SIZE, "attributes": attributes},
            )
            resources = resp.get("Resources", [])
            results.extend(resources)
            total = resp.get("totalResults", 0)
            items_per_page = len(resources)
            if not resources or start_index + items_per_page > total:
                break
            start_index += items_per_page
        return results

    def fetch_principals(self) -> None:
        """Fetch and cache all principals. Dispatches based on use_workspace_scim."""
        if self._users is not None:
            return
        if self._use_workspace_scim:
            self._fetch_workspace_principals()
        else:
            self._fetch_account_principals()

    def _fetch_account_principals(self) -> None:
        """Fetch principals via the workspace account SCIM proxy (all account principals).

        Users, groups, and service principals are fetched concurrently.
        """
        with ThreadPoolExecutor(max_workers=3) as pool:
            users_f = pool.submit(
                self._scim_list_all, "/api/2.0/account/scim/v2/Users", "userName",
            )
            groups_f = pool.submit(
                self._scim_list_all, "/api/2.0/account/scim/v2/Groups", "displayName",
            )
            sps_f = pool.submit(
                self._scim_list_all,
                "/api/2.0/account/scim/v2/ServicePrincipals",
                "displayName,applicationId",
            )
            users_data = users_f.result()
            groups_data = groups_f.result()
            sps_data = sps_f.result()

        self._users = {u["userName"] for u in users_data if "userName" in u}
        self._groups = {g["displayName"] for g in groups_data if "displayName" in g}
        self._build_sp_map(sps_data)

    def _fetch_workspace_principals(self) -> None:
        """Fetch principals via the SDK's workspace SCIM API (workspace principals only).

        Users, groups, and service principals are fetched concurrently.
        """
        with ThreadPoolExecutor(max_workers=3) as pool:
            users_f = pool.submit(
                lambda: list(self._client.users.list(attributes="userName")),
            )
            groups_f = pool.submit(
                lambda: list(self._client.groups.list(attributes="displayName")),
            )
            sps_f = pool.submit(
                lambda: list(self._client.service_principals.list(attributes="displayName,applicationId")),
            )
            users = users_f.result()
            groups = groups_f.result()
            sps = sps_f.result()

        self._users = {user.user_name for user in users}
        self._groups = {group.display_name for group in groups}
        self._build_sp_map([
            {"displayName": sp.display_name, "applicationId": sp.application_id}
            for sp in sps
        ])

    def _build_sp_map(self, sps_data: list[dict]) -> None:
        """Build the service principal maps from SCIM-format dicts."""
        sp_map: dict[str, str] = {}
        for sp in sps_data:
            display_name = sp.get("displayName")
            app_id = sp.get("applicationId")
            if not display_name or not app_id:
                continue
            if display_name in sp_map:
                self._duplicate_sps.add(display_name)
                continue
            sp_map[display_name] = app_id
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

    def fetch_actual_governed_tags(self) -> set[GovernedTag]:
        """Fetch the account's current tag policies and convert them to GovernedTag state.

        Safe to call inside the parallel fetch block — does not depend on the
        principal cache.
        """
        return {
            GovernedTag(
                name=policy.tag_key,
                description=policy.description or "",
                allowed_values=frozenset(v.name for v in (policy.values or [])),
            )
            for policy in self._client.tag_policies.list_tag_policies()
        }

    def create_tag_policy(self, policy: TagPolicy) -> TagPolicy:
        """Create a new tag policy in the account. Thin passthrough to the SDK."""
        return self._client.tag_policies.create_tag_policy(policy)

    def update_tag_policy(self, tag_key: str, policy: TagPolicy, update_mask: str) -> TagPolicy:
        """Update an existing tag policy. `update_mask` is a comma-separated list
        of field names (e.g. 'description,values'); `*` is discouraged by the SDK."""
        return self._client.tag_policies.update_tag_policy(
            tag_key=tag_key, tag_policy=policy, update_mask=update_mask,
        )

    def delete_tag_policy(self, tag_key: str) -> None:
        """Delete a governed tag (account-level tag policy) by its key. Thin
        passthrough to the SDK — gated at the governor boundary by the
        ``--enable-governed-tag-deletion`` flag and interactive confirmation."""
        self._client.tag_policies.delete_tag_policy(tag_key)
