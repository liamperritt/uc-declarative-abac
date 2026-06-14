from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable

from databricks.sdk import WorkspaceClient
from databricks.sdk.service.iam import GrantRule, RuleSetResponse, RuleSetUpdateRequest
from databricks.sdk.service.tags import TagPolicy

from uc_declarative_abac.governed_tags import GovernedTag
from uc_declarative_abac.utils import (
    DuplicateServicePrincipalError,
    OrchestratorError,
    PrincipalValidationError,
)
from uc_declarative_abac.principals import Group, Principal, ensure_resolved
from uc_declarative_abac.types import PrincipalType

_logger = logging.getLogger("uc_declarative_abac")


_SCIM_PAGE_SIZE = 100

# Account-level system groups that the workspace SCIM API does not surface (they
# exist only at the account level) but are near-universally useful as policy
# targets. Appended to the fetched groups in workspace-SCIM mode.
_ACCOUNT_SYSTEM_GROUPS = frozenset({"account users", "account admins"})

# Account Access Control Proxy ASSIGN role on tag policies.
# TBD: verify in integration testing; the SDK does not export a constant for
# this role name. If the API rejects it, call
# `account_access_control_proxy.get_assignable_roles_for_resource` once and
# update this constant accordingly.
_TAG_POLICY_ASSIGN_ROLE = "roles/tagPolicy.assigner"

# Bounded concurrency for per-tag get_rule_set calls during the actual-state fetch.
_ASSIGN_FETCH_WORKERS = 8

# Bounded concurrency for per-group GET /Groups/{id} member fetches.
_GROUP_FETCH_WORKERS = 8


def _ruleset_name(account_id: str, tag_id: str) -> str:
    """Build the AccessControl proxy ruleset resource name for a tag policy."""
    return f"accounts/{account_id}/tagPolicies/{tag_id}/ruleSets/default"


def _parse_ruleset_principal(s: str) -> str:
    """Strip the SCIM-prefix (`users/`, `groups/`, `servicePrincipals/`) from a
    ruleset principal string and return the bare identifier. The differ resolves
    type from the workspace cache via resolve_by_identifier."""
    _, _, identifier = s.partition("/")
    return identifier or s


def _member_dict_to_principal(
    member: dict, identifier_by_scim_id: dict[str, str],
) -> Principal | None:
    """Convert a raw SCIM group-member dict to an unresolved Principal.

    The member's ``value`` is a SCIM id; it is mapped to the principal's canonical
    identifier (username / display name / application_id). Returns None when the
    member's SCIM id has no known identifier (the member is then dropped)."""
    scim_id = member.get("value")
    identifier = identifier_by_scim_id.get(scim_id) if scim_id else None
    if not identifier:
        return None
    return Principal(PrincipalType.UNKNOWN, identifier=identifier)


def _principal_to_member_dict(
    principal: Principal, scim_id_by_identifier: dict[str, str],
) -> dict:
    """Convert a resolved Principal to a SCIM group-member dict ({"value": <scim id>}).

    The Principal must be resolved (its canonical identifier is looked up in the
    SCIM-id map)."""
    ensure_resolved(principal)
    return {"value": scim_id_by_identifier.get(principal.identifier, principal.identifier)}


class WorkspaceHelper:
    """Wraps WorkspaceClient for fetching and validating principals.

    Supports two modes controlled by use_workspace_scim:
    - use_workspace_scim=False (default): uses the workspace account SCIM proxy endpoints to
      list all users, groups, and service principals in the account.
    - use_workspace_scim=True: uses the SDK's SCIM API to list only workspace-level principals.

    Caches results after initial fetch.
    """

    def __init__(
        self,
        workspace_client: WorkspaceClient,
        use_workspace_scim: bool = False,
        manage_groups: bool = False,
    ) -> None:
        self._client = workspace_client
        self._use_workspace_scim = use_workspace_scim
        self._manage_groups = manage_groups
        self._users: set[str] | None = None
        self._groups: set[str] | None = None
        self._service_principals: dict[str, str] | None = None  # display_name -> application_id
        self._duplicate_sps: set[str] = set()
        # Group-management caches, populated by _fetch_account_principals when
        # manage_groups is enabled (otherwise left empty). Membership is NOT cached
        # here — it is fetched per-group on demand in fetch_actual_groups.
        self._group_id_by_name: dict[str, str] = {}  # display_name -> group SCIM id
        self._scim_id_by_identifier: dict[str, str] = {}  # canonical identifier -> SCIM id
        self._identifier_by_scim_id: dict[str, str] = {}  # SCIM id -> canonical identifier
        self._tag_policies_lock = threading.Lock()
        self._tag_policies: list[TagPolicy] | None = None
        self._tag_policy_id_by_name: dict[str, str] = {}

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
        # When managing groups, the SAME three list calls request each principal's
        # SCIM id so member SCIM ids can be translated to canonical identifiers.
        # Group membership itself is NOT read from the list response — the account
        # SCIM proxy does not reliably return `members` inline; it is fetched
        # per-group via GET /Groups/{id} in fetch_actual_groups (scoped to config).
        if self._manage_groups:
            users_attrs = "id,userName"
            groups_attrs = "id,displayName"
            sps_attrs = "id,displayName,applicationId"
        else:
            users_attrs = "userName"
            groups_attrs = "displayName"
            sps_attrs = "displayName,applicationId"

        with ThreadPoolExecutor(max_workers=3) as pool:
            users_f = pool.submit(
                self._scim_list_all, "/api/2.0/account/scim/v2/Users", users_attrs,
            )
            groups_f = pool.submit(
                self._scim_list_all, "/api/2.0/account/scim/v2/Groups", groups_attrs,
            )
            sps_f = pool.submit(
                self._scim_list_all,
                "/api/2.0/account/scim/v2/ServicePrincipals",
                sps_attrs,
            )
            users_data = users_f.result()
            groups_data = groups_f.result()
            sps_data = sps_f.result()

        self._users = {u["userName"] for u in users_data if "userName" in u}
        self._groups = {g["displayName"] for g in groups_data if "displayName" in g}
        self._build_sp_map(sps_data)
        if self._manage_groups:
            self._build_group_id_maps(users_data, groups_data, sps_data)

    def _build_group_id_maps(
        self, users_data: list[dict], groups_data: list[dict], sps_data: list[dict],
    ) -> None:
        """Build the SCIM-id ↔ canonical-identifier maps and the group-name → id
        index from the principal list responses.

        Group *membership* is not read here — the account SCIM proxy list endpoint
        does not reliably return members inline. Membership is fetched per-group in
        fetch_actual_groups via GET /Groups/{id} (scoped to configured groups). The
        maps built here translate member SCIM ids back to canonical identifiers
        (username / display name / application_id) once those GETs return."""
        for user in users_data:
            scim_id, identifier = user.get("id"), user.get("userName")
            if scim_id and identifier:
                self._identifier_by_scim_id[scim_id] = identifier
                self._scim_id_by_identifier[identifier] = scim_id
        for sp in sps_data:
            scim_id, identifier = sp.get("id"), sp.get("applicationId")
            if scim_id and identifier:
                self._identifier_by_scim_id[scim_id] = identifier
                self._scim_id_by_identifier[identifier] = scim_id
        for group in groups_data:
            scim_id, display_name = group.get("id"), group.get("displayName")
            if scim_id and display_name:
                self._identifier_by_scim_id[scim_id] = display_name
                self._scim_id_by_identifier[display_name] = scim_id
                self._group_id_by_name[display_name] = scim_id

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
        # The workspace SCIM API does not surface account-level system groups, so
        # add them — they are near-universally useful as policy targets.
        self._groups = {group.display_name for group in groups} | _ACCOUNT_SYSTEM_GROUPS
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

    def _fetch_group_by_id(self, group_id: str) -> dict:
        """GET a single account group (with its members) via the SCIM proxy.

        TBD: verify in integration testing; the account SCIM proxy list endpoint
        does not reliably return `members` inline, so membership is read here from
        the individual-group endpoint (members carry `value`; the group carries
        `externalId`)."""
        return self._client.api_client.do(
            "GET", f"/api/2.0/account/scim/v2/Groups/{group_id}",
        )

    def _build_group_from_response(self, resp: dict) -> Group:
        """Translate a single-group GET response into Group state.

        Member SCIM ids are mapped back to canonical identifiers via the cache
        built during fetch_principals; untranslatable members are dropped."""
        members = frozenset(
            p for p in (
                _member_dict_to_principal(m, self._identifier_by_scim_id)
                for m in (resp.get("members") or [])
            ) if p is not None
        )
        return Group(
            display_name=resp.get("displayName") or "",
            external_id=resp.get("externalId") or "",
            members=members,
        )

    def fetch_actual_groups(self, desired_names: set[str] | None = None) -> set[Group]:
        """Fetch actual-state Groups (with membership) for the configured groups.

        Scoped to ``desired_names`` (the groups declared in config) intersected with
        the account groups discovered during ``fetch_principals()`` — groups absent
        from config are never fetched, since their membership is irrelevant. Issues
        one ``GET /Groups/{id}`` per managed group (the account SCIM proxy list call
        does not reliably return members inline), dispatched concurrently up to
        ``_GROUP_FETCH_WORKERS``. Must be called after ``fetch_principals()``.
        Returns an empty set when group management is disabled.
        """
        if not self._manage_groups or not self._group_id_by_name:
            return set()
        names = set(self._group_id_by_name)
        if desired_names is not None:
            names &= desired_names
        if not names:
            return set()
        targets = [(name, self._group_id_by_name[name]) for name in names]
        worker_count = min(_GROUP_FETCH_WORKERS, len(targets))
        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            responses = pool.map(lambda t: self._fetch_group_by_id(t[1]), targets)
            return {self._build_group_from_response(resp) for resp in responses}

    def create_group(self, display_name: str, members: Iterable[Principal]) -> None:
        """Create a Databricks-managed account group with the given initial members.

        TBD: verify in integration testing; the exact SCIM body shape for the
        account SCIM proxy create endpoint is assumed here. If the API rejects it,
        adjust the body (e.g. schemas / members shape) accordingly.
        """
        member_dicts = [
            _principal_to_member_dict(m, self._scim_id_by_identifier) for m in members
        ]
        self._client.api_client.do(
            "POST",
            "/api/2.0/account/scim/v2/Groups",
            body={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "displayName": display_name,
                "members": member_dicts,
            },
        )

    def add_group_members(self, display_name: str, members: Iterable[Principal]) -> None:
        """Add members to an existing Databricks-managed account group via SCIM PatchOp.

        TBD: verify in integration testing; the exact SCIM PatchOp body shape for
        the account SCIM proxy patch endpoint is assumed here. If the API rejects
        it, adjust the body accordingly.
        """
        group_id = self._group_id_by_name[display_name]
        member_dicts = [
            _principal_to_member_dict(m, self._scim_id_by_identifier) for m in members
        ]
        self._client.api_client.do(
            "PATCH",
            f"/api/2.0/account/scim/v2/Groups/{group_id}",
            body={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {"op": "add", "path": "members", "value": member_dicts},
                ],
            },
        )

    def _ensure_tag_policies_loaded(self) -> list[TagPolicy]:
        """Lazily list tag policies once and cache them. Thread-safe."""
        with self._tag_policies_lock:
            if self._tag_policies is None:
                policies = list(self._client.tag_policies.list_tag_policies())
                self._tag_policies = policies
                self._tag_policy_id_by_name = {p.tag_key: p.id for p in policies if p.id}
            return self._tag_policies

    def fetch_actual_governed_tags(
        self, desired_names: set[str] | None = None,
    ) -> set[GovernedTag]:
        """Fetch the account's current tag policies and convert them to GovernedTag state.

        For each tag whose tag_key is in ``desired_names``, also fetch the tag
        policy's rule set and populate ``assigners`` from the ASSIGN grant
        rule. Tags absent from ``desired_names`` get an empty ``assigners`` —
        they only flow through the create/delete paths in the diff, where the
        field is irrelevant.

        Cost: 1 list call + |actual ∩ desired_names| get_rule_set calls,
        the latter dispatched concurrently up to ``_ASSIGN_FETCH_WORKERS``.

        Safe to call inside the parallel fetch block — does not depend on the
        principal cache.
        """
        policies = self._ensure_tag_policies_loaded()
        scoped_names: set[str] = set(desired_names) if desired_names else set()
        assigners_by_name: dict[str, frozenset[Principal]] = {}
        if scoped_names:
            assigners_by_name = self._fetch_assigners_for(
                [p for p in policies if p.tag_key in scoped_names and p.id],
            )
        return {
            GovernedTag(
                name=policy.tag_key,
                description=policy.description or "",
                allowed_values=frozenset(v.name for v in (policy.values or [])),
                assigners=assigners_by_name.get(policy.tag_key, frozenset()),
            )
            for policy in policies
        }

    def _fetch_assigners_for(
        self, policies: list[TagPolicy],
    ) -> dict[str, frozenset[Principal]]:
        """Concurrently fetch the assigners (ASSIGN-role principals) for each tag policy."""
        if not policies:
            return {}
        worker_count = min(_ASSIGN_FETCH_WORKERS, len(policies))
        results: dict[str, frozenset[Principal]] = {}
        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            future_to_name = {
                pool.submit(self.get_tag_policy_rule_set, policy.id): policy.tag_key
                for policy in policies
            }
            for future, name in future_to_name.items():
                resp = future.result()
                results[name] = self._extract_assigners(resp)
        return results

    @staticmethod
    def _extract_assigners(resp: RuleSetResponse) -> frozenset[Principal]:
        """Read the ASSIGN grant_rule from a rule-set response and return its
        assigners as unresolved Principal objects. Non-ASSIGN rules are ignored."""
        assigners: set[Principal] = set()
        for rule in (resp.grant_rules or []):
            if rule.role != _TAG_POLICY_ASSIGN_ROLE:
                continue
            for raw in (rule.principals or []):
                assigners.add(Principal(
                    PrincipalType.UNKNOWN,
                    identifier=_parse_ruleset_principal(raw),
                ))
        return frozenset(assigners)

    def get_tag_policy_rule_set(self, tag_id: str) -> RuleSetResponse:
        """Fetch the default rule set for a tag policy. Uses an empty etag (fresh
        state) — callers performing read-modify-write should pass the returned
        etag back into ``update_tag_policy_rule_set``."""
        name = _ruleset_name(self._account_id(), tag_id)
        return self._client.account_access_control_proxy.get_rule_set(name=name, etag="")

    def get_tag_policy_rule_set_by_name(self, tag_name: str) -> RuleSetResponse:
        """Look up the tag's id from the cache, then fetch its default rule set."""
        tag_id = self._tag_policy_id_by_name.get(tag_name)
        if not tag_id:
            raise OrchestratorError(
                f"Tag policy id not cached for {tag_name!r}; call fetch_actual_governed_tags "
                "or register_created_tag_policy first."
            )
        return self.get_tag_policy_rule_set(tag_id)

    def update_tag_policy_rule_set(
        self, tag_id: str, etag: str, grant_rules: list[GrantRule],
    ) -> RuleSetResponse:
        """Replace the rule set for a tag policy. ``etag`` must come from a prior
        ``get_tag_policy_rule_set`` call (read-modify-write for optimistic concurrency)."""
        name = _ruleset_name(self._account_id(), tag_id)
        request = RuleSetUpdateRequest(name=name, etag=etag, grant_rules=grant_rules)
        return self._client.account_access_control_proxy.update_rule_set(
            name=name, rule_set=request,
        )

    def register_created_tag_policy(self, tag_policy: TagPolicy) -> None:
        """Update the name→id cache after a successful create_tag_policy call so
        rule-set operations can target the newly-created tag immediately."""
        if tag_policy.id and tag_policy.tag_key:
            self._tag_policy_id_by_name[tag_policy.tag_key] = tag_policy.id

    def get_tag_policy_id(self, tag_name: str) -> str | None:
        """Return the cached tag policy id for a tag name, or None if unknown."""
        return self._tag_policy_id_by_name.get(tag_name)

    def _account_id(self) -> str:
        """Read account_id from the WorkspaceClient config; raise on absence."""
        account_id = getattr(self._client.config, "account_id", None)
        if not account_id:
            raise OrchestratorError(
                "WorkspaceClient.config.account_id is not set; required for tag-policy "
                "rule-set operations. Configure account_id in your Databricks profile."
            )
        return account_id

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
        passthrough to the SDK — gated at the orchestrator boundary by the
        ``--enable-governed-tag-deletion`` flag and interactive confirmation."""
        self._client.tag_policies.delete_tag_policy(tag_key)
