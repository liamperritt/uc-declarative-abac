from __future__ import annotations

import logging
import threading
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

from databricks.sdk import WorkspaceClient
from databricks.sdk.service.iam import GrantRule, RuleSetResponse, RuleSetUpdateRequest
from databricks.sdk.service.iamv2 import DirectGroupMember
from databricks.sdk.service.tags import TagPolicy

from uc_declarative_abac.governed_tags import GovernedTag
from uc_declarative_abac.principals import (
    Group,
    GroupRename,
    Principal,
    ensure_resolved,
)
from uc_declarative_abac.types import PrincipalType
from uc_declarative_abac.utils import (
    SYSTEM_ACCOUNT_GROUPS,
    DuplicateServicePrincipalError,
    OrchestratorError,
    PrincipalValidationError,
)

_logger = logging.getLogger("uc_declarative_abac")


# Account-level system groups that neither identity API surfaces (they exist only at
# the account level) but are near-universally useful as policy targets. Appended to
# the fetched groups in both modes. Sourced from utils (single source of truth,
# shared with the group-deletion candidate filter).
_ACCOUNT_SYSTEM_GROUPS = SYSTEM_ACCOUNT_GROUPS

# Account Access Control Proxy ASSIGN role on tag policies.
# TBD: verify in integration testing; the SDK does not export a constant for
# this role name. If the API rejects it, call
# `account_access_control_proxy.get_assignable_roles_for_resource` once and
# update this constant accordingly.
_TAG_POLICY_ASSIGN_ROLE = "roles/tagPolicy.assigner"

# Account Access Control Proxy assumer role on account groups (the RBAC
# `roles/group.assumer` grant that lets its principals manage the group's role
# assignments). TBD: verify in integration testing; the SDK does not export a constant
# for this role name. If the API rejects it, call
# `account_access_control_proxy.get_assignable_roles_for_resource` once and update this.
_GROUP_ASSUMER_ROLE = "roles/group.assumer"

# Bounded concurrency for per-tag get_rule_set calls during the actual-state fetch.
_ASSIGN_FETCH_WORKERS = 8

# Bounded concurrency for per-group member-list fetches.
_GROUP_FETCH_WORKERS = 8


def _ruleset_name(account_id: str, tag_id: str) -> str:
    """Build the AccessControl proxy ruleset resource name for a tag policy."""
    return f"accounts/{account_id}/tagPolicies/{tag_id}/ruleSets/default"


def _group_ruleset_name(account_id: str, group_id: str) -> str:
    """Build the AccessControl proxy ruleset resource name for an account group."""
    return f"accounts/{account_id}/groups/{group_id}/ruleSets/default"


def _encode_path_segment(value: str) -> str:
    """Percent-encode a value for use as a single URL path segment."""
    return quote(value, safe="")


def _parse_ruleset_principal(s: str) -> str:
    """Strip the SCIM-prefix (`users/`, `groups/`, `servicePrincipals/`) from a
    ruleset principal string and return the bare identifier. The differ resolves
    type from the workspace cache via resolve_by_identifier."""
    _, _, identifier = s.partition("/")
    return identifier or s


def _direct_member_to_principal(
    member: DirectGroupMember,
    identifier_by_id: dict[str, str],
) -> Principal | None:
    """Convert a V2 DirectGroupMember (read path) to an unresolved Principal.

    ``member.principal_id`` is the member's numeric internal id (an ``int``); it is
    mapped to the principal's canonical identifier (username / display name /
    application_id). Returns None when the id has no known identifier (the member is
    then dropped)."""
    identifier = identifier_by_id.get(str(member.principal_id))
    if not identifier:
        return None
    return Principal(PrincipalType.UNKNOWN, identifier=identifier)


def _principal_to_member_dict(
    principal: Principal,
    scim_id_by_identifier: dict[str, str],
) -> dict:
    """Convert a resolved Principal to a SCIM group-member dict ({"value": <id>}) for
    the account SCIM proxy write path.

    The Principal must be resolved; its canonical identifier is looked up in the id
    map (populated from the V2 read path — the V2 internal id doubles as the SCIM
    member value)."""
    ensure_resolved(principal)
    return {
        "value": scim_id_by_identifier.get(principal.identifier, principal.identifier)
    }


class WorkspaceHelper:
    """Wraps WorkspaceClient for fetching and validating principals.

    Supports two modes controlled by use_workspace_scim:
    - use_workspace_scim=False (default): the account path. **Reads** (listing users,
      groups, and service principals; reading group membership) use the Workspace
      Identity V2 API (``workspace_iam_v2``). **Writes** (create / rename / delete a
      group, add / remove members) use the account SCIM proxy — the SCIM
      ``POST /Groups`` grants the creating principal the MANAGER role on the new group,
      which the V2 create does not, so keeping writes on SCIM lets the engine manage
      what it creates. The V2 internal id and the SCIM id are the same value, so ids
      read via V2 are used directly in the SCIM write path.
    - use_workspace_scim=True: uses the SDK's SCIM API to list only workspace-level principals.

    Caches results after initial fetch.
    """

    def __init__(
        self,
        workspace_client: WorkspaceClient,
        use_workspace_scim: bool = False,
        manage_groups: bool = False,
        skip_users_fetch: bool = False,
    ) -> None:
        self._client = workspace_client
        self._use_workspace_scim = use_workspace_scim
        self._manage_groups = manage_groups
        self._skip_users_fetch = skip_users_fetch
        self._users: set[str] | None = None
        self._groups: set[str] | None = None
        self._service_principals: dict[str, str] | None = (
            None  # display_name -> application_id
        )
        self._duplicate_sps: set[str] = set()
        # Group-management caches, populated by _fetch_account_principals when
        # manage_groups is enabled (otherwise left empty). Membership is NOT cached
        # here — it is fetched per-group on demand in fetch_actual_groups. Ids are the
        # numeric internal principal ids the V2 API exposes as strings (str(int)).
        self._group_id_by_name: dict[str, str] = {}  # display_name -> group id
        self._group_name_by_id: dict[str, str] = {}  # group id -> display_name
        self._external_id_by_group_name: dict[
            str, str
        ] = {}  # display_name -> external_id ("" for Databricks-managed)
        self._renamed_group_new_by_old: dict[
            str, str
        ] = {}  # old display_name -> new display_name
        self._scim_id_by_identifier: dict[
            str, str
        ] = {}  # canonical identifier -> internal id
        self._identifier_by_scim_id: dict[
            str, str
        ] = {}  # internal id -> canonical identifier
        self._tag_policies_lock = threading.Lock()
        self._tag_policies: list[TagPolicy] | None = None
        self._tag_policy_id_by_name: dict[str, str] = {}

    def fetch_principals(self) -> None:
        """Fetch and cache all principals. Dispatches based on use_workspace_scim."""
        if self._users is not None:
            return
        if self._use_workspace_scim:
            self._fetch_workspace_principals()
        else:
            self._fetch_account_principals()

    def _fetch_account_principals(self) -> None:
        """Fetch principals via the Workspace Identity V2 API (all account principals).

        Users, groups, and service principals are fetched concurrently via the
        ``workspace_iam_v2`` list proxies (the SDK owns pagination). Every list object
        carries its numeric internal id, so — unlike the old SCIM proxy — no attribute
        selection is needed. Group *membership* is not read here (the V2 list has no
        inline members); it is fetched per-group in fetch_actual_groups, scoped to
        configured groups. Principal ``account_*_status`` is intentionally not filtered
        on: every listed principal is a valid grant/policy target, matching prior
        behaviour.
        """
        iam = self._client.workspace_iam_v2
        with ThreadPoolExecutor(max_workers=3) as pool:
            # When skipping the user fetch, don't submit the users list at all — it is
            # the slowest list for large accounts and pure overhead for orgs that
            # govern only groups and service principals.
            users_f = (
                None
                if self._skip_users_fetch
                else pool.submit(lambda: list(iam.list_users_proxy()))
            )
            groups_f = pool.submit(lambda: list(iam.list_groups_proxy()))
            sps_f = pool.submit(lambda: list(iam.list_service_principals_proxy()))
            users_data = users_f.result() if users_f is not None else []
            groups_data = groups_f.result()
            sps_data = sps_f.result()

        self._users = {u.username for u in users_data if u.username}
        # The list proxy returns real account groups but not the special system
        # groups (e.g. `account admins`), so add them — they are valid grant/policy
        # principals even though they aren't returned by the list call.
        self._groups = {
            g.group_name for g in groups_data if g.group_name
        } | _ACCOUNT_SYSTEM_GROUPS
        # _build_sp_map takes SCIM-format dicts (shared with the workspace-SCIM path).
        self._build_sp_map(
            [
                {"displayName": sp.display_name, "applicationId": sp.application_id}
                for sp in sps_data
            ]
        )
        if self._manage_groups:
            self._build_group_id_maps(users_data, groups_data, sps_data)

    def _build_group_id_maps(
        self,
        users_data: list,
        groups_data: list,
        sps_data: list,
    ) -> None:
        """Build the id ↔ canonical-identifier maps and the group-name → id index from
        the V2 list responses.

        Group *membership* is not read here — the V2 group list has no inline members.
        Membership is fetched per-group in fetch_actual_groups (scoped to configured
        groups). The maps built here translate a member's numeric principal id back to
        its canonical identifier (username / display name / application_id) once those
        fetches return; ids are stored as strings (the V2 ``*_id`` field type)."""
        for user in users_data:
            id_, identifier = user.user_id, user.username
            if id_ and identifier:
                self._identifier_by_scim_id[id_] = identifier
                self._scim_id_by_identifier[identifier] = id_
        for sp in sps_data:
            id_, identifier = sp.service_principal_id, sp.application_id
            if id_ and identifier:
                self._identifier_by_scim_id[id_] = identifier
                self._scim_id_by_identifier[identifier] = id_
        for group in groups_data:
            id_, display_name = group.group_id, group.group_name
            if id_ and display_name:
                self._identifier_by_scim_id[id_] = display_name
                self._scim_id_by_identifier[display_name] = id_
                self._group_id_by_name[display_name] = id_
                self._group_name_by_id[id_] = display_name
                self._external_id_by_group_name[display_name] = group.external_id or ""

    def _fetch_workspace_principals(self) -> None:
        """Fetch principals via the SDK's workspace SCIM API (workspace principals only).

        Users, groups, and service principals are fetched concurrently.
        """
        with ThreadPoolExecutor(max_workers=3) as pool:
            # See _fetch_account_principals: skip the user list entirely when the
            # org governs only groups and service principals.
            users_f = (
                None
                if self._skip_users_fetch
                else pool.submit(
                    lambda: list(self._client.users.list(attributes="userName")),
                )
            )
            groups_f = pool.submit(
                lambda: list(self._client.groups.list(attributes="displayName")),
            )
            sps_f = pool.submit(
                lambda: list(
                    self._client.service_principals.list(
                        attributes="displayName,applicationId"
                    )
                ),
            )
            users = users_f.result() if users_f is not None else []
            groups = groups_f.result()
            sps = sps_f.result()

        self._users = {user.user_name for user in users}
        # The workspace SCIM API does not surface account-level system groups, so
        # add them — they are near-universally useful as policy targets.
        self._groups = {group.display_name for group in groups} | _ACCOUNT_SYSTEM_GROUPS
        self._build_sp_map(
            [
                {"displayName": sp.display_name, "applicationId": sp.application_id}
                for sp in sps
            ]
        )

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
            result[sp_name] = Principal(
                PrincipalType.SERVICE_PRINCIPAL, app_id, sp_name
            )
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
            raise PrincipalValidationError(f"Unknown principals: {', '.join(unknown)}")

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
        raise PrincipalValidationError(f"Service principal not found: {display_name}")

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

        A group pending a rename this run is still referenced by its OLD display
        name in actual state (deployed grants/policies/assigners); that old name is
        canonicalized to the NEW group principal so it matches the desired
        (new-name) references and yields no spurious diff.
        """
        if self._users and identifier in self._users:
            return Principal(PrincipalType.USER, identifier, identifier)
        new_name = self._renamed_group_new_by_old.get(identifier)
        if new_name is not None:
            return Principal(PrincipalType.GROUP, new_name, new_name)
        if self._groups and identifier in self._groups:
            return Principal(PrincipalType.GROUP, identifier, identifier)
        sp_reverse = getattr(self, "_sp_app_id_to_name", {})
        if identifier in sp_reverse:
            return Principal(
                PrincipalType.SERVICE_PRINCIPAL,
                identifier,
                sp_reverse[identifier],
            )
        raise PrincipalValidationError(
            f"Principal not found by identifier: {identifier}"
        )

    def _fetch_group_members(self, group_id: str) -> frozenset[Principal]:
        """List a single group's direct members via the V2 identity API and return them
        as canonical-identifier Principals.

        ``list_direct_group_members_proxy`` takes the group's numeric id as an ``int``;
        each member's numeric ``principal_id`` is mapped back to a canonical identifier
        via the cache built during fetch_principals. Untranslatable members are
        dropped."""
        members = self._client.workspace_iam_v2.list_direct_group_members_proxy(
            int(group_id)
        )
        return frozenset(
            p
            for p in (
                _direct_member_to_principal(m, self._identifier_by_scim_id)
                for m in members
            )
            if p is not None
        )

    def _fetch_group_members_for(
        self, group_ids: set[str]
    ) -> dict[str, frozenset[Principal]]:
        """Fetch membership (as canonical-identifier Principals) for each group id via
        one ``list_direct_group_members_proxy`` call each, dispatched concurrently up to
        ``_GROUP_FETCH_WORKERS``. Only groups whose desired ``members`` are authoritative
        are passed in — the rest keep ``members=None`` (unmanaged, never fetched)."""
        if not group_ids:
            return {}
        worker_count = min(_GROUP_FETCH_WORKERS, len(group_ids))
        results: dict[str, frozenset[Principal]] = {}
        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            future_to_id = {
                pool.submit(self._fetch_group_members, gid): gid for gid in group_ids
            }
            for future, gid in future_to_id.items():
                results[gid] = future.result()
        return results

    def _fetch_group_assumers_for(
        self, group_ids: set[str]
    ) -> dict[str, frozenset[Principal]]:
        """Fetch the assumer principals (``roles/group.assumer``) for each group id via
        its account access-control rule set, dispatched concurrently up to
        ``_ASSIGN_FETCH_WORKERS``. Only groups whose desired ``assumers`` are
        authoritative are passed in — the rest keep ``assumers=None`` (unmanaged)."""
        if not group_ids:
            return {}
        worker_count = min(_ASSIGN_FETCH_WORKERS, len(group_ids))
        results: dict[str, frozenset[Principal]] = {}
        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            future_to_id = {
                pool.submit(self.get_group_rule_set, gid): gid for gid in group_ids
            }
            for future, gid in future_to_id.items():
                results[gid] = self._extract_group_assumers(future.result())
        return results

    @staticmethod
    def _extract_group_assumers(resp: RuleSetResponse) -> frozenset[Principal]:
        """Read the assumer grant_rule from a rule-set response and return its
        principals as unresolved Principal objects. Non-assumer rules are ignored."""
        assumers: set[Principal] = set()
        for rule in resp.grant_rules or []:
            if rule.role != _GROUP_ASSUMER_ROLE:
                continue
            for raw in rule.principals or []:
                assumers.add(
                    Principal(
                        PrincipalType.UNKNOWN,
                        identifier=_parse_ruleset_principal(raw),
                    )
                )
        return frozenset(assumers)

    def fetch_actual_groups(
        self,
        desired_names: set[str] | None = None,
        desired_ids: set[str] | None = None,
        member_fetch_names: set[str] | None = None,
        member_fetch_ids: set[str] | None = None,
        assumer_fetch_names: set[str] | None = None,
        assumer_fetch_ids: set[str] | None = None,
    ) -> set[Group]:
        """Fetch actual-state Groups (identity, membership, assumers) for configured groups.

        Identity (display name, id, ``external_id``) is built from the caches populated
        during ``fetch_principals()`` — no per-group call. The candidate set is
        ``desired_names`` (the groups declared in config) intersected with the account
        groups, plus any account group whose id is in ``desired_ids`` (matched under its
        *current* display name — this is how a renamed group, whose config holds the new
        name but whose account still holds the old one, is located by id). A desired id
        with no matching account group is left for the differ to flag.

        Membership and assumers are **authoritative only when supplied**, so each is
        fetched only for its own subset: a group's members are read (one
        ``list_direct_group_members_proxy`` call — the V2 group list doesn't return
        members inline) only when its display name is in ``member_fetch_names`` or its id
        in ``member_fetch_ids``; its assumers are read (one rule-set GET) only when in
        ``assumer_fetch_names`` / ``assumer_fetch_ids``. Groups outside a subset keep that
        field ``None`` (unmanaged — never fetched). Both fetches are dispatched
        concurrently. Must be called after ``fetch_principals()``. Returns an empty set
        when group management is disabled.
        """
        if not self._manage_groups or not self._group_id_by_name:
            return set()
        names = set(self._group_id_by_name)
        if desired_names is not None:
            names &= desired_names
        for scim_id in desired_ids or set():
            actual_name = self._group_name_by_id.get(scim_id)
            if actual_name is not None:
                names.add(actual_name)
        if not names:
            return set()
        member_fetch_names = member_fetch_names or set()
        member_fetch_ids = member_fetch_ids or set()
        assumer_fetch_names = assumer_fetch_names or set()
        assumer_fetch_ids = assumer_fetch_ids or set()
        # display_name -> id, deduped by name (id is unique per name in the cache).
        candidates = {name: self._group_id_by_name[name] for name in names}
        members_by_id = self._fetch_group_members_for(
            {
                gid
                for name, gid in candidates.items()
                if name in member_fetch_names or gid in member_fetch_ids
            }
        )
        assumers_by_id = self._fetch_group_assumers_for(
            {
                gid
                for name, gid in candidates.items()
                if name in assumer_fetch_names or gid in assumer_fetch_ids
            }
        )
        return {
            Group(
                display_name=name,
                id=gid,
                external_id=self._external_id_by_group_name.get(name, ""),
                members=members_by_id.get(gid),
                assumers=assumers_by_id.get(gid),
            )
            for name, gid in candidates.items()
        }

    def list_account_groups(self) -> set[Group]:
        """Return every account group as membership-less Group state (display name, id,
        external_id).

        Built from the group id/external-id maps populated during ``fetch_principals()``
        — no additional API calls and no membership fetch, since the group-deletion
        candidate filter only needs identity and provenance (``external_id``). Returns an
        empty set unless group management (the ``manage_groups`` fetch path) is enabled.
        Must be called after ``fetch_principals()``.
        """
        if not self._manage_groups:
            return set()
        return {
            Group(
                display_name=name,
                external_id=self._external_id_by_group_name.get(name, ""),
                id=scim_id,
            )
            for name, scim_id in self._group_id_by_name.items()
        }

    def register_pending_groups(self, names: Iterable[str]) -> None:
        """Add group display names that will be created this run to the principal
        cache so downstream domains can resolve them as GROUP principals before the
        group physically exists. A group's resolved identity is fully determined by
        its display name (identifier == name), so no fetch is needed. Mirrors
        register_created_tag_policy's cache-priming for newly-created objects."""
        names = set(names)
        if not names:
            return
        self._groups = (self._groups or set()) | names

    def register_pending_renames(self, renames: Iterable[GroupRename]) -> None:
        """Reflect pending group renames in the principal cache so downstream
        domains resolve the renamed group consistently.

        Mirrors register_pending_groups: the group domain runs first, so the cache
        is updated here before later domains (governed-tag assigners, policies,
        privileges, securable owners) resolve principals. The old name is removed
        from ``_groups`` and the new name added, so a **config-side** reference to
        the old name (``resolve_by_name``) fails (a stale YAML reference must error)
        while the new name resolves. **Actual-state** references still carry the old
        name (the deployed grants/policies/assigners aren't renamed yet — in dry-run
        they never are), so ``resolve_by_identifier`` canonicalizes the old name to
        the new group principal via ``_renamed_group_new_by_old``; that way an actual
        grant to the old name compares equal to a desired grant to the new name and
        produces no spurious diff. Applied even in dry-run — the rename call is
        skipped, but the cache must reflect the rename for resolution. Also remaps
        ``_group_id_by_name`` so the executor's member add/remove (keyed by the new
        display name) finds the group id."""
        for rename in renames:
            scim_id = self._group_id_by_name.pop(rename.old_display_name, rename.id)
            self._group_id_by_name[rename.new_display_name] = scim_id
            self._group_name_by_id[scim_id] = rename.new_display_name
            self._scim_id_by_identifier.pop(rename.old_display_name, None)
            self._scim_id_by_identifier[rename.new_display_name] = scim_id
            self._identifier_by_scim_id[scim_id] = rename.new_display_name
            self._renamed_group_new_by_old[rename.old_display_name] = (
                rename.new_display_name
            )
            if self._groups is not None:
                self._groups = (self._groups - {rename.old_display_name}) | {
                    rename.new_display_name
                }

    def rename_group(self, group_id: str, new_display_name: str) -> None:
        """Rename a Databricks-managed account group via a SCIM PatchOp (replace
        displayName). Requires the engine principal to hold the MANAGER role on the
        group.

        Writes go through the account SCIM proxy (not the V2 identity API): the SCIM
        proxy is the mutation path that keeps the engine principal MANAGER on groups it
        creates, so all group writes stay on it for consistency.
        """
        self._client.api_client.do(
            "PATCH",
            f"/api/2.0/account/scim/v2/Groups/{group_id}",
            body={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {"op": "replace", "path": "displayName", "value": new_display_name},
                ],
            },
        )

    def delete_group(self, group_id: str) -> None:
        """Delete a Databricks-managed account group via the account SCIM proxy."""
        self._client.api_client.do(
            "DELETE",
            f"/api/2.0/account/scim/v2/Groups/{group_id}",
        )

    def create_group(self, display_name: str) -> str:
        """Create a Databricks-managed account group (initially empty) via the account
        SCIM proxy and return its new id.

        Writes use the SCIM proxy rather than the V2 identity API deliberately: the
        SCIM ``POST /Groups`` grants the creating principal the MANAGER role on the new
        group (so the engine can manage it going forward), whereas V2
        ``create_group_proxy`` does not.

        Members are added afterwards via ``add_group_members`` rather than at creation
        time: a group whose members include other groups created in the same run can
        only be linked once every group (and its id) exists. The caller must feed the
        returned id to ``register_created_group`` on the main thread before adding
        members.
        """
        response = self._client.api_client.do(
            "POST",
            "/api/2.0/account/scim/v2/Groups",
            body={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "displayName": display_name,
            },
        )
        return (response or {}).get("id", "")

    def register_created_group(self, display_name: str, group_id: str) -> None:
        """Register a just-created group's id into the principal caches so it resolves
        as a GROUP principal and ``add_group_members`` can target it by id.

        Called on the main thread after ``create_group`` returns (workers never touch
        shared caches). Mirrors ``register_pending_groups``' cache-priming, but with
        the real id now known — which is what lets a member that is itself a group
        created this run resolve to a real id when its parent's membership is set.
        """
        self._groups = (self._groups or set()) | {display_name}
        if group_id:
            self._group_id_by_name[display_name] = group_id
            self._group_name_by_id[group_id] = display_name
            self._scim_id_by_identifier[display_name] = group_id
            self._identifier_by_scim_id[group_id] = display_name

    def add_group_members(
        self, display_name: str, members: Iterable[Principal]
    ) -> None:
        """Add members to an existing Databricks-managed account group via a SCIM
        PatchOp (batch add). The member ids come from the V2 read path (the internal id
        doubles as the SCIM member value)."""
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

    def remove_group_members(
        self, display_name: str, members: Iterable[Principal]
    ) -> None:
        """Remove members from an existing Databricks-managed account group via a SCIM
        PatchOp (batch remove). Requires the engine principal to hold the MANAGER role
        on the group."""
        group_id = self._group_id_by_name[display_name]
        operations = [
            {
                "op": "remove",
                "path": f'members[value eq "{_principal_to_member_dict(m, self._scim_id_by_identifier)["value"]}"]',
            }
            for m in members
        ]
        if not operations:
            return
        self._client.api_client.do(
            "PATCH",
            f"/api/2.0/account/scim/v2/Groups/{group_id}",
            body={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": operations,
            },
        )

    def _ensure_tag_policies_loaded(self) -> list[TagPolicy]:
        """Lazily list tag policies once and cache them. Thread-safe."""
        with self._tag_policies_lock:
            if self._tag_policies is None:
                policies = list(self._client.tag_policies.list_tag_policies())
                self._tag_policies = policies
                self._tag_policy_id_by_name = {
                    p.tag_key: p.id for p in policies if p.id
                }
            return self._tag_policies

    def fetch_actual_governed_tags(
        self,
        desired_names: set[str] | None = None,
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
        self,
        policies: list[TagPolicy],
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
        for rule in resp.grant_rules or []:
            if rule.role != _TAG_POLICY_ASSIGN_ROLE:
                continue
            for raw in rule.principals or []:
                assigners.add(
                    Principal(
                        PrincipalType.UNKNOWN,
                        identifier=_parse_ruleset_principal(raw),
                    )
                )
        return frozenset(assigners)

    def get_tag_policy_rule_set(self, tag_id: str) -> RuleSetResponse:
        """Fetch the default rule set for a tag policy. Uses an empty etag (fresh
        state) — callers performing read-modify-write should pass the returned
        etag back into ``update_tag_policy_rule_set``."""
        name = _ruleset_name(self._account_id(), tag_id)
        return self._client.account_access_control_proxy.get_rule_set(
            name=name, etag=""
        )

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
        self,
        tag_id: str,
        etag: str,
        grant_rules: list[GrantRule],
    ) -> RuleSetResponse:
        """Replace the rule set for a tag policy. ``etag`` must come from a prior
        ``get_tag_policy_rule_set`` call (read-modify-write for optimistic concurrency)."""
        name = _ruleset_name(self._account_id(), tag_id)
        request = RuleSetUpdateRequest(name=name, etag=etag, grant_rules=grant_rules)
        return self._client.account_access_control_proxy.update_rule_set(
            name=name,
            rule_set=request,
        )

    def get_group_rule_set(self, group_id: str) -> RuleSetResponse:
        """Fetch the default account access-control rule set for a group. Uses an empty
        etag (fresh state) — callers performing read-modify-write should pass the
        returned etag back into ``update_group_rule_set``."""
        name = _group_ruleset_name(self._account_id(), group_id)
        return self._client.account_access_control_proxy.get_rule_set(
            name=name, etag=""
        )

    def update_group_rule_set(
        self,
        group_id: str,
        etag: str,
        grant_rules: list[GrantRule],
    ) -> RuleSetResponse:
        """Replace the account access-control rule set for a group. ``etag`` must come
        from a prior ``get_group_rule_set`` call (read-modify-write for optimistic
        concurrency)."""
        name = _group_ruleset_name(self._account_id(), group_id)
        request = RuleSetUpdateRequest(name=name, etag=etag, grant_rules=grant_rules)
        return self._client.account_access_control_proxy.update_rule_set(
            name=name,
            rule_set=request,
        )

    def get_group_id(self, display_name: str) -> str | None:
        """Return the cached id for a group display name, or None."""
        return self._group_id_by_name.get(display_name)

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

    def update_tag_policy(
        self, tag_key: str, policy: TagPolicy, update_mask: str
    ) -> TagPolicy:
        """Update a tag policy, encoding its key as one URL path segment.

        ``update_mask`` is a comma-separated list of field names (for example,
        ``description,values``); ``*`` is discouraged by the SDK.
        """
        return self._client.tag_policies.update_tag_policy(
            tag_key=_encode_path_segment(tag_key),
            tag_policy=policy,
            update_mask=update_mask,
        )

    def delete_tag_policy(self, tag_key: str) -> None:
        """Delete a governed tag, encoding its key as one URL path segment.

        Deletion is gated at the orchestrator boundary by the
        ``--enable-governed-tag-deletion`` flag and interactive confirmation.
        """
        self._client.tag_policies.delete_tag_policy(_encode_path_segment(tag_key))
