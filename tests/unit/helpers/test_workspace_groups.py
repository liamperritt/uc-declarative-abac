from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from databricks.sdk.service.iam import GrantRule, RuleSetResponse, RuleSetUpdateRequest

from uc_declarative_abac.helpers import WorkspaceHelper
from uc_declarative_abac.principals import GroupRename, Principal
from uc_declarative_abac.types import PrincipalType
from uc_declarative_abac.utils import PrincipalValidationError

# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------
#
# The account identity path now runs on Workspace Identity V2. Principal ids are
# numeric internal ids: the V2 list objects expose them as strings (``user_id`` /
# ``group_id`` / ``service_principal_id``) while ``DirectGroupMember.principal_id``
# is an ``int``. Tests therefore use numeric-string ids so the helper's ``int(...)``
# casts at the membership-call boundary line up (a member's ``principal_id`` int
# equals ``int`` of the owning principal's id string).


def _make_user(user_name: str, user_id: str) -> SimpleNamespace:
    """Stand-in for a databricks.sdk.service.iamv2.User."""
    return SimpleNamespace(username=user_name, user_id=user_id)


def _make_group(
    display_name: str,
    group_id: str,
    external_id: str = "",
    members: list[SimpleNamespace] | None = None,
) -> SimpleNamespace:
    """Stand-in for a databricks.sdk.service.iamv2.Group.

    ``members`` is not a real V2 Group field — the V2 list proxy never returns
    membership inline. It is carried here only so the mock client can serve it via
    ``list_direct_group_members_proxy``; the helper never reads it off the group.
    """
    return SimpleNamespace(
        group_name=display_name,
        group_id=group_id,
        external_id=external_id,
        members=members or [],
    )


def _make_sp(display_name: str, application_id: str, sp_id: str) -> SimpleNamespace:
    """Stand-in for a databricks.sdk.service.iamv2.ServicePrincipal."""
    return SimpleNamespace(
        display_name=display_name,
        application_id=application_id,
        service_principal_id=sp_id,
    )


def _make_member(principal_id: int) -> SimpleNamespace:
    """Stand-in for a databricks.sdk.service.iamv2.DirectGroupMember."""
    return SimpleNamespace(principal_id=principal_id)


def _make_workspace_client(
    users: list[SimpleNamespace] | None = None,
    groups: list[SimpleNamespace] | None = None,
    service_principals: list[SimpleNamespace] | None = None,
) -> MagicMock:
    """Build a MagicMock WorkspaceClient for the hybrid account path: reads on the
    ``workspace_iam_v2`` proxies, writes on the account SCIM proxy (``api_client.do``).

    Reads — ``list_groups_proxy`` yields groups WITHOUT members (V2 has no inline
    membership), and ``list_direct_group_members_proxy`` serves each group's members
    keyed by group id. Writes — ``api_client.do`` handles the SCIM mutations: a
    ``POST /Groups`` returns the new group's id; PATCH (rename / member add/remove) and
    DELETE return a benign dict and are inspected via ``call_args_list``.
    """
    client = MagicMock()
    groups = groups or []
    members_by_id = {str(g.group_id): g.members for g in groups}

    iam = client.workspace_iam_v2
    iam.list_users_proxy.side_effect = lambda **kwargs: iter(users or [])
    iam.list_service_principals_proxy.side_effect = lambda **kwargs: iter(
        service_principals or []
    )
    iam.list_groups_proxy.side_effect = lambda **kwargs: iter(
        SimpleNamespace(
            group_name=g.group_name,
            group_id=g.group_id,
            external_id=g.external_id,
        )
        for g in groups
    )
    iam.list_direct_group_members_proxy.side_effect = lambda group_id, **kwargs: iter(
        members_by_id.get(str(group_id), [])
    )

    def _scim_write(method, path, **kwargs):
        if method == "POST" and path.endswith("/Groups"):
            return {"id": "created-group-id"}
        return {}

    client.api_client.do.side_effect = _scim_write
    return client


# ---------------------------------------------------------------------------
# fetch_actual_groups — gating on manage_groups
# ---------------------------------------------------------------------------


def test_workspace_helper_returns_no_groups_when_manage_groups_disabled() -> None:
    """With manage_groups=False (default), no group state is built and
    fetch_actual_groups returns an empty set."""
    client = _make_workspace_client(
        groups=[_make_group("data_engineers", "g-1")],
    )
    helper = WorkspaceHelper(client, manage_groups=False)
    helper.fetch_principals()

    assert helper.fetch_actual_groups() == set()


def test_workspace_helper_fetches_members_per_managed_group() -> None:
    """fetch_actual_groups issues one list_direct_group_members_proxy call per managed
    (configured) group — membership is not available from the group list response."""
    client = _make_workspace_client(
        users=[_make_user("alice@example.com", "1")],
        groups=[
            _make_group("data_engineers", "10"),
            _make_group("analysts", "20"),
        ],
        service_principals=[_make_sp("etl-sp", "abc-123", "100")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    assert client.workspace_iam_v2.list_direct_group_members_proxy.call_count == 0

    helper.fetch_actual_groups(
        desired_names={"data_engineers"}, member_fetch_names={"data_engineers"}
    )

    # One member fetch for the single configured group (analysts is not fetched).
    assert client.workspace_iam_v2.list_direct_group_members_proxy.call_count == 1


def test_workspace_helper_actual_group_includes_existing_members() -> None:
    """Regression for the always-re-adds bug: an existing group's members are read
    from the per-group member fetch, so the actual Group carries the members it
    already has (the differ can then compute an empty additions set on a synced
    group)."""
    client = _make_workspace_client(
        users=[_make_user("liam.perritt@databricks.com", "1")],
        service_principals=[_make_sp("sp_uc_governor_test", "app-uuid", "100")],
        groups=[
            _make_group(
                "uc_governor_test_team",
                "10",
                members=[
                    _make_member(1),
                    _make_member(100),
                ],
            ),
        ],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    result = helper.fetch_actual_groups(
        desired_names={"uc_governor_test_team"},
        member_fetch_names={"uc_governor_test_team"},
    )

    group = next(g for g in result if g.display_name == "uc_governor_test_team")
    identifiers = {member.identifier for member in group.members}
    assert identifiers == {"liam.perritt@databricks.com", "app-uuid"}


# ---------------------------------------------------------------------------
# fetch_actual_groups — group state
# ---------------------------------------------------------------------------


def test_workspace_helper_returns_a_group_per_fetched_group() -> None:
    """With manage_groups=True, fetch_actual_groups returns one Group per fetched
    group, with display_name matching."""
    client = _make_workspace_client(
        groups=[
            _make_group("data_engineers", "10"),
            _make_group("analysts", "20"),
        ],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    result = helper.fetch_actual_groups()

    names = {group.display_name for group in result}
    assert names == {"data_engineers", "analysts"}


def test_workspace_helper_translates_user_member_to_username_identifier() -> None:
    """A group with a user member is translated from the member's numeric principal
    id to the user's userName as the member identifier."""
    client = _make_workspace_client(
        users=[_make_user("alice@example.com", "1")],
        groups=[
            _make_group(
                "data_engineers",
                "10",
                members=[_make_member(1)],
            ),
        ],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    result = helper.fetch_actual_groups(member_fetch_names={"data_engineers"})

    group = next(g for g in result if g.display_name == "data_engineers")
    assert (
        Principal(PrincipalType.UNKNOWN, identifier="alice@example.com")
        in group.members
    )


def test_workspace_helper_translates_sp_member_to_application_id_identifier() -> None:
    """A group member matching a service principal is translated to the SP's
    applicationId as the member identifier."""
    client = _make_workspace_client(
        service_principals=[_make_sp("etl-sp", "abc-123-uuid", "100")],
        groups=[
            _make_group(
                "automation",
                "10",
                members=[_make_member(100)],
            ),
        ],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    result = helper.fetch_actual_groups(member_fetch_names={"automation"})

    group = next(g for g in result if g.display_name == "automation")
    assert Principal(PrincipalType.UNKNOWN, identifier="abc-123-uuid") in group.members


def test_workspace_helper_populates_external_id_for_idp_managed_group() -> None:
    """external_id is populated for an IdP-managed group (non-empty externalId)
    and empty for a normal group. external_id is read from the LIST response cache,
    not per-group GETs."""
    client = _make_workspace_client(
        groups=[
            _make_group("idp_group", "10", external_id="ext-999"),
            _make_group("native_group", "20", external_id=""),
        ],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    result = helper.fetch_actual_groups()

    idp = next(g for g in result if g.display_name == "idp_group")
    native = next(g for g in result if g.display_name == "native_group")
    assert idp.external_id == "ext-999"
    assert native.external_id == ""


def test_workspace_helper_filters_groups_to_desired_names() -> None:
    """fetch_actual_groups(desired_names=...) returns only groups whose
    display_name is in the desired set."""
    client = _make_workspace_client(
        groups=[
            _make_group("data_engineers", "10"),
            _make_group("analysts", "20"),
        ],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    result = helper.fetch_actual_groups(desired_names={"data_engineers"})

    names = {group.display_name for group in result}
    assert names == {"data_engineers"}


def test_workspace_helper_drops_untranslatable_members() -> None:
    """A member whose numeric principal id matches no fetched principal is dropped
    from the resulting group's members."""
    client = _make_workspace_client(
        users=[_make_user("alice@example.com", "1")],
        groups=[
            _make_group(
                "data_engineers",
                "10",
                members=[
                    _make_member(1),
                    _make_member(999),
                ],
            ),
        ],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    result = helper.fetch_actual_groups(member_fetch_names={"data_engineers"})

    group = next(g for g in result if g.display_name == "data_engineers")
    identifiers = {member.identifier for member in group.members}
    assert identifiers == {"alice@example.com"}


# ---------------------------------------------------------------------------
# register_pending_groups
# ---------------------------------------------------------------------------


def test_workspace_helper_register_pending_groups_resolves_as_group() -> None:
    """A group registered as pending (to be created this run) resolves as a GROUP
    principal by both name and identifier, even though it wasn't in the fetch."""
    client = _make_workspace_client(users=[_make_user("alice@example.com", "1")])
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    helper.register_pending_groups({"new_team"})

    assert helper.resolve_by_name("new_team") == Principal(
        PrincipalType.GROUP,
        "new_team",
        "new_team",
    )
    assert helper.resolve_by_identifier("new_team") == Principal(
        PrincipalType.GROUP,
        "new_team",
        "new_team",
    )


# ---------------------------------------------------------------------------
# add_group_members
# ---------------------------------------------------------------------------


def test_workspace_helper_add_group_members_issues_patch() -> None:
    """add_group_members issues a SCIM PATCH whose path contains the target group's id
    and whose request references the member's id."""
    client = _make_workspace_client(
        users=[_make_user("alice@example.com", "1")],
        groups=[_make_group("data_engineers", "10")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    member = Principal(PrincipalType.USER, "alice@example.com", "alice@example.com")
    helper.add_group_members("data_engineers", [member])

    patch_calls = [
        call
        for call in client.api_client.do.call_args_list
        if call.args and call.args[0] == "PATCH"
    ]
    assert len(patch_calls) == 1
    call = patch_calls[0]
    assert "/Groups/10" in call.args[1]
    # The member's id should appear somewhere in the captured request body.
    assert "'1'" in repr(call.kwargs) or '"1"' in repr(call.kwargs)


# ---------------------------------------------------------------------------
# remove_group_members
# ---------------------------------------------------------------------------


def test_workspace_helper_remove_group_members_issues_patch() -> None:
    """remove_group_members issues a SCIM PATCH whose path contains the target group's
    id and whose request references the member's id in a remove op."""
    client = _make_workspace_client(
        users=[_make_user("alice@example.com", "1")],
        groups=[_make_group("data_engineers", "10")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    member = Principal(PrincipalType.USER, "alice@example.com", "alice@example.com")
    helper.remove_group_members("data_engineers", [member])

    patch_calls = [
        call
        for call in client.api_client.do.call_args_list
        if call.args and call.args[0] == "PATCH"
    ]
    assert len(patch_calls) == 1
    call = patch_calls[0]
    assert "/Groups/10" in call.args[1]
    captured = repr(call.kwargs)
    assert "1" in captured
    assert "remove" in captured


# ---------------------------------------------------------------------------
# create_group
# ---------------------------------------------------------------------------


def test_workspace_helper_create_group_posts_empty_and_returns_id() -> None:
    """create_group POSTs the group with NO members via the SCIM proxy and returns the
    new id. Members are added in a later phase, so a group whose members are themselves
    created this run can be linked once every group exists."""
    client = _make_workspace_client()
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    new_id = helper.create_group("new_team")

    assert new_id == "created-group-id"
    post_calls = [
        call
        for call in client.api_client.do.call_args_list
        if call.args and call.args[0] == "POST"
    ]
    assert len(post_calls) == 1
    call = post_calls[0]
    assert "/api/2.0/account/scim/v2/Groups" in call.args[1]
    captured = repr(call.kwargs)
    assert "new_team" in captured
    assert "members" not in captured


def test_workspace_helper_register_created_group_makes_group_resolvable_and_manageable() -> (
    None
):
    """After register_created_group, the new group resolves as a GROUP principal and
    add_group_members targets it by its registered id (no KeyError)."""
    client = _make_workspace_client(
        users=[_make_user("child@example.com", "5")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    helper.register_created_group("new_team", "500")

    resolved = helper.resolve_by_name("new_team")
    assert resolved.principal_type == PrincipalType.GROUP
    assert resolved.name == "new_team"

    member = Principal(PrincipalType.USER, "child@example.com", "child@example.com")
    helper.add_group_members("new_team", [member])

    patch_calls = [
        call
        for call in client.api_client.do.call_args_list
        if call.args and call.args[0] == "PATCH"
    ]
    assert len(patch_calls) == 1
    assert "/Groups/500" in patch_calls[0].args[1]


# ---------------------------------------------------------------------------
# fetch_actual_groups — rename (locate by id)
# ---------------------------------------------------------------------------


def test_workspace_helper_fetches_renamed_group_by_id_when_name_not_in_desired_names() -> (
    None
):
    """A group whose id is in desired_ids is fetched under its CURRENT (actual)
    display name even when that name is not in desired_names — config wants the new
    name, but the account still returns the old name with the matching id."""
    client = _make_workspace_client(
        groups=[_make_group("old_name", "10")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    result = helper.fetch_actual_groups(
        desired_names={"new_name"},
        desired_ids={"10"},
    )

    # Located by id and returned under its current (old) display name.
    names = {group.display_name for group in result}
    assert "old_name" in names


def test_workspace_helper_sets_id_on_actual_group_from_response() -> None:
    """The returned Group carries the id from the group identity cache."""
    client = _make_workspace_client(
        groups=[_make_group("old_name", "10")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    result = helper.fetch_actual_groups(desired_ids={"10"})

    group = next(g for g in result if g.display_name == "old_name")
    assert group.id == "10"


# ---------------------------------------------------------------------------
# register_pending_renames
# ---------------------------------------------------------------------------


def test_workspace_helper_register_pending_renames_adds_new_name_and_removes_old() -> (
    None
):
    """After register_pending_renames, the NEW display name resolves as a GROUP
    principal and the OLD name no longer resolves."""
    client = _make_workspace_client(
        groups=[_make_group("old_name", "10")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    helper.register_pending_renames(
        [
            GroupRename(
                id="10", old_display_name="old_name", new_display_name="new_name"
            )
        ],
    )

    resolved = helper.resolve_by_name("new_name")
    assert resolved.principal_type == PrincipalType.GROUP

    with pytest.raises(PrincipalValidationError):
        helper.resolve_by_name("old_name")


def test_workspace_helper_register_pending_renames_remaps_group_id_to_new_name() -> (
    None
):
    """After the rename, a member add against the NEW name resolves the group's id —
    the SCIM PATCH targets the same id that previously belonged to the old name."""
    client = _make_workspace_client(
        users=[_make_user("alice@example.com", "1")],
        groups=[_make_group("old_name", "10")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    helper.register_pending_renames(
        [
            GroupRename(
                id="10", old_display_name="old_name", new_display_name="new_name"
            )
        ],
    )

    member = Principal(PrincipalType.USER, "alice@example.com", "alice@example.com")
    helper.add_group_members("new_name", [member])

    patch_calls = [
        call
        for call in client.api_client.do.call_args_list
        if call.args and call.args[0] == "PATCH"
    ]
    assert len(patch_calls) == 1
    assert "/Groups/10" in patch_calls[0].args[1]


def test_workspace_helper_resolves_new_name_after_pending_rename() -> None:
    """resolve_by_name(new_name) returns a GROUP principal after a pending rename."""
    client = _make_workspace_client(
        groups=[_make_group("old_name", "10")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    helper.register_pending_renames(
        [
            GroupRename(
                id="10", old_display_name="old_name", new_display_name="new_name"
            )
        ],
    )

    assert helper.resolve_by_name("new_name").principal_type == PrincipalType.GROUP


def test_workspace_helper_rejects_old_name_after_pending_rename() -> None:
    """resolve_by_name(old_name) raises after a pending rename retires the old name."""
    client = _make_workspace_client(
        groups=[_make_group("old_name", "10")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    helper.register_pending_renames(
        [
            GroupRename(
                id="10", old_display_name="old_name", new_display_name="new_name"
            )
        ],
    )

    with pytest.raises(PrincipalValidationError):
        helper.resolve_by_name("old_name")


def test_workspace_helper_resolves_old_name_by_identifier_to_new_group_after_pending_rename() -> (
    None
):
    """resolve_by_identifier(old_name) returns the NEW group principal after a
    pending rename — deployed actual-state references to the old display name must
    map onto the renamed group rather than failing or showing a spurious diff."""
    client = _make_workspace_client(
        groups=[_make_group("old_name", "10")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    helper.register_pending_renames(
        [
            GroupRename(
                id="10", old_display_name="old_name", new_display_name="new_name"
            )
        ],
    )

    resolved = helper.resolve_by_identifier("old_name")
    assert resolved.principal_type == PrincipalType.GROUP
    assert resolved.identifier == "new_name"
    assert resolved.name == "new_name"


# ---------------------------------------------------------------------------
# rename_group
# ---------------------------------------------------------------------------


def test_workspace_helper_rename_group_issues_replace_displayname_patch() -> None:
    """rename_group issues a SCIM PATCH to /Groups/{id} whose Operations contain a
    replace op on the displayName path with the new value."""
    client = _make_workspace_client(
        groups=[_make_group("old_name", "10")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    helper.rename_group("10", "new")

    patch_calls = [
        call
        for call in client.api_client.do.call_args_list
        if call.args and call.args[0] == "PATCH"
    ]
    assert len(patch_calls) == 1
    call = patch_calls[0]
    assert call.args[1] == "/api/2.0/account/scim/v2/Groups/10"
    body = call.kwargs["body"]
    operations = body["Operations"]
    assert any(
        op.get("op") == "replace"
        and op.get("path") == "displayName"
        and op.get("value") == "new"
        for op in operations
    )


# ---------------------------------------------------------------------------
# fetch_actual_groups — member_fetch gating
# ---------------------------------------------------------------------------


def test_workspace_helper_members_not_fetched_when_absent_from_member_fetch() -> None:
    """When a group is not in member_fetch_names or member_fetch_ids,
    fetch_actual_groups does not fetch its members (no per-group member fetch).
    The returned group has members=None."""
    client = _make_workspace_client(
        users=[_make_user("alice@example.com", "1")],
        groups=[
            _make_group(
                "data_engineers",
                "10",
                members=[_make_member(1)],
            ),
        ],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    # fetch_actual_groups with no member_fetch_names — members not fetched
    result = helper.fetch_actual_groups(desired_names={"data_engineers"})

    group = next(g for g in result if g.display_name == "data_engineers")
    assert group.members is None
    # No per-group member fetch was issued.
    assert client.workspace_iam_v2.list_direct_group_members_proxy.call_count == 0


# ---------------------------------------------------------------------------
# fetch_actual_groups — assumer_fetch gating
# ---------------------------------------------------------------------------


def test_workspace_helper_assumers_fetched_only_for_assumer_fetch() -> None:
    """Assumers are fetched via get_rule_set only when the group is in
    assumer_fetch_names or assumer_fetch_ids. Groups outside the fetch set
    have assumers=None."""
    client = _make_workspace_client(
        groups=[
            _make_group("data_engineers", "g-1"),
            _make_group("analysts", "g-2"),
        ],
    )
    # Mock get_rule_set for account access control
    client.config.account_id = "acc-123"
    client.account_access_control_proxy.get_rule_set.return_value = RuleSetResponse(
        name="accounts/acc-123/groups/g-1/ruleSets/default",
        etag="e1",
        grant_rules=[
            GrantRule(
                role="roles/group.assumer",
                principals=["users/alice@co.com", "groups/data-admins"],
            ),
        ],
    )

    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    # Fetch assumers only for data_engineers
    result = helper.fetch_actual_groups(
        desired_names={"data_engineers", "analysts"},
        assumer_fetch_names={"data_engineers"},
    )

    de_group = next(g for g in result if g.display_name == "data_engineers")
    analysts_group = next(g for g in result if g.display_name == "analysts")

    # data_engineers had assumers fetched
    assert de_group.assumers is not None
    assert len(de_group.assumers) == 2
    identifiers = {p.identifier for p in de_group.assumers}
    assert "alice@co.com" in identifiers
    assert "data-admins" in identifiers

    # analysts was not in assumer_fetch, so assumers not fetched
    assert analysts_group.assumers is None


def test_workspace_helper_assumers_fetched_by_id() -> None:
    """Assumers are fetched when the group id is in assumer_fetch_ids."""
    client = _make_workspace_client(
        groups=[_make_group("data_engineers", "g-1")],
    )
    client.config.account_id = "acc-123"
    client.account_access_control_proxy.get_rule_set.return_value = RuleSetResponse(
        name="accounts/acc-123/groups/g-1/ruleSets/default",
        etag="e2",
        grant_rules=[
            GrantRule(
                role="roles/group.assumer", principals=["servicePrincipals/sp-uuid"]
            ),
        ],
    )

    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    result = helper.fetch_actual_groups(
        desired_names={"data_engineers"},
        assumer_fetch_ids={"g-1"},
    )

    group = next(g for g in result if g.display_name == "data_engineers")
    assert group.assumers is not None
    assert len(group.assumers) == 1
    assert "sp-uuid" in {p.identifier for p in group.assumers}


# ---------------------------------------------------------------------------
# get_group_rule_set
# ---------------------------------------------------------------------------


def test_workspace_helper_get_group_rule_set_builds_resource_name() -> None:
    """get_group_rule_set builds the correct ruleset resource name and calls
    account_access_control_proxy.get_rule_set."""
    client = _make_workspace_client()
    client.config.account_id = "acc-123"
    client.account_access_control_proxy.get_rule_set.return_value = RuleSetResponse(
        name="accounts/acc-123/groups/g-99/ruleSets/default",
        etag="e-test",
        grant_rules=[],
    )

    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    result = helper.get_group_rule_set("g-99")

    # Verify the resource name was built correctly
    call_kwargs = client.account_access_control_proxy.get_rule_set.call_args.kwargs
    assert call_kwargs["name"] == "accounts/acc-123/groups/g-99/ruleSets/default"
    assert call_kwargs["etag"] == ""
    assert result.etag == "e-test"


# ---------------------------------------------------------------------------
# update_group_rule_set
# ---------------------------------------------------------------------------


def test_workspace_helper_update_group_rule_set_calls_with_request() -> None:
    """update_group_rule_set builds the correct ruleset resource name and calls
    account_access_control_proxy.update_rule_set with a RuleSetUpdateRequest."""
    client = _make_workspace_client()
    client.config.account_id = "acc-456"
    client.account_access_control_proxy.update_rule_set.return_value = RuleSetResponse(
        name="accounts/acc-456/groups/g-42/ruleSets/default",
        etag="e-updated",
        grant_rules=[],
    )

    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    grant_rules = [
        GrantRule(role="roles/group.assumer", principals=["users/bob@co.com"]),
    ]
    result = helper.update_group_rule_set("g-42", "e-old", grant_rules)

    # Verify update_rule_set was called with the correct arguments
    call_kwargs = client.account_access_control_proxy.update_rule_set.call_args.kwargs
    assert call_kwargs["name"] == "accounts/acc-456/groups/g-42/ruleSets/default"
    request = call_kwargs["rule_set"]
    assert isinstance(request, RuleSetUpdateRequest)
    assert request.name == "accounts/acc-456/groups/g-42/ruleSets/default"
    assert request.etag == "e-old"
    assert len(request.grant_rules) == 1
    assert request.grant_rules[0].role == "roles/group.assumer"
    assert result.etag == "e-updated"


# ---------------------------------------------------------------------------
# get_group_id
# ---------------------------------------------------------------------------


def test_workspace_helper_get_group_id_returns_cached_id() -> None:
    """get_group_id returns the cached id for a known group display name."""
    client = _make_workspace_client(
        groups=[_make_group("data_engineers", "10")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    result = helper.get_group_id("data_engineers")

    assert result == "10"


def test_workspace_helper_get_group_id_returns_none_for_unknown_group() -> None:
    """get_group_id returns None for an unknown group display name."""
    client = _make_workspace_client(
        groups=[_make_group("data_engineers", "10")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    result = helper.get_group_id("unknown_group")

    assert result is None
