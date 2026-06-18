from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from uc_declarative_abac.helpers import WorkspaceHelper
from uc_declarative_abac.principals import GroupRename, Principal
from uc_declarative_abac.types import PrincipalType
from uc_declarative_abac.utils import PrincipalValidationError


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------


def _make_user(user_name: str, id: str) -> dict:
    return {"id": id, "userName": user_name}


def _make_group(
    display_name: str,
    id: str,
    external_id: str = "",
    members: list[dict] | None = None,
) -> dict:
    return {
        "id": id,
        "displayName": display_name,
        "externalId": external_id,
        "members": members or [],
    }


def _make_sp(display_name: str, application_id: str, id: str) -> dict:
    return {"id": id, "displayName": display_name, "applicationId": application_id}


def _make_member(value: str, type: str = "User", display: str = "") -> dict:
    return {"value": value, "type": type, "display": display}


def _make_workspace_client(
    users: list[dict] | None = None,
    groups: list[dict] | None = None,
    service_principals: list[dict] | None = None,
) -> MagicMock:
    """Build a MagicMock WorkspaceClient whose api_client.do serves SCIM responses.

    Emulates the real account SCIM proxy: the ``GET /Groups`` LIST returns only
    ``id`` + ``displayName`` (NOT members — the proxy doesn't return them inline),
    while ``GET /Groups/{id}`` returns the full group object (members, externalId).
    POST/PATCH mutations return a benign dict and are inspected via call_args_list.
    """
    client = MagicMock()
    groups = groups or []
    groups_by_id = {g["id"]: g for g in groups}

    def _do(method, path, **kwargs):
        if method in ("POST", "PATCH"):
            return {}
        # Per-group GET: /api/2.0/account/scim/v2/Groups/{id} → full group object.
        if "/Groups/" in path:
            group_id = path.rsplit("/", 1)[-1]
            return groups_by_id.get(group_id, {})
        if path.endswith("/Users"):
            resources = users or []
        elif path.endswith("/ServicePrincipals"):
            resources = service_principals or []
        elif path.endswith("/Groups"):
            # The LIST endpoint does not return members inline — emulate by
            # returning only id + displayName.
            resources = [
                {"id": g["id"], "displayName": g["displayName"]} for g in groups
            ]
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
    """fetch_principals issues the three list calls; fetch_actual_groups then issues
    one additional GET /Groups/{id} per managed (configured) group — membership is
    not available from the list response."""
    client = _make_workspace_client(
        users=[_make_user("alice@example.com", "u-1")],
        groups=[
            _make_group("data_engineers", "g-1"),
            _make_group("analysts", "g-2"),
        ],
        service_principals=[_make_sp("etl-sp", "abc-123", "sp-1")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    assert client.api_client.do.call_count == 3

    helper.fetch_actual_groups(desired_names={"data_engineers"})

    # +1 GET for the single configured group (analysts is not fetched).
    assert client.api_client.do.call_count == 4


def test_workspace_helper_actual_group_includes_existing_members() -> None:
    """Regression for the always-re-adds bug: an existing group's members are read
    from the per-group GET, so the actual Group carries the members it already has
    (the differ can then compute an empty additions set on a synced group)."""
    client = _make_workspace_client(
        users=[_make_user("liam.perritt@databricks.com", "u-1")],
        service_principals=[_make_sp("sp_uc_governor_test", "app-uuid", "sp-1")],
        groups=[
            _make_group(
                "uc_governor_test_team", "g-1",
                members=[_make_member("u-1", "User"), _make_member("sp-1", "ServicePrincipal")],
            ),
        ],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    result = helper.fetch_actual_groups(desired_names={"uc_governor_test_team"})

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
            _make_group("data_engineers", "g-1"),
            _make_group("analysts", "g-2"),
        ],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    result = helper.fetch_actual_groups()

    names = {group.display_name for group in result}
    assert names == {"data_engineers", "analysts"}


def test_workspace_helper_translates_user_member_to_username_identifier() -> None:
    """A group with a user member is translated from the SCIM `value` id to the
    user's userName as the member identifier."""
    client = _make_workspace_client(
        users=[_make_user("alice@example.com", "u-1")],
        groups=[
            _make_group(
                "data_engineers", "g-1", members=[_make_member("u-1", "User")],
            ),
        ],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    result = helper.fetch_actual_groups()

    group = next(g for g in result if g.display_name == "data_engineers")
    assert Principal(PrincipalType.UNKNOWN, identifier="alice@example.com") in group.members


def test_workspace_helper_translates_sp_member_to_application_id_identifier() -> None:
    """A group member matching a service principal is translated to the SP's
    applicationId as the member identifier."""
    client = _make_workspace_client(
        service_principals=[_make_sp("etl-sp", "abc-123-uuid", "sp-1")],
        groups=[
            _make_group(
                "automation", "g-1",
                members=[_make_member("sp-1", "ServicePrincipal")],
            ),
        ],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    result = helper.fetch_actual_groups()

    group = next(g for g in result if g.display_name == "automation")
    assert Principal(PrincipalType.UNKNOWN, identifier="abc-123-uuid") in group.members


def test_workspace_helper_populates_external_id_for_idp_managed_group() -> None:
    """external_id is populated for an IdP-managed group (non-empty externalId)
    and empty for a normal group."""
    client = _make_workspace_client(
        groups=[
            _make_group("idp_group", "g-1", external_id="ext-999"),
            _make_group("native_group", "g-2", external_id=""),
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
            _make_group("data_engineers", "g-1"),
            _make_group("analysts", "g-2"),
        ],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    result = helper.fetch_actual_groups(desired_names={"data_engineers"})

    names = {group.display_name for group in result}
    assert names == {"data_engineers"}


def test_workspace_helper_drops_untranslatable_members() -> None:
    """A member whose SCIM value matches no fetched principal is dropped from the
    resulting group's members."""
    client = _make_workspace_client(
        users=[_make_user("alice@example.com", "u-1")],
        groups=[
            _make_group(
                "data_engineers", "g-1",
                members=[
                    _make_member("u-1", "User"),
                    _make_member("u-ghost", "User"),
                ],
            ),
        ],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    result = helper.fetch_actual_groups()

    group = next(g for g in result if g.display_name == "data_engineers")
    identifiers = {member.identifier for member in group.members}
    assert identifiers == {"alice@example.com"}


# ---------------------------------------------------------------------------
# register_pending_groups
# ---------------------------------------------------------------------------


def test_workspace_helper_register_pending_groups_resolves_as_group() -> None:
    """A group registered as pending (to be created this run) resolves as a GROUP
    principal by both name and identifier, even though it wasn't in the fetch."""
    client = _make_workspace_client(users=[_make_user("alice@example.com", "u-1")])
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    helper.register_pending_groups({"new_team"})

    assert helper.resolve_by_name("new_team") == Principal(
        PrincipalType.GROUP, "new_team", "new_team",
    )
    assert helper.resolve_by_identifier("new_team") == Principal(
        PrincipalType.GROUP, "new_team", "new_team",
    )


# ---------------------------------------------------------------------------
# add_group_members
# ---------------------------------------------------------------------------


def test_workspace_helper_add_group_members_issues_patch() -> None:
    """add_group_members issues a PATCH whose path contains the target group's
    SCIM id and whose request references the member's SCIM id."""
    client = _make_workspace_client(
        users=[_make_user("alice@example.com", "u-1")],
        groups=[_make_group("data_engineers", "g-1")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    member = Principal(PrincipalType.USER, "alice@example.com", "alice@example.com")
    helper.add_group_members("data_engineers", [member])

    patch_calls = [
        call for call in client.api_client.do.call_args_list
        if call.args and call.args[0] == "PATCH"
    ]
    assert len(patch_calls) == 1
    call = patch_calls[0]
    path = call.args[1]
    assert "g-1" in path
    # The member's SCIM id should appear somewhere in the captured request body.
    assert "u-1" in repr(call.kwargs)


# ---------------------------------------------------------------------------
# remove_group_members
# ---------------------------------------------------------------------------


def test_workspace_helper_remove_group_members_issues_patch() -> None:
    """remove_group_members issues a PATCH whose path contains the target group's
    SCIM id and whose request references the member's SCIM id."""
    client = _make_workspace_client(
        users=[_make_user("alice@example.com", "u-1")],
        groups=[_make_group("data_engineers", "g-1")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    member = Principal(PrincipalType.USER, "alice@example.com", "alice@example.com")
    helper.remove_group_members("data_engineers", [member])

    patch_calls = [
        call for call in client.api_client.do.call_args_list
        if call.args and call.args[0] == "PATCH"
    ]
    assert len(patch_calls) == 1
    call = patch_calls[0]
    assert "g-1" in call.args[1]
    captured = repr(call.kwargs)
    # The member's SCIM id appears in the remove op and "remove" is the op.
    assert "u-1" in captured
    assert "remove" in captured


# ---------------------------------------------------------------------------
# create_group
# ---------------------------------------------------------------------------


def test_workspace_helper_create_group_issues_post() -> None:
    """create_group issues a POST to the Groups endpoint whose body references the
    new group's displayName and the member's SCIM id."""
    client = _make_workspace_client(
        users=[_make_user("alice@example.com", "u-1")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    member = Principal(PrincipalType.USER, "alice@example.com", "alice@example.com")
    helper.create_group("new_team", [member])

    post_calls = [
        call for call in client.api_client.do.call_args_list
        if call.args and call.args[0] == "POST"
    ]
    assert len(post_calls) == 1
    call = post_calls[0]
    path = call.args[1]
    assert "/api/2.0/account/scim/v2/Groups" in path
    captured = repr(call.kwargs)
    assert "new_team" in captured
    assert "u-1" in captured


# ---------------------------------------------------------------------------
# fetch_actual_groups — rename (locate by id)
# ---------------------------------------------------------------------------


def test_workspace_helper_fetches_renamed_group_by_id_when_name_not_in_desired_names() -> None:
    """A group whose SCIM id is in desired_ids is fetched under its CURRENT (actual)
    display name even when that name is not in desired_names — config wants the new
    name, but the account still returns the old name with the matching id."""
    client = _make_workspace_client(
        groups=[_make_group("old_name", "g-1")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    result = helper.fetch_actual_groups(
        desired_names={"new_name"}, desired_ids={"g-1"},
    )

    # Located by id and returned under its current (old) display name.
    names = {group.display_name for group in result}
    assert "old_name" in names


def test_workspace_helper_sets_id_on_actual_group_from_response() -> None:
    """The returned Group carries the SCIM id from the per-group GET response."""
    client = _make_workspace_client(
        groups=[_make_group("old_name", "g-1")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    result = helper.fetch_actual_groups(desired_ids={"g-1"})

    group = next(g for g in result if g.display_name == "old_name")
    assert group.id == "g-1"


# ---------------------------------------------------------------------------
# register_pending_renames
# ---------------------------------------------------------------------------


def test_workspace_helper_register_pending_renames_adds_new_name_and_removes_old() -> None:
    """After register_pending_renames, the NEW display name resolves as a GROUP
    principal and the OLD name no longer resolves."""
    client = _make_workspace_client(
        groups=[_make_group("old_name", "g-1")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    helper.register_pending_renames(
        [GroupRename(id="g-1", old_display_name="old_name", new_display_name="new_name")],
    )

    resolved = helper.resolve_by_name("new_name")
    assert resolved.principal_type == PrincipalType.GROUP

    with pytest.raises(PrincipalValidationError):
        helper.resolve_by_name("old_name")


def test_workspace_helper_register_pending_renames_remaps_group_id_to_new_name() -> None:
    """After the rename, a member add against the NEW name resolves the group's SCIM
    id — the PATCH targets the same id that previously belonged to the old name."""
    client = _make_workspace_client(
        users=[_make_user("alice@example.com", "u-1")],
        groups=[_make_group("old_name", "g-1")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    helper.register_pending_renames(
        [GroupRename(id="g-1", old_display_name="old_name", new_display_name="new_name")],
    )

    member = Principal(PrincipalType.USER, "alice@example.com", "alice@example.com")
    helper.add_group_members("new_name", [member])

    patch_calls = [
        call for call in client.api_client.do.call_args_list
        if call.args and call.args[0] == "PATCH"
    ]
    assert len(patch_calls) == 1
    assert "g-1" in patch_calls[0].args[1]


def test_workspace_helper_resolves_new_name_after_pending_rename() -> None:
    """resolve_by_name(new_name) returns a GROUP principal after a pending rename."""
    client = _make_workspace_client(
        groups=[_make_group("old_name", "g-1")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    helper.register_pending_renames(
        [GroupRename(id="g-1", old_display_name="old_name", new_display_name="new_name")],
    )

    assert helper.resolve_by_name("new_name").principal_type == PrincipalType.GROUP


def test_workspace_helper_rejects_old_name_after_pending_rename() -> None:
    """resolve_by_name(old_name) raises after a pending rename retires the old name."""
    client = _make_workspace_client(
        groups=[_make_group("old_name", "g-1")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    helper.register_pending_renames(
        [GroupRename(id="g-1", old_display_name="old_name", new_display_name="new_name")],
    )

    with pytest.raises(PrincipalValidationError):
        helper.resolve_by_name("old_name")


def test_workspace_helper_resolves_old_name_by_identifier_to_new_group_after_pending_rename() -> None:
    """resolve_by_identifier(old_name) returns the NEW group principal after a
    pending rename — deployed actual-state references to the old display name must
    map onto the renamed group rather than failing or showing a spurious diff."""
    client = _make_workspace_client(
        groups=[_make_group("old_name", "g-1")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    helper.register_pending_renames(
        [GroupRename(id="g-1", old_display_name="old_name", new_display_name="new_name")],
    )

    resolved = helper.resolve_by_identifier("old_name")
    assert resolved.principal_type == PrincipalType.GROUP
    assert resolved.identifier == "new_name"
    assert resolved.name == "new_name"


# ---------------------------------------------------------------------------
# rename_group
# ---------------------------------------------------------------------------


def test_workspace_helper_rename_group_issues_replace_displayname_patch() -> None:
    """rename_group issues a PATCH to /Groups/{scim_id} whose Operations contain a
    replace op on the displayName path with the new value."""
    client = _make_workspace_client(
        groups=[_make_group("old_name", "g-1")],
    )
    helper = WorkspaceHelper(client, manage_groups=True)
    helper.fetch_principals()

    helper.rename_group("g-1", "new")

    patch_calls = [
        call for call in client.api_client.do.call_args_list
        if call.args and call.args[0] == "PATCH"
    ]
    assert len(patch_calls) == 1
    call = patch_calls[0]
    assert call.args[1] == "/api/2.0/account/scim/v2/Groups/g-1"
    body = call.kwargs["body"]
    operations = body["Operations"]
    assert any(
        op.get("op") == "replace"
        and op.get("path") == "displayName"
        and op.get("value") == "new"
        for op in operations
    )
