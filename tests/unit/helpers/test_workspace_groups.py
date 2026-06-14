from __future__ import annotations

from unittest.mock import MagicMock

from uc_declarative_abac.helpers import WorkspaceHelper
from uc_declarative_abac.principals import Principal
from uc_declarative_abac.types import PrincipalType


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
