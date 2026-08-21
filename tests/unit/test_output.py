from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from uc_declarative_abac.governed_tags import GovernedTag, GovernedTagDiff
from uc_declarative_abac.output import render_deploy_json, render_validate_json
from uc_declarative_abac.orchestrator import OrchestratorDiffsResult
from uc_declarative_abac.policies import Policy, PolicyDiff
from uc_declarative_abac.principals import (
    Group,
    GroupDiff,
    GroupRename,
    Principal,
)
from uc_declarative_abac.privileges import (
    PrivilegeDiff,
    SecurablePrivilege,
)
from uc_declarative_abac.securables import (
    AttributeUpdate,
    Securable,
    SecurableDiff,
)
from uc_declarative_abac.tags import SecurableTag, TagDiff
from uc_declarative_abac.types import (
    PolicyType,
    PrincipalType,
    PrivilegeType,
    SecurableType,
)


def test_json_output_validate_report_conforms_to_validate_report_schema():
    repository_root = Path(__file__).parents[2]
    schema = json.loads(
        (repository_root / "schemas" / "validate-report-v1.schema.json").read_text()
    )
    report = json.loads(render_validate_json(Path("configs/example")))

    errors = list(Draft202012Validator(schema).iter_errors(report))

    assert errors == []


def test_json_output_renders_deterministic_versioned_dry_run_report():
    config_dir = Path("configs/example")
    result = OrchestratorDiffsResult(
        group_diff=GroupDiff(),
        securable_diff=SecurableDiff(),
        governed_tag_diff=GovernedTagDiff(),
        tag_diff=TagDiff(
            to_add={
                SecurableTag(
                    securable_type=SecurableType.TABLE,
                    securable_full_name="analytics.sales.orders",
                    tag_name="sensitivity",
                    tag_value="confidential",
                ),
                SecurableTag(
                    securable_type=SecurableType.CATALOG,
                    securable_full_name="analytics",
                    tag_name="environment",
                    tag_value="production",
                ),
                SecurableTag(
                    securable_type=SecurableType.TABLE,
                    securable_full_name="analytics.sales.orders",
                    tag_name="domain",
                    tag_value="sales",
                ),
            }
        ),
        policy_diff=PolicyDiff(),
        privilege_diff=PrivilegeDiff(),
    )

    report = json.loads(render_deploy_json(result, config_dir=config_dir, dry_run=True))

    assert report["format_version"] == "1"
    assert report["mode"] == "deploy"
    assert report["dry_run"] is True
    assert report["config_dir"] == str(config_dir)
    assert [
        (resource["type"], resource["full_name"]) for resource in report["resources"]
    ] == [
        ("CATALOG", "analytics"),
        ("TABLE", "analytics.sales.orders"),
    ]
    assert report["resources"][1]["changes"] == [
        {
            "domain": "tags",
            "operation": "add",
            "payload": {"tag_name": "domain", "tag_value": "sales"},
            "status": "planned",
        },
        {
            "domain": "tags",
            "operation": "add",
            "payload": {
                "tag_name": "sensitivity",
                "tag_value": "confidential",
            },
            "status": "planned",
        },
    ]
    assert report["summary"]["total"] == 3
    assert report["summary"]["add"] == 3


def test_json_output_renders_representative_changes_for_every_domain():
    analyst = Principal(
        principal_type=PrincipalType.USER,
        name="analyst@example.com",
        identifier="analyst@example.com",
    )
    data_engineers = Principal(
        principal_type=PrincipalType.GROUP,
        name="data_engineers",
        identifier="data_engineers",
    )
    table_name = "analytics.sales.orders"
    tag = SecurableTag(
        securable_type=SecurableType.TABLE,
        securable_full_name=table_name,
        tag_name="sensitivity",
        tag_value="restricted",
    )
    policy = Policy(
        securable_type=SecurableType.TABLE,
        securable_full_name=table_name,
        name="mask_customer_email",
        policy_type=PolicyType.MASK,
        function_name="analytics.security.mask_email",
        to_principals=(data_engineers,),
        except_principals=(),
        when_condition=None,
        match_columns=(("sensitivity", "restricted"),),
        on_column="email",
        using_columns=(),
    )
    result = OrchestratorDiffsResult(
        group_diff=GroupDiff(groups_to_create={"data_engineers": frozenset({analyst})}),
        securable_diff=SecurableDiff(
            securables_to_create=[
                Securable(SecurableType.CATALOG, "analytics", comment="Analytics")
            ],
            attributes_to_update=[
                AttributeUpdate(
                    securable_type=SecurableType.SCHEMA,
                    full_name="analytics.sales",
                    attribute="comment",
                    old_value=frozenset({"Old comment"}),
                    new_value=frozenset({"Sales data"}),
                )
            ],
        ),
        governed_tag_diff=GovernedTagDiff(
            to_create={
                GovernedTag(
                    name="sensitivity",
                    description="Data sensitivity",
                    allowed_values=frozenset({"restricted"}),
                    assigners=frozenset({data_engineers}),
                )
            }
        ),
        tag_diff=TagDiff(
            to_update={tag},
            old_values={(SecurableType.TABLE, table_name, "sensitivity"): "internal"},
        ),
        policy_diff=PolicyDiff(to_create={policy}),
        privilege_diff=PrivilegeDiff(
            to_grant={
                SecurablePrivilege(
                    securable_type=SecurableType.TABLE,
                    securable_full_name=table_name,
                    principal=data_engineers,
                    privilege_type=PrivilegeType.SELECT,
                )
            }
        ),
    )

    report = json.loads(
        render_deploy_json(result, config_dir=Path("configs/example"), dry_run=True)
    )
    resources = {
        (resource["type"], resource["full_name"]): resource["changes"]
        for resource in report["resources"]
    }

    assert resources[("GROUP", "data_engineers")] == [
        {
            "domain": "groups",
            "operation": "add",
            "payload": {"members": ["analyst@example.com"]},
            "status": "planned",
        }
    ]
    assert resources[("CATALOG", "analytics")] == [
        {
            "domain": "securables",
            "operation": "add",
            "payload": {"comment": "Analytics"},
            "status": "planned",
        }
    ]
    assert resources[("SCHEMA", "analytics.sales")] == [
        {
            "domain": "securables",
            "operation": "change",
            "payload": {
                "attribute": "comment",
                "old_value": ["Old comment"],
                "new_value": ["Sales data"],
            },
            "status": "planned",
        }
    ]
    assert {
        (change["domain"], change["operation"])
        for change in resources[("TABLE", table_name)]
    } == {("tags", "change"), ("policies", "add"), ("privileges", "add")}
    tag_change = next(
        change
        for change in resources[("TABLE", table_name)]
        if change["domain"] == "tags"
    )
    assert tag_change["payload"] == {
        "tag_name": "sensitivity",
        "old_value": "internal",
        "tag_value": "restricted",
    }
    assert resources[("GOVERNED_TAG", "sensitivity")] == [
        {
            "domain": "governed_tags",
            "operation": "add",
            "payload": {
                "description": "Data sensitivity",
                "allowed_values": ["restricted"],
                "assigners": ["data_engineers"],
            },
            "status": "planned",
        }
    ]
    assert report["summary"] == {
        "total": 7,
        "add": 5,
        "change": 2,
        "remove": 0,
        "by_domain": {
            "groups": {"add": 1, "change": 0, "remove": 0},
            "securables": {"add": 1, "change": 1, "remove": 0},
            "governed_tags": {"add": 1, "change": 0, "remove": 0},
            "tags": {"add": 0, "change": 1, "remove": 0},
            "policies": {"add": 1, "change": 0, "remove": 0},
            "privileges": {"add": 1, "change": 0, "remove": 0},
        },
    }


def test_json_output_renders_change_and_remove_operations_for_every_domain():
    member = Principal(
        principal_type=PrincipalType.USER,
        name="member@example.com",
        identifier="member@example.com",
    )
    data_engineers = Principal(
        principal_type=PrincipalType.GROUP,
        name="data_engineers",
        identifier="data_engineers",
    )
    table_name = "analytics.sales.orders"
    old_policy = Policy(
        securable_type=SecurableType.TABLE,
        securable_full_name=table_name,
        name="mask_customer_email",
        policy_type=PolicyType.MASK,
        function_name="analytics.security.old_mask_email",
        to_principals=(data_engineers,),
        except_principals=(),
        when_condition=None,
        match_columns=(("sensitivity", "restricted"),),
        on_column="email",
        using_columns=(),
    )
    replacement_policy = Policy(
        securable_type=SecurableType.TABLE,
        securable_full_name=table_name,
        name="mask_customer_email",
        policy_type=PolicyType.MASK,
        function_name="analytics.security.mask_email",
        to_principals=(data_engineers,),
        except_principals=(),
        when_condition=None,
        match_columns=(("sensitivity", "restricted"),),
        on_column="email",
        using_columns=(),
    )
    deleted_policy = Policy(
        securable_type=SecurableType.TABLE,
        securable_full_name=table_name,
        name="obsolete_filter",
        policy_type=PolicyType.FILTER,
        function_name="analytics.security.filter_rows",
        to_principals=(data_engineers,),
        except_principals=(),
        when_condition=None,
        match_columns=(("domain", "sales"),),
        on_column=None,
        using_columns=(),
    )
    updated_governed_tag = GovernedTag(
        name="sensitivity",
        description="Updated description",
        allowed_values=frozenset({"restricted"}),
        assigners=frozenset({data_engineers}),
    )
    old_governed_tag = GovernedTag(
        name="sensitivity",
        description="Old description",
        allowed_values=frozenset({"internal"}),
        assigners=frozenset(),
    )
    deleted_governed_tag = GovernedTag(name="obsolete_tag")
    result = OrchestratorDiffsResult(
        group_diff=GroupDiff(
            members_to_add={"data_engineers": frozenset({member})},
            members_to_remove={"former_engineers": frozenset({member})},
            groups_to_rename=[
                GroupRename(
                    id="group-1",
                    old_display_name="engineering",
                    new_display_name="data_engineering",
                )
            ],
            groups_to_delete={Group(display_name="obsolete_group", id="group-2")},
        ),
        securable_diff=SecurableDiff(
            securables_to_replace=[
                Securable(
                    SecurableType.FUNCTION,
                    "analytics.security.mask_email",
                    comment="Replacement function",
                )
            ],
            old_securables={
                "analytics.security.mask_email": Securable(
                    SecurableType.FUNCTION,
                    "analytics.security.mask_email",
                    comment="Old function",
                )
            },
        ),
        governed_tag_diff=GovernedTagDiff(
            to_update={updated_governed_tag},
            to_delete={deleted_governed_tag},
            old_values={"sensitivity": old_governed_tag},
        ),
        tag_diff=TagDiff(
            to_remove={
                SecurableTag(
                    securable_type=SecurableType.TABLE,
                    securable_full_name=table_name,
                    tag_name="obsolete",
                    tag_value="true",
                )
            }
        ),
        policy_diff=PolicyDiff(
            to_replace={replacement_policy},
            to_delete={deleted_policy},
            old_policies={
                (SecurableType.TABLE, table_name, old_policy.name): old_policy
            },
        ),
        privilege_diff=PrivilegeDiff(
            to_revoke={
                SecurablePrivilege(
                    securable_type=SecurableType.TABLE,
                    securable_full_name=table_name,
                    principal=data_engineers,
                    privilege_type=PrivilegeType.MODIFY,
                )
            }
        ),
    )

    report = json.loads(
        render_deploy_json(result, config_dir=Path("configs/example"), dry_run=True)
    )
    resources = {
        (resource["type"], resource["full_name"]): resource["changes"]
        for resource in report["resources"]
    }

    assert {
        (change["domain"], change["operation"])
        for changes in resources.values()
        for change in changes
    } >= {
        ("groups", "add"),
        ("groups", "change"),
        ("groups", "remove"),
        ("securables", "change"),
        ("governed_tags", "change"),
        ("governed_tags", "remove"),
        ("tags", "remove"),
        ("policies", "change"),
        ("policies", "remove"),
        ("privileges", "remove"),
    }
    assert all(
        change["status"] == "planned"
        for changes in resources.values()
        for change in changes
    )
    assert isinstance(report["warnings"], list)
    assert isinstance(report["errors"], list)
