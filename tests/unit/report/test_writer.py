from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from databricks.sdk.service.sql import StatementState

from uc_declarative_abac.configs import ResourcesConfig
from uc_declarative_abac.governed_tags import GovernedTag
from uc_declarative_abac.helpers import UnityCatalogHelper
from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.principals import Group, Principal
from uc_declarative_abac.report import ReportState, build_pseudo_policies, write_report
from uc_declarative_abac.types import PolicyType, PrincipalType
from uc_declarative_abac.utils import OrchestratorError


def _uc_helper() -> tuple[UnityCatalogHelper, list[str]]:
    """A UnityCatalogHelper over a mock client that records every executed statement."""
    client = MagicMock()
    executed: list[str] = []

    def _capture(*args, **kwargs):
        executed.append(kwargs.get("statement", args[0] if args else ""))
        response = MagicMock()
        response.status.state = StatementState.SUCCEEDED
        return response

    client.statement_execution.execute_statement.side_effect = _capture
    return UnityCatalogHelper(client, "warehouse-id"), executed


def _ws_helper(
    memberships: dict | None = None, assumers: dict | None = None
) -> MagicMock:
    ws = MagicMock()
    ws.fetch_all_group_memberships.return_value = memberships or {}
    ws.fetch_all_group_assumers.return_value = assumers or {}
    return ws


def _resolver() -> MagicMock:
    """A resolver stub that returns each principal unchanged (identity resolution)."""
    r = MagicMock()
    r.resolve_principal.side_effect = lambda p: p
    return r


def _config(resources: dict | None = None) -> ResourcesConfig:
    return ResourcesConfig.model_validate(resources or {"catalogs": {}})


def _logger() -> ChangeLogger:
    return ChangeLogger(dry_run=False)


def test_write_report_creates_the_schema_first():
    """The report creates the target schema (if absent) before any table."""
    uc, executed = _uc_helper()
    state = ReportState(config=_config())
    write_report("rep.abac", state, uc, _ws_helper(), _resolver(), _logger())
    assert executed[0] == "CREATE SCHEMA IF NOT EXISTS rep.abac"


def test_write_report_creates_a_table_per_domain_with_groups_last():
    """Every domain table is created in the schema, and the groups table is written last."""
    uc, executed = _uc_helper()
    state = ReportState(
        config=_config(),
        governed_tags={GovernedTag(name="pii")},
        account_groups={Group(display_name="data_eng", id="10")},
    )
    write_report("rep.abac", state, uc, _ws_helper(), _resolver(), _logger())

    creates = [s for s in executed if s.startswith("CREATE OR REPLACE TABLE")]
    created = [s.split()[4] for s in creates]  # the fqn
    for name in (
        "rep.abac.governed_tags",
        "rep.abac.policies",
        "rep.abac.pseudo_policies",
        "rep.abac.privileges",
        "rep.abac.principals",
        "rep.abac.securables",
        "rep.abac.securable_tags",
        "rep.abac.domains",
        "rep.abac.groups",
    ):
        assert name in created
    # groups is created last.
    assert created[-1] == "rep.abac.groups"


def test_write_report_inserts_rows_for_nonempty_and_skips_insert_for_empty():
    """A non-empty domain gets an INSERT; an empty domain gets only the CREATE."""
    uc, executed = _uc_helper()
    state = ReportState(config=_config(), governed_tags={GovernedTag(name="pii")})
    write_report("rep.abac", state, uc, _ws_helper(), _resolver(), _logger())

    inserts = [s for s in executed if s.startswith("INSERT INTO")]
    assert any(s.startswith("INSERT INTO rep.abac.governed_tags") for s in inserts)
    # principals had no rows → no INSERT for it.
    assert not any(s.startswith("INSERT INTO rep.abac.principals") for s in inserts)


def test_write_report_is_resilient_to_a_failing_table_write():
    """One table's write failing does not prevent the others (including groups)."""
    uc, executed = _uc_helper()
    original = uc.execute_sql

    def _flaky(statement: str) -> None:
        if "rep.abac.principals" in statement:
            raise RuntimeError("boom")
        original(statement)

    uc.execute_sql = _flaky  # type: ignore[method-assign]
    state = ReportState(
        config=_config(),
        governed_tags={GovernedTag(name="pii")},
        account_groups={Group(display_name="g", id="1")},
    )
    # Must not raise.
    write_report("rep.abac", state, uc, _ws_helper(), _resolver(), _logger())

    created = [
        s.split()[4] for s in executed if s.startswith("CREATE OR REPLACE TABLE")
    ]
    assert "rep.abac.governed_tags" in created
    assert "rep.abac.groups" in created


def test_write_report_rejects_non_qualified_schema():
    """report_schema must be catalog.schema (exactly two parts)."""
    uc, _ = _uc_helper()
    state = ReportState(config=_config())
    with pytest.raises(OrchestratorError):
        write_report("just_catalog", state, uc, _ws_helper(), _resolver(), _logger())


def test_write_report_resolves_principals_before_writing():
    """Fetched group members (UNKNOWN, identifier-only) are resolved via the resolver, so
    the groups table carries the resolved type and name rather than UNKNOWN."""
    uc, executed = _uc_helper()
    ws = _ws_helper(
        {"1": frozenset({Principal(PrincipalType.UNKNOWN, identifier="alice@x")})}
    )
    resolver = MagicMock()
    resolver.resolve_principal.side_effect = lambda p: Principal(
        PrincipalType.USER, identifier=p.identifier, name=p.identifier
    )
    state = ReportState(
        config=_config(), account_groups={Group(display_name="g", id="1")}
    )

    write_report("rep.abac", state, uc, ws, resolver, _logger())

    groups_insert = next(
        s for s in executed if s.startswith("INSERT INTO rep.abac.groups")
    )
    assert "'USER'" in groups_insert
    assert "alice@x" in groups_insert
    assert "'UNKNOWN'" not in groups_insert


def test_build_pseudo_policies_carries_privileges_and_when_condition():
    """A grant policy config becomes a Policy with privileges + a tag when_condition."""
    config = _config(
        {
            "catalogs": {
                "cat": {
                    "name": "cat",
                    "policies": [
                        {
                            "name": "g1",
                            "type": "grant",
                            "privileges": ["select"],
                            "to": ["analysts"],
                            "has_tags": {"pii": "email"},
                        }
                    ],
                }
            }
        }
    )
    (policy,) = build_pseudo_policies(config)
    assert policy.policy_type == PolicyType.GRANT
    assert policy.name == "g1"
    assert policy.when_condition == "has_tag_value('pii', 'email')"
    assert [p.value for p in policy.privileges] == ["select"]
    assert policy.to_principals == (Principal(PrincipalType.UNKNOWN, name="analysts"),)
