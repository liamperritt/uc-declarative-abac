from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from uc_declarative_abac.configs import GrantPolicyConfig, ResourcesConfig
from uc_declarative_abac.domains import Domain
from uc_declarative_abac.governed_tags import GovernedTag
from uc_declarative_abac.helpers import UnityCatalogHelper, WorkspaceHelper
from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.policies import Policy, render_tag_condition
from uc_declarative_abac.principals import Group, Principal, PrincipalResolver
from uc_declarative_abac.privileges import SecurablePrivilege
from uc_declarative_abac.report import sql
from uc_declarative_abac.securables import (
    Function,
    Securable,
    SecurableAttributes,
    Table,
)
from uc_declarative_abac.tags import SecurableTag
from uc_declarative_abac.types import PolicyType, PrincipalType, SecurableType
from uc_declarative_abac.utils import (
    OrchestratorError,
    PrincipalValidationError,
    parallel_for_each,
)

_logger = logging.getLogger("uc_declarative_abac")

_PRINCIPAL_STRUCT = "STRUCT<principal_type: STRING, identifier: STRING, name: STRING>"
_PRINCIPAL_ARRAY = f"ARRAY<{_PRINCIPAL_STRUCT}>"


@dataclass
class ReportState:
    """The full deployed state a report run writes out, plus the inputs it needs.

    ``config`` is the resolved ResourcesConfig (used to derive the grant "pseudo"
    policies). ``cached_group_members`` / ``cached_group_assumers`` map a group's internal
    id to the members / assumers already fetched during the deploy (the group domain) —
    those groups are excluded from the report's own fetch and merged straight in.
    """

    config: ResourcesConfig
    governed_tags: set[GovernedTag] = field(default_factory=set)
    policies: set[Policy] = field(default_factory=set)
    privileges: set[SecurablePrivilege] = field(default_factory=set)
    principals: set[Principal] = field(default_factory=set)
    securables: set[Securable] = field(default_factory=set)
    attributes: set[SecurableAttributes] = field(default_factory=set)
    securable_tags: set[SecurableTag] = field(default_factory=set)
    domains: set[Domain] = field(default_factory=set)
    account_groups: set[Group] = field(default_factory=set)
    cached_group_members: dict[str, frozenset[Principal]] = field(default_factory=dict)
    cached_group_assumers: dict[str, frozenset[Principal]] = field(default_factory=dict)


# --- Row rendering ---------------------------------------------------------


def _row(*exprs: str) -> str:
    """Render one ``VALUES`` tuple from already-rendered column expressions."""
    return f"({', '.join(exprs)})"


def _resolve(resolver: PrincipalResolver, principal: Principal) -> Principal:
    """Best-effort resolve a principal for the report (fills in type + full name /
    identifier). Kept as-is when it can't be resolved — the report is non-fatal and the
    operator can't act on an unresolvable principal."""
    try:
        return resolver.resolve_principal(principal)
    except PrincipalValidationError:
        return principal


def _resolve_all(
    resolver: PrincipalResolver, principals: Iterable[Principal]
) -> list[Principal]:
    return [_resolve(resolver, p) for p in principals]


def _principal_struct(resolver: PrincipalResolver, principal: Principal | None) -> str:
    """Render a resolved principal struct (or NULL)."""
    if principal is None:
        return "NULL"
    return sql.principal_struct(_resolve(resolver, principal))


def _principal_array(
    resolver: PrincipalResolver, principals: Iterable[Principal]
) -> str:
    """Render an array of resolved principal structs."""
    return sql.principal_array(_resolve_all(resolver, principals))


def _owners_expr(
    resolver: PrincipalResolver, owners: frozenset[Principal] | None
) -> str:
    """Render an optional owner/assumer set (None = unmanaged) as a resolved principal
    array, or NULL."""
    return _principal_array(resolver, owners) if owners is not None else "NULL"


def _privileges_expr(privileges: tuple | None) -> str:
    """Render a Policy's optional privileges tuple as a string array, or NULL."""
    if privileges is None:
        return "NULL"
    return sql.str_array([p.value for p in privileges])


def _governed_tag_row(resolver: PrincipalResolver, tag: GovernedTag) -> str:
    return _row(
        sql.sql_literal(tag.name),
        sql.sql_literal(tag.description),
        sql.str_array(sorted(tag.allowed_values)),
        _principal_array(resolver, tag.assigners),
    )


def _policy_row(resolver: PrincipalResolver, policy: Policy) -> str:
    match_columns = sql.array(
        sql.named_struct(
            [("alias", sql.sql_literal(alias)), ("condition", sql.sql_literal(cond))]
        )
        for alias, cond in policy.match_columns
    )
    return _row(
        sql.sql_literal(policy.securable_type.value),
        sql.sql_literal(policy.securable_full_name),
        sql.sql_literal(policy.name),
        sql.sql_literal(policy.policy_type.value),
        sql.sql_literal(policy.function_name or None),
        _principal_array(resolver, policy.to_principals),
        _principal_array(resolver, policy.except_principals),
        sql.sql_literal(policy.when_condition),
        match_columns,
        sql.sql_literal(policy.on_column),
        sql.str_array(policy.using_columns),
        sql.sql_literal(policy.comment),
        sql.sql_literal(policy.for_securable_type.value),
        _privileges_expr(policy.privileges),
    )


def _privilege_row(resolver: PrincipalResolver, privilege: SecurablePrivilege) -> str:
    return _row(
        sql.sql_literal(privilege.securable_type.value),
        sql.sql_literal(privilege.securable_full_name),
        _principal_struct(resolver, privilege.principal),
        sql.sql_literal(privilege.privilege_type.value),
    )


def _principal_row(principal: Principal) -> str:
    return _row(
        sql.sql_literal(principal.principal_type.value),
        sql.sql_literal(principal.identifier),
        sql.sql_literal(principal.name),
    )


def _securable_row(
    resolver: PrincipalResolver,
    securable: Securable,
    attrs_by_key: dict[tuple[SecurableType, str], SecurableAttributes],
) -> str:
    attrs = attrs_by_key.get((securable.securable_type, securable.full_name))
    owner = _principal_struct(resolver, attrs.owner) if attrs else "NULL"
    rfa = (
        sql.str_array(sorted(attrs.rfa_destinations))
        if attrs and attrs.rfa_destinations is not None
        else "NULL"
    )
    definition = sql.sql_literal(getattr(securable, "definition", None))
    parameters = (
        sql.array(
            sql.named_struct(
                [("name", sql.sql_literal(name)), ("type", sql.sql_literal(ptype))]
            )
            for name, ptype in securable.parameters
        )
        if isinstance(securable, Function)
        else "NULL"
    )
    columns = (
        sql.array(
            sql.named_struct(
                [
                    ("full_name", sql.sql_literal(col.full_name)),
                    ("comment", sql.sql_literal(col.comment)),
                ]
            )
            for col in securable.columns
        )
        if isinstance(securable, Table)
        else "NULL"
    )
    return _row(
        sql.sql_literal(securable.securable_type.value),
        sql.sql_literal(securable.full_name),
        sql.sql_literal(securable.comment),
        owner,
        rfa,
        definition,
        parameters,
        columns,
    )


def _securable_tag_row(tag: SecurableTag) -> str:
    return _row(
        sql.sql_literal(tag.securable_type.value),
        sql.sql_literal(tag.securable_full_name),
        sql.sql_literal(tag.tag_name),
        sql.sql_literal(tag.tag_value),
    )


def _domain_row(resolver: PrincipalResolver, domain: Domain) -> str:
    icon = (
        sql.named_struct(
            [
                ("name", sql.sql_literal(domain.icon.name)),
                ("color", sql.sql_literal(domain.icon.color)),
            ]
        )
        if domain.icon is not None
        else "NULL"
    )
    return _row(
        sql.sql_literal(domain.tag_key),
        sql.sql_literal(domain.description),
        sql.sql_literal(domain.subtitle),
        sql.sql_bool(domain.draft),
        icon,
        _owners_expr(resolver, domain.business_owners),
        _owners_expr(resolver, domain.technical_owners),
        sql.sql_literal(domain.parent_tag_key),
    )


def _group_row(
    resolver: PrincipalResolver,
    group: Group,
    members: frozenset[Principal],
    assumers: frozenset[Principal],
) -> str:
    return _row(
        sql.sql_literal(group.display_name),
        sql.sql_literal(group.id),
        sql.sql_literal(group.external_id),
        _principal_array(resolver, members),
        _principal_array(resolver, assumers),
    )


# --- Table schemas ---------------------------------------------------------

_GOVERNED_TAGS_COLUMNS = [
    ("name", "STRING"),
    ("description", "STRING"),
    ("allowed_values", "ARRAY<STRING>"),
    ("assigners", _PRINCIPAL_ARRAY),
]
_POLICY_COLUMNS = [
    ("securable_type", "STRING"),
    ("securable_full_name", "STRING"),
    ("name", "STRING"),
    ("policy_type", "STRING"),
    ("function_name", "STRING"),
    ("to_principals", _PRINCIPAL_ARRAY),
    ("except_principals", _PRINCIPAL_ARRAY),
    ("when_condition", "STRING"),
    ("match_columns", "ARRAY<STRUCT<alias: STRING, condition: STRING>>"),
    ("on_column", "STRING"),
    ("using_columns", "ARRAY<STRING>"),
    ("comment", "STRING"),
    ("for_securable_type", "STRING"),
    ("privileges", "ARRAY<STRING>"),
]
_PRIVILEGE_COLUMNS = [
    ("securable_type", "STRING"),
    ("securable_full_name", "STRING"),
    ("principal", _PRINCIPAL_STRUCT),
    ("privilege_type", "STRING"),
]
_PRINCIPAL_COLUMNS = [
    ("principal_type", "STRING"),
    ("identifier", "STRING"),
    ("name", "STRING"),
]
_SECURABLE_COLUMNS = [
    ("securable_type", "STRING"),
    ("full_name", "STRING"),
    ("comment", "STRING"),
    ("owner", _PRINCIPAL_STRUCT),
    ("rfa_destinations", "ARRAY<STRING>"),
    ("definition", "STRING"),
    ("parameters", "ARRAY<STRUCT<name: STRING, type: STRING>>"),
    ("columns", "ARRAY<STRUCT<full_name: STRING, comment: STRING>>"),
]
_SECURABLE_TAG_COLUMNS = [
    ("securable_type", "STRING"),
    ("securable_full_name", "STRING"),
    ("tag_name", "STRING"),
    ("tag_value", "STRING"),
]
_DOMAIN_COLUMNS = [
    ("tag_key", "STRING"),
    ("description", "STRING"),
    ("subtitle", "STRING"),
    ("draft", "BOOLEAN"),
    ("icon", "STRUCT<name: STRING, color: STRING>"),
    ("business_owners", _PRINCIPAL_ARRAY),
    ("technical_owners", _PRINCIPAL_ARRAY),
    ("parent_tag_key", "STRING"),
]
_GROUP_COLUMNS = [
    ("display_name", "STRING"),
    ("id", "STRING"),
    ("external_id", "STRING"),
    ("members", _PRINCIPAL_ARRAY),
    ("assumers", _PRINCIPAL_ARRAY),
]


# --- Pseudo (grant) policy construction ------------------------------------


def _grant_to_policy(
    securable_type: SecurableType,
    securable_full_name: str,
    grant: GrantPolicyConfig,
) -> Policy:
    """Build a Policy that represents a grant ("pseudo") policy for the report.

    Grants are not a real UC policy object, so this reuses the Policy model: the tag
    predicate becomes a ``when_condition`` (rendered like a mask/filter policy), the
    config ``to`` display names become unresolved Principals, ``privileges`` is carried,
    and all function/column-level fields are left empty."""
    return Policy(
        securable_type=securable_type,
        securable_full_name=securable_full_name,
        name=grant.name,
        policy_type=PolicyType.GRANT,
        function_name="",
        to_principals=tuple(Principal(PrincipalType.UNKNOWN, name=n) for n in grant.to),
        except_principals=(),
        when_condition=render_tag_condition(grant.has_tags, grant.has_any_of_tags),
        match_columns=(),
        on_column=None,
        using_columns=(),
        comment=grant.comment,
        for_securable_type=grant.for_securable_type or securable_type,
        privileges=tuple(grant.privileges),
    )


def build_pseudo_policies(config: ResourcesConfig) -> set[Policy]:
    """Collect every declared grant policy as a Policy (see ``_grant_to_policy``).

    Mirrors the mask/filter compiler's traversal: catalog-, schema-, and table-level
    ``policies`` blocks, keeping only ``GrantPolicyConfig`` entries and tagging each with
    the securable type of the level it was declared on."""
    pseudo: set[Policy] = set()
    for catalog in config.catalogs.values():
        for p in catalog.policies or []:
            if isinstance(p, GrantPolicyConfig):
                pseudo.add(
                    _grant_to_policy(SecurableType.CATALOG, catalog.full_name, p)
                )
        for schema in catalog.schemas or []:
            for p in schema.policies or []:
                if isinstance(p, GrantPolicyConfig):
                    pseudo.add(
                        _grant_to_policy(SecurableType.SCHEMA, schema.full_name, p)
                    )
            for table in schema.tables or []:
                for p in table.policies or []:
                    if isinstance(p, GrantPolicyConfig):
                        pseudo.add(
                            _grant_to_policy(SecurableType.TABLE, table.full_name, p)
                        )
    return pseudo


# --- Writing ---------------------------------------------------------------


def _validate_report_schema(report_schema: str) -> None:
    parts = report_schema.split(".")
    if len(parts) != 2 or not all(parts):
        raise OrchestratorError(
            "--report-schema must be a fully-qualified catalog.schema name, got: "
            f"{report_schema!r}"
        )


def _run_statement(uc_helper: UnityCatalogHelper, statement: str, label: str) -> None:
    """Execute one report statement, re-raising any failure with context.

    Surfaces which statement failed (``label``), the underlying exception type, and a
    truncated snippet of the SQL — the raw SDK error is often just a generic server
    message (e.g. an HTTP 500), so without this the operator can't tell what broke."""
    try:
        uc_helper.execute_sql(statement)
    except Exception as exc:
        snippet = statement[:500] + ("…" if len(statement) > 500 else "")
        raise OrchestratorError(
            f"{label}: {type(exc).__name__}: {exc}\n    statement: {snippet}"
        ) from exc


def _write_table(
    uc_helper: UnityCatalogHelper,
    fqn: str,
    columns: list[tuple[str, str]],
    rows: list[str],
) -> int:
    """Create (or replace) one report table and populate it with batched INSERTs.

    Returns the row count. Raises (with the failing statement's context, see
    ``_run_statement``) on any SQL failure; the caller runs this under ``parallel_for_each``
    so a failure is captured and logged without aborting the other tables (a
    partially-populated table is acceptable — the next run replaces it)."""
    _run_statement(
        uc_helper, sql.create_or_replace_table(fqn, columns), f"{fqn} CREATE"
    )
    statements = sql.batch_inserts(fqn, [name for name, _ in columns], rows)
    for i, statement in enumerate(statements, 1):
        _run_statement(
            uc_helper, statement, f"{fqn} INSERT batch {i}/{len(statements)}"
        )
    _logger.info(
        "  report: wrote %d row(s) to %s in %d batch(es)",
        len(rows),
        fqn,
        len(statements),
    )
    return len(rows)


def write_report(
    report_schema: str,
    state: ReportState,
    uc_helper: UnityCatalogHelper,
    ws_helper: WorkspaceHelper,
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
    max_parallel: int = 8,
) -> None:
    """Write the full deployed state to per-domain Unity Catalog tables in ``report_schema``.

    Phase A writes the eight non-group tables and fetches every account group's direct
    membership concurrently; Phase B then writes the ``groups`` table last (merging the
    freshly fetched memberships with those already cached from the group domain). Table
    writes and the membership fetch are resilient — a failure is logged and skipped
    without failing the run (the deploy has already succeeded).

    Every principal written (group members, policy/grant ``to``/``except``, privilege
    grantee, owners, assigners) is resolved via ``resolver`` to its full type + name +
    identifier; an unresolvable principal is written as-is (see ``_resolve``)."""
    _validate_report_schema(report_schema)
    change_logger.log_section_header("Deployment Report")
    _logger.info("  Writing deployed state report to %s", report_schema)
    started = time.perf_counter()

    # Ensure the target schema exists before writing tables into it. Best-effort: a
    # failure here is logged (the table writes below would then fail and be logged too),
    # never raised — the report is non-fatal after a successful deploy.
    try:
        uc_helper.execute_sql(sql.create_schema_if_not_exists(report_schema))
    except Exception as exc:  # noqa: BLE001 - report write is non-fatal
        _logger.error("  report: creating schema %s failed: %s", report_schema, exc)

    attrs_by_key = {(a.securable_type, a.full_name): a for a in state.attributes}
    pseudo_policies = build_pseudo_policies(state.config)

    def _spec(name: str, columns: list[tuple[str, str]], rows: list[str]):
        return (f"{report_schema}.{name}", columns, rows)

    table_specs = [
        _spec(
            "governed_tags",
            _GOVERNED_TAGS_COLUMNS,
            [_governed_tag_row(resolver, x) for x in state.governed_tags],
        ),
        _spec(
            "policies",
            _POLICY_COLUMNS,
            [_policy_row(resolver, x) for x in state.policies],
        ),
        _spec(
            "pseudo_policies",
            _POLICY_COLUMNS,
            [_policy_row(resolver, x) for x in pseudo_policies],
        ),
        _spec(
            "privileges",
            _PRIVILEGE_COLUMNS,
            [_privilege_row(resolver, x) for x in state.privileges],
        ),
        _spec(
            "principals",
            _PRINCIPAL_COLUMNS,
            [_principal_row(x) for x in state.principals],
        ),
        _spec(
            "securables",
            _SECURABLE_COLUMNS,
            [_securable_row(resolver, x, attrs_by_key) for x in state.securables],
        ),
        _spec(
            "securable_tags",
            _SECURABLE_TAG_COLUMNS,
            [_securable_tag_row(x) for x in state.securable_tags],
        ),
        _spec(
            "domains",
            _DOMAIN_COLUMNS,
            [_domain_row(resolver, x) for x in state.domains],
        ),
    ]

    def _progress(kind: str) -> Callable[[int, int], None]:
        def _cb(done: int, total: int) -> None:
            if done == total or done % 500 == 0:
                _logger.info(
                    "  report: fetched %s for %d/%d group(s)", kind, done, total
                )

        return _cb

    def _fetch_members() -> dict[str, frozenset[Principal]]:
        return ws_helper.fetch_all_group_memberships(
            exclude_ids=set(state.cached_group_members),
            on_progress=_progress("members"),
        )

    def _fetch_assumers() -> dict[str, frozenset[Principal]]:
        return ws_helper.fetch_all_group_assumers(
            exclude_ids=set(state.cached_group_assumers),
            on_progress=_progress("assumers"),
        )

    # Phase A: the eight table writes + the membership and assumer fetches, concurrently.
    phase_a: list[tuple[str, object]] = [
        (spec[0], (lambda s=spec: _write_table(uc_helper, *s))) for spec in table_specs
    ]
    phase_a.append(("group-members-fetch", _fetch_members))
    phase_a.append(("group-assumers-fetch", _fetch_assumers))

    def _on_complete(item, result, error) -> None:
        if error is not None:
            _logger.error("  report: %s failed: %s", item[0], error)

    results = parallel_for_each(
        phase_a,
        lambda item: item[1](),
        max_workers=max_parallel,
        on_complete=_on_complete,
    )

    fetched_members: dict[str, frozenset[Principal]] = {}
    fetched_assumers: dict[str, frozenset[Principal]] = {}
    failures = 0
    for item, result, error in results:
        if error is not None:
            failures += 1
        elif item[0] == "group-members-fetch":
            fetched_members = result or {}
        elif item[0] == "group-assumers-fetch":
            fetched_assumers = result or {}

    # Phase B: groups table, written last with merged memberships and assumers.
    members_by_id = {**state.cached_group_members, **fetched_members}
    assumers_by_id = {**state.cached_group_assumers, **fetched_assumers}
    group_rows = [
        _group_row(
            resolver,
            g,
            members_by_id.get(g.id, frozenset()),
            assumers_by_id.get(g.id, frozenset()),
        )
        for g in state.account_groups
    ]
    try:
        _write_table(uc_helper, f"{report_schema}.groups", _GROUP_COLUMNS, group_rows)
    except Exception as exc:  # noqa: BLE001 - report write is non-fatal
        failures += 1
        _logger.error("  report: %s.groups failed: %s", report_schema, exc)

    elapsed = time.perf_counter() - started
    _logger.info(
        "  Report complete: 9 table(s), %d failure(s) in %.1fs",
        failures,
        elapsed,
    )
