from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from databricks.sdk import WorkspaceClient

from uc_declarative_abac.configs import (
    ResourcesConfig,
    consolidate_resources,
    discover_yaml_files,
    load_raw_configs,
    resolve_refs,
)
from uc_declarative_abac.governed_tags import (
    GovernedTagDiff,
    compile_desired_governed_tags,
    compute_governed_tag_diff,
    execute_governed_tag_diff,
)
from uc_declarative_abac.helpers import (
    UnityCatalogHelper,
    WorkspaceHelper,
)
from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.policies import (
    PolicyDiff,
    compile_desired_policies,
    compute_policy_diff,
    execute_policy_diff,
)
from uc_declarative_abac.principals import (
    GroupDiff,
    PrincipalResolver,
    compile_desired_groups,
    compute_group_diff,
    execute_group_diff,
)
from uc_declarative_abac.privileges import (
    PrivilegeDiff,
    compile_desired_privileges,
    compute_privilege_diff,
    execute_privilege_diff,
)
from uc_declarative_abac.securables import (
    SecurableAttributes,
    SecurableDiff,
    compile_desired_attributes,
    compile_desired_securables,
    compute_securable_diff,
    execute_securable_diff,
)
from uc_declarative_abac.tags import (
    TagDiff,
    compile_desired_tags,
    compute_tag_diff,
    execute_tag_diff,
    filter_retained_removals,
)
from uc_declarative_abac.types import SecurableType
from uc_declarative_abac.utils import (
    ExecutionBatchError,
    OrchestratorError,
    Scope,
    parse_flat_scope,
    parse_hierarchical_scope,
    parse_namespace_filter,
    scope_from_namespace_tokens,
    run_date_for_timezone,
)

_logger = logging.getLogger("uc_declarative_abac")


@dataclass(frozen=True)
class OrchestratorDiffsResult:
    """Computed diffs from one ``orchestrator.run()`` invocation, one per domain.

    Ordered as the domains are orchestrated — group management runs first.
    """

    group_diff: GroupDiff
    securable_diff: SecurableDiff
    governed_tag_diff: GovernedTagDiff
    tag_diff: TagDiff
    policy_diff: PolicyDiff
    privilege_diff: PrivilegeDiff


def _filter_taggable_attributes(
    attrs: set[SecurableAttributes],
    scope: Scope,
) -> set[SecurableAttributes]:
    """Drop non-function attributes whose namespace isn't in scope.

    FUNCTION attributes always flow through (functions are engine-managed
    independently of the taggable-management gate). When ``scope`` is empty
    (inert), this collapses to "function attributes only" — which is the
    behaviour when taggable management is off.
    """
    return {
        a
        for a in attrs
        if a.securable_type == SecurableType.FUNCTION
        or scope.matches(a.full_name)
    }


def _collect_configured_namespaces(config: ResourcesConfig) -> set[str]:
    """Collect every namespace token a filter flag may reference.

    That is each configured catalog name plus every configured
    ``catalog.schema`` full name — the valid tokens ``parse_namespace_filter``
    validates entries against.
    """
    namespaces: set[str] = set()
    for catalog in config.catalogs.values():
        namespaces.add(catalog.full_name)
        for schema in catalog.schemas or []:
            namespaces.add(schema.full_name)
    return namespaces


def _collect_configured_full_names(config: ResourcesConfig) -> set[str]:
    """Every configured securable full name at every level.

    Unlike ``_collect_configured_namespaces`` (catalog/schema only, kept narrow so
    the legacy ``parse_namespace_filter`` validation is unchanged), this reaches
    tables, columns, volumes, and functions — the universe a new-style
    hierarchical scope is checked against for zero-match warnings.
    """
    names: set[str] = set()
    for catalog in config.catalogs.values():
        names.add(catalog.full_name)
        for schema in catalog.schemas or []:
            names.add(schema.full_name)
            for table in schema.tables or []:
                names.add(table.full_name)
                for column in table.columns or []:
                    names.add(column.full_name)
            for volume in schema.volumes or []:
                names.add(volume.full_name)
            for function in schema.functions or []:
                names.add(function.full_name)
    return names


def _build_hierarchical_scope(
    new_spec: str | None,
    *,
    legacy_enabled: bool,
    legacy_namespaces: str,
    configured_namespaces: set[str],
) -> Scope:
    """Resolve one securable-domain feature to a ``Scope``.

    A new-style spec (non-``None``) wins and is parsed leniently. Otherwise the
    legacy enable + ``*_for_namespaces`` pair is honoured: when enabled, the
    namespace string is validated strictly via ``parse_namespace_filter`` and
    wrapped as a hierarchical scope byte-equivalent to the old
    ``in_namespace_scope``; when disabled, an empty (inert) scope.
    """
    if new_spec is not None:
        return parse_hierarchical_scope(new_spec)
    if legacy_enabled:
        tokens = parse_namespace_filter(legacy_namespaces, configured_namespaces)
        return scope_from_namespace_tokens(tokens)
    return Scope()


def _build_flat_scope(new_spec: str | None, *, legacy_enabled: bool) -> Scope:
    """Resolve one flat-domain feature (groups, governed tags) to a ``Scope``.

    A new-style spec wins; otherwise the legacy enable bool maps to match-all
    when set, or an empty (inert) scope when unset.
    """
    if new_spec is not None:
        return parse_flat_scope(new_spec)
    return parse_flat_scope("*") if legacy_enabled else Scope()


def _warn_unmatched_scopes(
    named_scopes: list[tuple[str, str | None, Scope]],
    universe: set[str],
) -> None:
    """Warn (never fail) about new-style scope entries that match nothing.

    Only new-style specs (``new_spec is not None``) are checked — legacy flags
    retain their own strict validation. Each unmatched entry is a likely typo.
    """
    for flag, new_spec, scope in named_scopes:
        if new_spec is None:
            continue
        unmatched = scope.unmatched_entries(universe)
        if unmatched:
            _logger.warning(
                "%s: scope entr%s %s matched no configured resource — "
                "possible typo (this feature will govern nothing for %s).",
                flag,
                "y" if len(unmatched) == 1 else "ies",
                ", ".join(repr(u) for u in unmatched),
                "it" if len(unmatched) == 1 else "them",
            )


def load_config(
    config_dir: Path,
    ref_override_strategy: Literal["merge", "replace"] = "merge",
) -> ResourcesConfig:
    """Discover, resolve, and validate YAML configs without contacting Databricks."""
    paths = discover_yaml_files(config_dir)
    raw_defs, raw_resources = load_raw_configs(paths)
    resolved = resolve_refs(
        raw_defs, raw_resources, override_strategy=ref_override_strategy
    )
    consolidated = consolidate_resources(resolved)
    return ResourcesConfig.model_validate(consolidated)


def run(
    config_dir: Path,
    workspace_client: WorkspaceClient,
    warehouse_id: str,
    system_catalog: str = "system",
    timezone: str = "UTC",
    dry_run: bool = False,
    use_workspace_scim: bool = False,
    skip_users_fetch: bool = False,
    enable_tag_management: bool = False,
    enable_taggable_management: bool = False,
    enable_taggable_creation: bool = False,
    enable_privilege_management: bool = False,
    enable_governed_tag_deletion: bool = False,
    enable_policy_deletion: bool = False,
    enable_group_creation: bool = False,
    enable_group_management: bool = False,
    enable_group_deletion: bool = False,
    ignore_unresolvable_principals: str = "",
    manage_tags_for_namespaces: str = "*",
    manage_privileges_for_namespaces: str = "*",
    manage_taggables_for_namespaces: str = "*",
    create_taggables_for_namespaces: str = "*",
    delete_policies_for_namespaces: str = "*",
    tag_management_scopes: str | None = None,
    privilege_management_scopes: str | None = None,
    taggable_management_scopes: str | None = None,
    taggable_creation_scopes: str | None = None,
    policy_deletion_scopes: str | None = None,
    group_creation_scopes: str | None = None,
    group_management_scopes: str | None = None,
    group_deletion_scopes: str | None = None,
    governed_tag_deletion_scopes: str | None = None,
    retain_tag_prefixes: str = "class.",
    force: bool = False,
    ref_override_strategy: Literal["merge", "replace"] = "merge",
    max_parallel_changes: int = 8,
) -> OrchestratorDiffsResult:
    """Run the full governance pipeline: discover, resolve, compile, diff, apply.

    Returns the computed diffs for every domain in execution order.
    In dry-run mode, diffs are computed but no SQL is executed.

    **Feature gating.** Each mutating feature resolves to a single ``Scope`` (see
    ``uc_declarative_abac.utils.Scope``) via ``_build_hierarchical_scope`` /
    ``_build_flat_scope``. A new-style ``*_scopes`` argument (non-``None``) wins
    and is parsed leniently — empty ⇒ disabled, ``"*"`` ⇒ all, otherwise a
    comma-separated pattern list (securable domains use dotted prefixes with
    downward inheritance; flat domains match names/prefixes). Otherwise the
    deprecated ``enable_*`` + ``*_for_namespaces`` pair is honoured with identical
    behaviour (strict ``parse_namespace_filter`` validation preserved). Effective
    enablement is ``scope.is_active()``: when a scope is empty the corresponding
    domain is skipped in both dry-run and real-run (no fetch, no diff, no log, no
    execute). An active ``privilege_management`` scope with an inactive
    ``tag_management`` scope makes the privileges compiler match its grant
    policies against the on-disk (``actual``) tag state instead of the config's
    desired tags. A new-style scope entry that matches no configured securable
    logs a warning (likely typo) but never fails the run.

    The deprecated ``*_for_namespaces`` strings scope each enabled domain to a
    subset of the configured namespaces. Each comma-separated entry is either a
    bare catalog name (covers everything under that catalog) or a qualified
    ``catalog.schema`` name (covers that schema and its children). ``"*"`` (the
    default) means "all configured catalogs". A filter has no effect unless its
    paired ``enable_*`` flag is set. Unknown catalog/schema names raise
    ``ValueError`` early. Function securables are never namespace-filtered —
    they're engine-managed and flow through all scopes.

    ``retain_tag_prefixes`` is a comma-separated list of tag-key prefixes the
    engine must never remove from securables, even when those tags are absent
    from config (it may still add/update them). Defaults to ``"class."`` to
    protect UC auto data classification tags. An empty string allows the engine
    to remove any unconfigured tag.

    Group management is the first domain orchestrated (before governed tags),
    gated by two orthogonal flags. ``enable_group_creation`` creates configured
    groups that don't yet exist, with their configured members (atomically; the
    engine auto-receives the MANAGER role on groups it creates).
    ``enable_group_management`` reconciles the membership of *existing* groups —
    adding missing members and removing members absent from config (an empty
    members list removes all); it requires the MANAGER role on each managed group.
    A configured group that doesn't exist is a fatal error under management unless
    creation is also enabled; existing externally-managed (IdP-provisioned) groups
    are a fatal error. With neither flag the group domain is inert. Both flags
    require the account SCIM proxy, so combining them with
    ``use_workspace_scim=True`` raises immediately.

    ``ignore_unresolvable_principals`` is a comma-separated list of actual-state
    (UC-side) principal identifiers — usernames, service-principal
    application_ids, or group display names — whose resolution-failure warning is
    suppressed across the privileges, securables (owner), and governed-tags
    (assigners) domains. Primarily for Databricks-managed
    system service principals that appear in system tables but aren't resolvable
    via SCIM. Empty by default.
    """
    # The run date used to evaluate every expiry_date (groups and grant policies)
    # is computed once, in the configured timezone, so both compilers agree even
    # across a midnight boundary.
    run_date = run_date_for_timezone(timezone)

    # 1. Discover + load + resolve YAML
    config = load_config(config_dir, ref_override_strategy)
    catalog_names = [c.full_name for c in config.catalogs.values()]
    configured_namespaces = _collect_configured_namespaces(config)
    configured_full_names = _collect_configured_full_names(config)

    # Resolve every feature to a single Scope (empty ⇒ inert). A new-style
    # --*-scopes spec wins; otherwise the deprecated enable_* + *_for_namespaces
    # pair is honoured with identical behaviour. Effective enablement then derives
    # from scope activeness, so the rest of the pipeline is scope-driven.
    tag_scope = _build_hierarchical_scope(
        tag_management_scopes,
        legacy_enabled=enable_tag_management,
        legacy_namespaces=manage_tags_for_namespaces,
        configured_namespaces=configured_namespaces,
    )
    privilege_scope = _build_hierarchical_scope(
        privilege_management_scopes,
        legacy_enabled=enable_privilege_management,
        legacy_namespaces=manage_privileges_for_namespaces,
        configured_namespaces=configured_namespaces,
    )
    taggable_management_scope = _build_hierarchical_scope(
        taggable_management_scopes,
        legacy_enabled=enable_taggable_management,
        legacy_namespaces=manage_taggables_for_namespaces,
        configured_namespaces=configured_namespaces,
    )
    taggable_creation_scope = _build_hierarchical_scope(
        taggable_creation_scopes,
        legacy_enabled=enable_taggable_creation,
        legacy_namespaces=create_taggables_for_namespaces,
        configured_namespaces=configured_namespaces,
    )
    policy_delete_scope = _build_hierarchical_scope(
        policy_deletion_scopes,
        legacy_enabled=enable_policy_deletion,
        legacy_namespaces=delete_policies_for_namespaces,
        configured_namespaces=configured_namespaces,
    )
    group_creation_scope = _build_flat_scope(
        group_creation_scopes, legacy_enabled=enable_group_creation
    )
    group_management_scope = _build_flat_scope(
        group_management_scopes, legacy_enabled=enable_group_management
    )
    group_deletion_scope = _build_flat_scope(
        group_deletion_scopes, legacy_enabled=enable_group_deletion
    )
    governed_tag_deletion_scope = _build_flat_scope(
        governed_tag_deletion_scopes, legacy_enabled=enable_governed_tag_deletion
    )

    # Effective enablement: a feature is on iff its scope has any entry.
    enable_tag_management = tag_scope.is_active()
    enable_privilege_management = privilege_scope.is_active()
    enable_taggable_management = taggable_management_scope.is_active()
    enable_taggable_creation = taggable_creation_scope.is_active()
    enable_policy_deletion = policy_delete_scope.is_active()
    enable_group_creation = group_creation_scope.is_active()
    enable_group_management = group_management_scope.is_active()
    enable_group_deletion = group_deletion_scope.is_active()
    enable_governed_tag_deletion = governed_tag_deletion_scope.is_active()

    # Warn (never fail) about new-style hierarchical scope entries that match no
    # configured securable — a likely typo that would silently govern nothing.
    _warn_unmatched_scopes(
        [
            ("--tag-management-scopes", tag_management_scopes, tag_scope),
            (
                "--privilege-management-scopes",
                privilege_management_scopes,
                privilege_scope,
            ),
            (
                "--taggable-management-scopes",
                taggable_management_scopes,
                taggable_management_scope,
            ),
            (
                "--taggable-creation-scopes",
                taggable_creation_scopes,
                taggable_creation_scope,
            ),
            ("--policy-deletion-scopes", policy_deletion_scopes, policy_delete_scope),
        ],
        configured_full_names,
    )

    # Group creation/management operate at the account level via the account SCIM
    # proxy. The workspace SCIM API surfaces only workspace-level groups and cannot
    # create or manage account groups, so enabling a group scope under
    # --use-workspace-scim is unsupported. (Configuring groups without any group
    # scope is inert and compatible with --use-workspace-scim.)
    group_domain_active = enable_group_creation or enable_group_management
    if config.groups and group_domain_active and use_workspace_scim:
        raise OrchestratorError(
            "Group creation/management requires the account SCIM proxy, but "
            "--use-workspace-scim was set. Remove --use-workspace-scim to create or "
            "manage the groups declared in config."
        )
    # Resolving user members of a managed group requires the account users list, so
    # group management cannot run alongside --skip-users-fetch.
    if config.groups and group_domain_active and skip_users_fetch:
        raise OrchestratorError(
            "Group creation/management requires the account users list to resolve "
            "user members, but --skip-users-fetch was set. Remove --skip-users-fetch "
            "to create or manage the groups declared in config."
        )
    # Group deletion makes config authoritative over group existence — it is only
    # usable alongside group creation, and never against an empty config (a
    # destructive account-wide sweep with no declared groups is disallowed outright).
    if enable_group_deletion and not config.groups:
        raise OrchestratorError(
            "Group deletion is enabled but no groups are declared under "
            "resources.groups. Declare the groups config should own, or disable "
            "group deletion."
        )
    if enable_group_deletion and not enable_group_creation:
        raise OrchestratorError(
            "Group deletion requires group creation to also be active (config must "
            "be authoritative over group existence). Enable group creation, or "
            "disable group deletion."
        )

    # Tag-key prefixes whose tags are never removed (only added/updated). Empty
    # string ⇒ no retention. Defaults to "class." to protect auto-classification.
    retain_prefixes = frozenset(
        p.strip() for p in retain_tag_prefixes.split(",") if p.strip()
    )
    # Actual-state (UC-side) identifiers whose resolution-failure warning is
    # suppressed across the privileges, securables (owner), and governed-tags
    # (assigners) domains. Matched by identifier only; resolvable principals are
    # unaffected. Empty by default ⇒ all unresolvable-principal warnings emitted.
    ignore_unresolvable = frozenset(
        p.strip() for p in ignore_unresolvable_principals.split(",") if p.strip()
    )

    # 2. Compile desired up-front so we can scope downstream fetches:
    #    - governed tags name set → rule-set fetches restricted to (actual ∩ desired)
    #    - securable attributes/securables → rfa_targets restricted to securables that
    #      actually declare ``rfa_destinations`` in config. Non-function securables are
    #      gated by the taggable-management flag (RFA is a managed attribute), but
    #      FUNCTION targets are always fetched — functions are engine-managed
    #      independently of the flag (mirroring ``_filter_taggable_attributes``). Without
    #      this the function's actual RFA state stays ``None`` when the flag is off, and an
    #      explicit empty list ("remove all") silently no-ops against a ``None`` actual.
    desired_groups = compile_desired_groups(config, run_date=run_date)
    desired_group_names = {g.display_name for g in desired_groups}
    desired_group_ids = {g.id for g in desired_groups if g.id}
    desired_governed_tags = compile_desired_governed_tags(config)
    desired_governed_tag_names = {gt.name for gt in desired_governed_tags}
    desired_attributes = compile_desired_attributes(config)
    desired_securables = compile_desired_securables(config)
    rfa_targets: set[tuple[SecurableType, str]] = {
        (a.securable_type, a.full_name)
        for a in desired_attributes
        if a.rfa_destinations is not None
        and (enable_taggable_management or a.securable_type == SecurableType.FUNCTION)
    }

    # 3. Parallel initial fetch (securables, tags, privileges, and principals concurrently)
    uc_helper = UnityCatalogHelper(
        workspace_client,
        warehouse_id,
        system_catalog=system_catalog,
    )
    ws_helper = WorkspaceHelper(
        workspace_client,
        use_workspace_scim=use_workspace_scim,
        manage_groups=group_domain_active and bool(desired_groups),
        skip_users_fetch=skip_users_fetch,
    )
    change_logger = ChangeLogger(dry_run=dry_run, logger=_logger)
    change_logger.log_banner()
    _logger.info(
        "  Fetching current state from workspace (this can take several minutes)..."
    )
    # actual_tags is needed by either the tags domain (for the diff) or the privileges
    # domain (for policy matching against on-disk tag state when tag management is off).
    need_actual_tags = enable_tag_management or enable_privilege_management
    with ThreadPoolExecutor() as pool:
        actual_securables_f = pool.submit(
            uc_helper.fetch_actual_securables,
            catalog_names,
            rfa_targets,
        )
        actual_policies_f = pool.submit(uc_helper.fetch_actual_policies, catalog_names)
        actual_governed_tags_f = pool.submit(
            ws_helper.fetch_actual_governed_tags,
            desired_governed_tag_names,
        )
        principals_f = pool.submit(ws_helper.fetch_principals)
        actual_tags_f = (
            pool.submit(uc_helper.fetch_actual_tags, catalog_names)
            if need_actual_tags
            else None
        )
        actual_privs_f = (
            pool.submit(uc_helper.fetch_actual_privileges, catalog_names)
            if enable_privilege_management
            else None
        )

        actual_securables, actual_attributes = actual_securables_f.result()
        actual_policies = actual_policies_f.result()
        actual_governed_tags = actual_governed_tags_f.result()
        principals_f.result()
        actual_tags = actual_tags_f.result() if actual_tags_f is not None else set()
        actual_privileges = (
            actual_privs_f.result() if actual_privs_f is not None else set()
        )
    _logger.info("  Successfully fetched current state")

    # Fetch membership for the configured groups only — one GET /Groups/{id} per
    # group (the account SCIM proxy list call doesn't return members inline),
    # dispatched concurrently. Empty when the group domain is inert.
    actual_groups = (
        ws_helper.fetch_actual_groups(desired_group_names, desired_group_ids)
        if group_domain_active
        else set()
    )
    # Group deletion needs the full account-group inventory (identity + provenance only,
    # no membership) to find Databricks-managed groups absent from config. Cheap — built
    # from caches populated during fetch_principals, no extra API calls.
    all_account_groups = (
        ws_helper.list_account_groups() if enable_group_deletion else set()
    )

    # 3. Construct the shared PrincipalResolver now that ws_helper cache is populated.
    resolver = PrincipalResolver(ws_helper)

    # 3a. Group workflow (the first domain — runs before governed tags so that any
    # groups referenced as policy/grant principals exist first). Inert unless a
    # group flag is set.
    group_diff = (
        compute_group_diff(
            desired_groups,
            actual_groups,
            resolver,
            change_logger,
            enable_group_creation=enable_group_creation,
            enable_group_management=enable_group_management,
            enable_group_deletion=enable_group_deletion,
            ignore_unresolvable=ignore_unresolvable,
            all_account_groups=all_account_groups,
            creation_scope=group_creation_scope,
            management_scope=group_management_scope,
            deletion_scope=group_deletion_scope,
        )
        if group_domain_active
        else GroupDiff()
    )
    # Groups slated for creation this run aren't in the principal cache yet (it was
    # fetched before any group existed). Register them so downstream domains
    # (governed-tag assigners, policies, privileges, securable owners) can resolve
    # them — group creation runs first, so they exist before any grant applies.
    ws_helper.register_pending_groups(group_diff.groups_to_create.keys())
    # Renames are reflected in the principal cache before downstream domains resolve:
    # the new display name becomes resolvable and the old one becomes unknown, so
    # references to the new name succeed and references to the old name fail (even in
    # dry-run, where the SCIM PATCH itself is skipped).
    ws_helper.register_pending_renames(group_diff.groups_to_rename)

    # 4. Governed tags workflow (account-level tag policies — must run before
    # catalog-scoped tag assignments, so new tag keys exist before SET TAGS).
    # desired_governed_tags was compiled at the start to scope the rule-set fetch.
    governed_tag_diff = compute_governed_tag_diff(
        desired_governed_tags,
        actual_governed_tags,
        resolver,
        change_logger,
        enable_deletion=enable_governed_tag_deletion,
        ignore_unresolvable=ignore_unresolvable,
        deletion_scope=governed_tag_deletion_scope,
    )
    # Union of declared governed tags (desired from config + actual on UC).
    # The names are used by the policies/privileges compilers to reject references
    # to tag keys that aren't governed; the full objects are used by the tags
    # compiler to validate that each securable tag's value is in the governed
    # tag's allowed_values. Desired-only covers in-flight creations, actual-only
    # covers already-deployed tags the config doesn't redeclare.
    governed_tags = desired_governed_tags | actual_governed_tags
    governed_tag_names = {t.name for t in governed_tags}

    # 5. Securables workflow (before tags and privileges) — desired sides were
    # compiled up-front; here we apply taggable-management scoping.
    # Drop non-function attribute updates whose catalog isn't in scope — the
    # engine must not touch catalog/schema/table/volume owners outside the
    # taggable-management scope. Function attributes flow through because
    # FUNCTION creation / replacement is always engine-managed. When the
    # taggable-management gate is off entirely, ``taggable_management_scope``
    # is empty and this collapses to "function attributes only".
    desired_attributes = _filter_taggable_attributes(
        desired_attributes, taggable_management_scope
    )
    actual_attributes = _filter_taggable_attributes(
        actual_attributes, taggable_management_scope
    )
    securable_diff = compute_securable_diff(
        desired_attributes,
        actual_attributes,
        desired_securables,
        actual_securables,
        resolver,
        change_logger,
        creation_in_scope_namespaces=taggable_creation_scope,
        ignore_unresolvable=ignore_unresolvable,
    )

    # 6. Tags workflow
    if enable_tag_management:
        desired_tags = compile_desired_tags(config, governed_tags, change_logger)
        in_scope_desired_tags = {
            t
            for t in desired_tags
            if tag_scope.matches(t.securable_full_name)
        }
        in_scope_actual_tags = {
            t
            for t in actual_tags
            if tag_scope.matches(t.securable_full_name)
        }
        out_of_scope_actual_tags = {
            t
            for t in actual_tags
            if not tag_scope.matches(t.securable_full_name)
        }
        tag_diff = compute_tag_diff(in_scope_desired_tags, in_scope_actual_tags)
        tag_diff, retained_tags = filter_retained_removals(tag_diff, retain_prefixes)
        if retained_tags:
            _logger.info(
                f"  Retaining {len(retained_tags)} unconfigured tag(s) matching "
                f"prefix(es) {sorted(retain_prefixes)} — these will not be removed"
            )
        # Post-run tag state used by the privileges compiler: in-scope catalogs
        # reflect the desired (about to be applied); out-of-scope reflect actual
        # (left untouched this run).
        tags_for_privilege_matching = in_scope_desired_tags | out_of_scope_actual_tags
    else:
        tag_diff = TagDiff()
        # When tag management is off the engine will not reconcile the config's
        # desired tags onto UC this run, so the privileges compiler must match
        # its policies against the on-disk tag state to stay honest.
        tags_for_privilege_matching = actual_tags

    # 7. Policies workflow (mask/filter)
    desired_policies = compile_desired_policies(
        config,
        governed_tag_names,
        change_logger,
    )
    policy_diff = compute_policy_diff(
        desired_policies,
        actual_policies,
        resolver,
        change_logger,
        ignore_unresolvable=ignore_unresolvable,
        delete_scope=policy_delete_scope,
    )

    # 8. Privileges workflow
    if enable_privilege_management:
        compiled_privileges = compile_desired_privileges(
            config,
            tags_for_privilege_matching,
            governed_tag_names,
            change_logger,
            run_date=run_date,
        )
        in_scope_compiled_privileges = {
            p
            for p in compiled_privileges
            if privilege_scope.matches(p.securable_full_name)
        }
        in_scope_actual_privileges = {
            p
            for p in actual_privileges
            if privilege_scope.matches(p.securable_full_name)
        }
        privilege_diff = compute_privilege_diff(
            in_scope_compiled_privileges,
            in_scope_actual_privileges,
            resolver,
            change_logger,
            ignore_unresolvable=ignore_unresolvable,
        )
    else:
        privilege_diff = PrivilegeDiff()

    # 9. Log and execute (or dry-run) — group management runs first.
    if (
        group_diff.groups_to_create
        or group_diff.members_to_add
        or group_diff.members_to_remove
        or group_diff.groups_to_rename
        or group_diff.groups_to_delete
    ):
        change_logger.log_section_header("Groups")
    execute_group_diff(
        ws_helper,
        group_diff,
        change_logger,
        dry_run=dry_run,
        force=force,
        max_parallel_changes=max_parallel_changes,
    )

    if (
        governed_tag_diff.to_create
        or governed_tag_diff.to_update
        or governed_tag_diff.to_delete
    ):
        change_logger.log_section_header("Governed tags")
    execute_governed_tag_diff(
        ws_helper,
        governed_tag_diff,
        change_logger,
        dry_run=dry_run,
        force=force,
        # max_parallel_changes not currently supported for governed tags
    )

    if (
        securable_diff.securables_to_create
        or securable_diff.securables_to_replace
        or securable_diff.attributes_to_update
    ):
        change_logger.log_section_header("Securables")
    execute_securable_diff(
        uc_helper,
        securable_diff,
        change_logger,
        dry_run=dry_run,
        max_parallel_changes=max_parallel_changes,
    )

    if tag_diff.to_add or tag_diff.to_update or tag_diff.to_remove:
        change_logger.log_section_header("Tags")
    execute_tag_diff(
        uc_helper,
        tag_diff,
        change_logger,
        governed_tag_names=governed_tag_names,
        dry_run=dry_run,
        force=force,
        max_parallel_changes=max_parallel_changes,
    )

    if policy_diff.to_create or policy_diff.to_replace or policy_diff.to_delete:
        change_logger.log_section_header("Policies")
    execute_policy_diff(
        uc_helper,
        policy_diff,
        change_logger,
        dry_run=dry_run,
        force=force,
        max_parallel_changes=max_parallel_changes,
    )

    if privilege_diff.to_grant or privilege_diff.to_revoke:
        change_logger.log_section_header("Privileges")
    execute_privilege_diff(
        uc_helper,
        privilege_diff,
        change_logger,
        dry_run=dry_run,
        max_parallel_changes=max_parallel_changes,
    )

    change_logger.log_errors_section()
    change_logger.log_summary()

    if change_logger.has_errors:
        raise ExecutionBatchError(change_logger.errors)

    return OrchestratorDiffsResult(
        group_diff=group_diff,
        securable_diff=securable_diff,
        governed_tag_diff=governed_tag_diff,
        tag_diff=tag_diff,
        policy_diff=policy_diff,
        privilege_diff=privilege_diff,
    )
