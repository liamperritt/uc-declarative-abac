from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Literal

from databricks.sdk import WorkspaceClient

from uc_declarative_abac.configs import (
    consolidate_resources,
    discover_yaml_files,
    load_raw_configs,
    resolve_refs,
    ResourcesConfig,
)
from uc_declarative_abac.governed_tags import (
    compile_desired_governed_tags,
    compute_governed_tag_diff,
    execute_governed_tag_diff,
    GovernedTagDiff,
)
from uc_declarative_abac.helpers import (
    UnityCatalogHelper,
    WorkspaceHelper,
)
from uc_declarative_abac.policies import (
    compile_desired_policies,
    compute_policy_diff,
    execute_policy_diff,
    PolicyDiff,
)
from uc_declarative_abac.principals import (
    compile_desired_groups,
    compute_group_diff,
    execute_group_diff,
    GroupDiff,
    PrincipalResolver,
)
from uc_declarative_abac.privileges import (
    compile_desired_privileges,
    compute_privilege_diff,
    execute_privilege_diff,
    PrivilegeDiff,
)
from uc_declarative_abac.securables import (
    compile_desired_attributes,
    compile_desired_securables,
    compute_securable_diff,
    execute_securable_diff,
    SecurableAttributes,
    SecurableDiff,
)
from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.tags import (
    compile_desired_tags,
    compute_tag_diff,
    execute_tag_diff,
    filter_retained_removals,
    TagDiff,
)
from uc_declarative_abac.types import SecurableType
from uc_declarative_abac.utils import (
    catalog_of,
    ExecutionBatchError,
    OrchestratorError,
    parse_catalog_filter,
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
    attrs: set[SecurableAttributes], in_scope_catalogs: frozenset[str],
) -> set[SecurableAttributes]:
    """Drop non-function attributes whose catalog isn't in scope.

    FUNCTION attributes always flow through (functions are engine-managed
    independently of the taggable-management gate). When ``in_scope_catalogs``
    is empty, this collapses to "function attributes only" — which is the
    behaviour when ``--enable-taggable-management`` is off.
    """
    return {
        a for a in attrs
        if a.securable_type == SecurableType.FUNCTION
        or catalog_of(a.full_name) in in_scope_catalogs
    }


def run(
    config_dir: Path,
    workspace_client: WorkspaceClient,
    warehouse_id: str,
    dry_run: bool = False,
    use_workspace_scim: bool = False,
    enable_tag_management: bool = False,
    enable_taggable_management: bool = False,
    enable_taggable_creation: bool = False,
    enable_privilege_management: bool = False,
    enable_governed_tag_deletion: bool = False,
    enable_group_creation: bool = False,
    enable_group_management: bool = False,
    ignore_unresolvable_principals: str = "",
    manage_tags_for_catalogs: str = "*",
    manage_privileges_for_catalogs: str = "*",
    manage_taggables_for_catalogs: str = "*",
    create_taggables_for_catalogs: str = "*",
    retain_tag_prefixes: str = "class.",
    force: bool = False,
    ref_override_strategy: Literal["merge", "replace"] = "merge",
    max_parallel_changes: int = 8,
) -> OrchestratorDiffsResult:
    """Run the full governance pipeline: discover, resolve, compile, diff, apply.

    Returns the computed diffs for every domain in execution order.
    In dry-run mode, diffs are computed but no SQL is executed.

    The four ``enable_*`` flags gate mutation classes. Each defaults to False;
    when unset the corresponding domain is skipped in both dry-run and real-run
    (no fetch, no diff, no log, no execute). ``enable_privilege_management=True``
    with ``enable_tag_management=False`` makes the privileges compiler match its
    grant policies against the on-disk (``actual``) tag state instead of the
    config's desired tags.

    The four ``*_for_catalogs`` strings further scope each enabled domain to a
    subset of the configured catalogs. ``"*"`` (the default) means "all
    configured catalogs"; a comma-separated list narrows to the listed names.
    A filter has no effect unless its paired ``enable_*`` flag is set. Unknown
    catalog names raise ``ValueError`` early. Function securables are never
    catalog-filtered — they're engine-managed and flow through all scopes.

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
    # 1. Discover + load + resolve YAML
    paths = discover_yaml_files(config_dir)
    raw_defs, raw_resources = load_raw_configs(paths)
    resolved = resolve_refs(raw_defs, raw_resources, override_strategy=ref_override_strategy)
    consolidated = consolidate_resources(resolved)
    config = ResourcesConfig.model_validate(consolidated)
    catalog_names = list(config.catalogs.keys())

    # Group creation/management operate at the account level via the account SCIM
    # proxy. The workspace SCIM API surfaces only workspace-level groups and cannot
    # create or manage account groups, so enabling a group flag under
    # --use-workspace-scim is unsupported. (Configuring groups without any group
    # flag is inert and compatible with --use-workspace-scim.)
    group_domain_active = enable_group_creation or enable_group_management
    if config.groups and group_domain_active and use_workspace_scim:
        raise OrchestratorError(
            "Group creation/management requires the account SCIM proxy, but "
            "--use-workspace-scim was set. Remove --use-workspace-scim to create or "
            "manage the groups declared in config."
        )

    # Parse per-domain catalog filters. Each scope is empty when its paired
    # enable flag is off — that single representation drives the rest of the
    # pipeline (empty set ⇒ domain inert for every catalog).
    tag_scope = (
        parse_catalog_filter(manage_tags_for_catalogs, catalog_names)
        if enable_tag_management else frozenset()
    )
    privilege_scope = (
        parse_catalog_filter(manage_privileges_for_catalogs, catalog_names)
        if enable_privilege_management else frozenset()
    )
    taggable_management_scope = (
        parse_catalog_filter(manage_taggables_for_catalogs, catalog_names)
        if enable_taggable_management else frozenset()
    )
    taggable_creation_scope = (
        parse_catalog_filter(create_taggables_for_catalogs, catalog_names)
        if enable_taggable_creation else frozenset()
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
    #      actually declare ``rfa_destinations`` in config (gated by the
    #      taggable-management flag, since RFA is a managed attribute)
    desired_groups = compile_desired_groups(config)
    desired_group_names = {g.display_name for g in desired_groups}
    desired_group_ids = {g.id for g in desired_groups if g.id}
    desired_governed_tags = compile_desired_governed_tags(config)
    desired_governed_tag_names = {gt.name for gt in desired_governed_tags}
    desired_attributes = compile_desired_attributes(config)
    desired_securables = compile_desired_securables(config)
    rfa_targets: set[tuple[SecurableType, str]] = (
        {
            (a.securable_type, a.full_name)
            for a in desired_attributes
            if a.rfa_destinations is not None
        }
        if enable_taggable_management
        else set()
    )

    # 3. Parallel initial fetch (securables, tags, privileges, and principals concurrently)
    uc_helper = UnityCatalogHelper(workspace_client, warehouse_id)
    ws_helper = WorkspaceHelper(
        workspace_client,
        use_workspace_scim=use_workspace_scim,
        manage_groups=group_domain_active and bool(desired_groups),
    )
    change_logger = ChangeLogger(dry_run=dry_run, logger=_logger)
    change_logger.log_banner()
    _logger.info("  Fetching current state from workspace (this can take several minutes)...")
    # actual_tags is needed by either the tags domain (for the diff) or the privileges
    # domain (for policy matching against on-disk tag state when tag management is off).
    need_actual_tags = enable_tag_management or enable_privilege_management
    with ThreadPoolExecutor() as pool:
        actual_securables_f = pool.submit(
            uc_helper.fetch_actual_securables, catalog_names, rfa_targets,
        )
        actual_policies_f = pool.submit(uc_helper.fetch_actual_policies, config)
        actual_governed_tags_f = pool.submit(
            ws_helper.fetch_actual_governed_tags, desired_governed_tag_names,
        )
        principals_f = pool.submit(ws_helper.fetch_principals)
        actual_tags_f = pool.submit(uc_helper.fetch_actual_tags, catalog_names) if need_actual_tags else None
        actual_privs_f = pool.submit(uc_helper.fetch_actual_privileges, catalog_names) if enable_privilege_management else None

        actual_securables, actual_attributes = actual_securables_f.result()
        actual_policies = actual_policies_f.result()
        actual_governed_tags = actual_governed_tags_f.result()
        principals_f.result()
        actual_tags = actual_tags_f.result() if actual_tags_f is not None else set()
        actual_privileges = actual_privs_f.result() if actual_privs_f is not None else set()
    _logger.info("  Successfully fetched current state")

    # Fetch membership for the configured groups only — one GET /Groups/{id} per
    # group (the account SCIM proxy list call doesn't return members inline),
    # dispatched concurrently. Empty when the group domain is inert.
    actual_groups = (
        ws_helper.fetch_actual_groups(desired_group_names, desired_group_ids)
        if group_domain_active else set()
    )

    # 3. Construct the shared PrincipalResolver now that ws_helper cache is populated.
    resolver = PrincipalResolver(ws_helper)

    # 3a. Group workflow (the first domain — runs before governed tags so that any
    # groups referenced as policy/grant principals exist first). Inert unless a
    # group flag is set.
    group_diff = compute_group_diff(
        desired_groups, actual_groups, resolver, change_logger,
        enable_group_creation=enable_group_creation,
        enable_group_management=enable_group_management,
        ignore_unresolvable=ignore_unresolvable,
    ) if group_domain_active else GroupDiff()
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
        desired_governed_tags, actual_governed_tags,
        resolver, change_logger,
        enable_deletion=enable_governed_tag_deletion,
        ignore_unresolvable=ignore_unresolvable,
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
    desired_attributes = _filter_taggable_attributes(desired_attributes, taggable_management_scope)
    actual_attributes = _filter_taggable_attributes(actual_attributes, taggable_management_scope)
    securable_diff = compute_securable_diff(
        desired_attributes, actual_attributes, desired_securables, actual_securables,
        resolver, change_logger,
        creation_in_scope_catalogs=taggable_creation_scope,
        ignore_unresolvable=ignore_unresolvable,
    )

    # 6. Tags workflow
    if enable_tag_management:
        desired_tags = compile_desired_tags(config, governed_tags, change_logger)
        in_scope_desired_tags = {
            t for t in desired_tags if catalog_of(t.securable_full_name) in tag_scope
        }
        in_scope_actual_tags = {
            t for t in actual_tags if catalog_of(t.securable_full_name) in tag_scope
        }
        out_of_scope_actual_tags = {
            t for t in actual_tags if catalog_of(t.securable_full_name) not in tag_scope
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
        config, governed_tag_names, change_logger,
    )
    policy_diff = compute_policy_diff(
        desired_policies, actual_policies, resolver, change_logger,
        ignore_unresolvable=ignore_unresolvable,
    )

    # 8. Privileges workflow
    if enable_privilege_management:
        compiled_privileges = compile_desired_privileges(
            config, tags_for_privilege_matching, governed_tag_names, change_logger,
            run_date=date.today(),
        )
        in_scope_compiled_privileges = {
            p for p in compiled_privileges if catalog_of(p.securable_full_name) in privilege_scope
        }
        in_scope_actual_privileges = {
            p for p in actual_privileges if catalog_of(p.securable_full_name) in privilege_scope
        }
        privilege_diff = compute_privilege_diff(
            in_scope_compiled_privileges, in_scope_actual_privileges, resolver, change_logger,
            ignore_unresolvable=ignore_unresolvable,
        )
    else:
        privilege_diff = PrivilegeDiff()

    # 9. Log and execute (or dry-run) — group management runs first.
    if (group_diff.groups_to_create or group_diff.members_to_add
            or group_diff.members_to_remove or group_diff.groups_to_rename):
        change_logger.log_section_header("Groups")
    execute_group_diff(
        ws_helper, group_diff, change_logger,
        dry_run=dry_run, max_parallel_changes=max_parallel_changes,
    )

    if governed_tag_diff.to_create or governed_tag_diff.to_update or governed_tag_diff.to_delete:
        change_logger.log_section_header("Governed tags")
    execute_governed_tag_diff(
        ws_helper, governed_tag_diff, change_logger,
        dry_run=dry_run, force=force,
        # max_parallel_changes not currently supported for governed tags
    )

    if securable_diff.securables_to_create or securable_diff.securables_to_replace or securable_diff.attributes_to_update:
        change_logger.log_section_header("Securables")
    execute_securable_diff(
        uc_helper, securable_diff, change_logger,
        dry_run=dry_run, max_parallel_changes=max_parallel_changes,
    )

    if tag_diff.to_add or tag_diff.to_update or tag_diff.to_remove:
        change_logger.log_section_header("Tags")
    execute_tag_diff(
        uc_helper, tag_diff, change_logger,
        governed_tag_names=governed_tag_names, dry_run=dry_run, force=force,
        max_parallel_changes=max_parallel_changes,
    )

    if policy_diff.to_create or policy_diff.to_replace:
        change_logger.log_section_header("Policies")
    execute_policy_diff(
        uc_helper, policy_diff, change_logger,
        dry_run=dry_run, max_parallel_changes=max_parallel_changes,
    )

    if privilege_diff.to_grant or privilege_diff.to_revoke:
        change_logger.log_section_header("Privileges")
    execute_privilege_diff(
        uc_helper, privilege_diff, change_logger,
        dry_run=dry_run, max_parallel_changes=max_parallel_changes,
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
