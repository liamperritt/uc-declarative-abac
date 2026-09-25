from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_declarative_abac.logger import ChangeLogger

from uc_declarative_abac.domains.state import (
    Domain,
    DomainDiff,
)
from uc_declarative_abac.principals import (
    Principal,
    PrincipalResolver,
    log_principal_resolution_failure,
)
from uc_declarative_abac.utils import (
    ExecutionError,
    OrchestratorError,
    PrincipalValidationError,
    Scope,
)

# Managed update fields, mapping the SDK/update-mask field path to the ``Domain``
# state attribute holding the desired value. The mask token is what the executor
# passes to the Domains ``update_mask``; for owners the token (``*_owner_ids``)
# differs from the readable state attribute (``*_owners``).
_MANAGED_FIELD_ATTRS: dict[str, str] = {
    "description": "description",
    "subtitle": "subtitle",
    "draft": "draft",
    "icon": "icon",
    "business_owner_ids": "business_owners",
    "technical_owner_ids": "technical_owners",
}


def _resolve_owner_set(
    owners: frozenset[Principal] | None,
    tag_key: str,
    role: str,
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
    ignore_unresolvable: frozenset[str],
) -> frozenset[Principal] | None:
    """Resolve one owner set, dropping (and logging) any principal that fails.

    ``None`` (unmanaged) is returned unchanged. Config-side failures are fatal and
    actual-side failures are non-fatal warnings — routed by
    ``log_principal_resolution_failure`` — exactly like governed-tag assigners.
    """
    if owners is None:
        return None
    resolved: set[Principal] = set()
    for principal in owners:
        try:
            resolved.add(resolver.resolve_principal(principal))
        except PrincipalValidationError as exc:
            log_principal_resolution_failure(
                change_logger,
                f"Resolve {role} owner for domain {tag_key}",
                principal,
                exc,
                ignore_unresolvable,
            )
    return frozenset(resolved)


def _resolve_domain_owners(
    domain: Domain,
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
    ignore_unresolvable: frozenset[str],
) -> Domain:
    """Return ``domain`` with its business/technical owner principals resolved."""
    return replace(
        domain,
        business_owners=_resolve_owner_set(
            domain.business_owners,
            domain.tag_key,
            "business",
            resolver,
            change_logger,
            ignore_unresolvable,
        ),
        technical_owners=_resolve_owner_set(
            domain.technical_owners,
            domain.tag_key,
            "technical",
            resolver,
            change_logger,
            ignore_unresolvable,
        ),
    )


def _log_unavailable_parent(
    domain: Domain,
    change_logger: ChangeLogger,
) -> None:
    """Log a fatal configuration error for a domain whose parent is unavailable."""
    change_logger.log_error(
        ExecutionError(
            context=f"Create domain '{domain.tag_key}'",
            exception=OrchestratorError(
                f"Parent domain '{domain.parent_tag_key}' is not available "
                "in desired or actual state."
            ),
        )
    )


def _get_creatable_domains(
    desired: set[Domain],
    actual_by_tag_key: dict[str, Domain],
    change_logger: ChangeLogger,
) -> set[Domain]:
    """Return missing domains whose parent exists now or will be created this run."""
    desired_tag_keys = {domain.tag_key for domain in desired}
    creatable: set[Domain] = set()
    for domain in desired:
        if domain.tag_key in actual_by_tag_key:
            continue
        if (
            domain.parent_tag_key
            and domain.parent_tag_key not in actual_by_tag_key
            and domain.parent_tag_key not in desired_tag_keys
        ):
            _log_unavailable_parent(domain, change_logger)
            continue
        creatable.add(
            replace(
                domain,
                parent_domain_id=actual_by_tag_key[domain.parent_tag_key].domain_id
                if domain.parent_tag_key in actual_by_tag_key
                else "",
            )
        )
    return creatable


def _changed_fields(desired: Domain, actual: Domain) -> tuple[str, ...]:
    """Determine which managed fields have changed, as update-mask tokens.

    Checks fields in canonical order: description, subtitle, draft, icon,
    business owners, technical owners.
    - description is ALWAYS managed.
    - subtitle, draft, icon, and the owner sets are managed only when desired is
      not None.
    A field changed iff desired value differs from actual (for managed fields).
    Owner tokens are the SDK field paths (``business_owner_ids`` /
    ``technical_owner_ids``); owners are compared as already-resolved principal sets.
    """
    changed: list[str] = []
    if desired.description != actual.description:
        changed.append("description")
    if desired.subtitle is not None and desired.subtitle != actual.subtitle:
        changed.append("subtitle")
    if desired.draft is not None and desired.draft != actual.draft:
        changed.append("draft")
    if desired.icon is not None and desired.icon != actual.icon:
        changed.append("icon")
    if (
        desired.business_owners is not None
        and desired.business_owners != actual.business_owners
    ):
        changed.append("business_owner_ids")
    if (
        desired.technical_owners is not None
        and desired.technical_owners != actual.technical_owners
    ):
        changed.append("technical_owner_ids")
    return tuple(changed)


def _get_domain_updates(
    desired: set[Domain],
    actual_by_tag_key: dict[str, Domain],
) -> tuple[set[Domain], dict[str, Domain], dict[str, tuple[str, ...]]]:
    """Return existing domains whose managed fields have changed.

    Returns a tuple of (to_update, old_values, update_masks), where:
    - to_update: domains with changes (using dataclasses.replace)
    - old_values: original values keyed by tag_key for audit trail
    - update_masks: changed field names per domain tag_key (canonical order)
    """
    to_update: set[Domain] = set()
    old_values: dict[str, Domain] = {}
    update_masks: dict[str, tuple[str, ...]] = {}
    for desired_domain in desired:
        actual_domain = actual_by_tag_key.get(desired_domain.tag_key)
        if actual_domain is None:
            continue
        changed = _changed_fields(desired_domain, actual_domain)
        if not changed:
            continue
        updated_values = {
            _MANAGED_FIELD_ATTRS[field]: getattr(
                desired_domain, _MANAGED_FIELD_ATTRS[field]
            )
            for field in changed
        }
        to_update.add(replace(actual_domain, **updated_values))
        old_values[desired_domain.tag_key] = actual_domain
        update_masks[desired_domain.tag_key] = changed
    return to_update, old_values, update_masks


def _get_domain_deletes(
    desired: set[Domain],
    actual: set[Domain],
    deletion_scope: Scope | None,
) -> set[Domain]:
    """Return actual-only domains whose tag keys match the deletion scope."""
    if deletion_scope is None:
        return set()
    desired_tag_keys = {domain.tag_key for domain in desired}
    return {
        domain
        for domain in actual
        if domain.tag_key not in desired_tag_keys
        and deletion_scope.matches(domain.tag_key)
    }


def compute_domain_diff(
    desired: set[Domain],
    actual: set[Domain],
    change_logger: ChangeLogger,
    resolver: PrincipalResolver,
    deletion_scope: Scope | None = None,
    ignore_unresolvable: frozenset[str] = frozenset(),
) -> DomainDiff:
    """Compute domain creations, metadata updates, and scoped deletions.

    Owner principals on both sides are resolved up front (config-side failures fatal,
    actual-side non-fatal warnings; unresolvable owners dropped) so create/update
    comparisons operate on resolved principal sets — the same pattern as governed-tag
    assigners.

    Deletion is disabled when ``deletion_scope`` is omitted. When supplied, only
    actual domains absent from the explicitly declared desired state and matching the
    flat scope become deletion candidates.
    """
    desired = {
        _resolve_domain_owners(d, resolver, change_logger, ignore_unresolvable)
        for d in desired
    }
    actual = {
        _resolve_domain_owners(a, resolver, change_logger, ignore_unresolvable)
        for a in actual
    }
    actual_by_tag_key = {domain.tag_key: domain for domain in actual}
    to_update, old_values, update_masks = _get_domain_updates(
        desired, actual_by_tag_key
    )
    return DomainDiff(
        to_create=_get_creatable_domains(desired, actual_by_tag_key, change_logger),
        to_update=to_update,
        to_delete=_get_domain_deletes(desired, actual, deletion_scope),
        old_values=old_values,
        update_masks=update_masks,
    )
