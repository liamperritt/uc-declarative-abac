from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_declarative_abac.logger import ChangeLogger

from uc_declarative_abac.discovery_domains.state import (
    DiscoveryDomain,
    DiscoveryDomainDiff,
)
from uc_declarative_abac.utils import ExecutionError, OrchestratorError, Scope


def _log_unavailable_parent(
    domain: DiscoveryDomain,
    change_logger: ChangeLogger,
) -> None:
    """Log a fatal configuration error for a domain whose parent is unavailable."""
    change_logger.log_error(
        ExecutionError(
            context=f"Create Discovery domain '{domain.tag_key}'",
            exception=OrchestratorError(
                f"Parent Discovery domain '{domain.parent_tag_key}' is not available "
                "in desired or actual state."
            ),
        )
    )


def _get_creatable_domains(
    desired: set[DiscoveryDomain],
    actual_by_tag_key: dict[str, DiscoveryDomain],
    change_logger: ChangeLogger,
) -> set[DiscoveryDomain]:
    """Return missing domains whose parent exists now or will be created this run."""
    desired_tag_keys = {domain.tag_key for domain in desired}
    creatable: set[DiscoveryDomain] = set()
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


def _changed_fields(
    desired: DiscoveryDomain, actual: DiscoveryDomain
) -> tuple[str, ...]:
    """Determine which managed fields have changed.

    Checks fields in canonical order: description, subtitle, draft, icon.
    - description is ALWAYS managed.
    - subtitle, draft, icon are managed only when desired is not None.
    A field changed iff desired value differs from actual (for managed fields).
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
    return tuple(changed)


def _get_domain_updates(
    desired: set[DiscoveryDomain],
    actual_by_tag_key: dict[str, DiscoveryDomain],
) -> tuple[
    set[DiscoveryDomain], dict[str, DiscoveryDomain], dict[str, tuple[str, ...]]
]:
    """Return existing domains whose managed fields have changed.

    Returns a tuple of (to_update, old_values, update_masks), where:
    - to_update: domains with changes (using dataclasses.replace)
    - old_values: original values keyed by tag_key for audit trail
    - update_masks: changed field names per domain tag_key (canonical order)
    """
    to_update: set[DiscoveryDomain] = set()
    old_values: dict[str, DiscoveryDomain] = {}
    update_masks: dict[str, tuple[str, ...]] = {}
    for desired_domain in desired:
        actual_domain = actual_by_tag_key.get(desired_domain.tag_key)
        if actual_domain is None:
            continue
        changed = _changed_fields(desired_domain, actual_domain)
        if not changed:
            continue
        updated_values = {field: getattr(desired_domain, field) for field in changed}
        to_update.add(replace(actual_domain, **updated_values))
        old_values[desired_domain.tag_key] = actual_domain
        update_masks[desired_domain.tag_key] = changed
    return to_update, old_values, update_masks


def _get_domain_deletes(
    desired: set[DiscoveryDomain],
    actual: set[DiscoveryDomain],
    deletion_scope: Scope | None,
) -> set[DiscoveryDomain]:
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


def compute_discovery_domain_diff(
    desired: set[DiscoveryDomain],
    actual: set[DiscoveryDomain],
    change_logger: ChangeLogger,
    deletion_scope: Scope | None = None,
) -> DiscoveryDomainDiff:
    """Compute Discovery domain creations, metadata updates, and scoped deletions.

    Deletion is disabled when ``deletion_scope`` is omitted. When supplied, only
    actual domains absent from the explicitly declared desired state and matching the
    flat scope become deletion candidates.
    """
    actual_by_tag_key = {domain.tag_key: domain for domain in actual}
    to_update, old_values, update_masks = _get_domain_updates(
        desired, actual_by_tag_key
    )
    return DiscoveryDomainDiff(
        to_create=_get_creatable_domains(desired, actual_by_tag_key, change_logger),
        to_update=to_update,
        to_delete=_get_domain_deletes(desired, actual, deletion_scope),
        old_values=old_values,
        update_masks=update_masks,
    )
