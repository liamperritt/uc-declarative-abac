from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_declarative_abac.logger import ChangeLogger

from uc_declarative_abac.discovery_domains.state import (
    DiscoveryDomain,
    DiscoveryDomainDiff,
)
from uc_declarative_abac.utils import ExecutionError, OrchestratorError


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


def _get_domain_updates(
    desired: set[DiscoveryDomain],
    actual_by_tag_key: dict[str, DiscoveryDomain],
) -> tuple[set[DiscoveryDomain], dict[str, DiscoveryDomain]]:
    """Return existing domains whose managed description has changed."""
    to_update: set[DiscoveryDomain] = set()
    old_values: dict[str, DiscoveryDomain] = {}
    for desired_domain in desired:
        actual_domain = actual_by_tag_key.get(desired_domain.tag_key)
        if (
            actual_domain is None
            or desired_domain.description == actual_domain.description
        ):
            continue
        to_update.add(replace(actual_domain, description=desired_domain.description))
        old_values[desired_domain.tag_key] = actual_domain
    return to_update, old_values


def compute_discovery_domain_diff(
    desired: set[DiscoveryDomain],
    actual: set[DiscoveryDomain],
    change_logger: ChangeLogger,
) -> DiscoveryDomainDiff:
    """Compute additive Discovery domain creations and metadata updates."""
    actual_by_tag_key = {domain.tag_key: domain for domain in actual}
    to_update, old_values = _get_domain_updates(desired, actual_by_tag_key)
    return DiscoveryDomainDiff(
        to_create=_get_creatable_domains(desired, actual_by_tag_key, change_logger),
        to_update=to_update,
        old_values=old_values,
    )
