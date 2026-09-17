from __future__ import annotations

from typing import TYPE_CHECKING

from databricks.sdk.errors.base import DatabricksError

if TYPE_CHECKING:
    from uc_declarative_abac.helpers import WorkspaceHelper
    from uc_declarative_abac.logger import ChangeLogger

from uc_declarative_abac.discovery_domains.state import (
    DiscoveryDomain,
    DiscoveryDomainDiff,
)
from uc_declarative_abac.utils import ExecutionError, OrchestratorError


def _get_parent_domain_id(
    ws_helper: WorkspaceHelper,
    domain: DiscoveryDomain,
    unavailable_tag_keys: set[str],
) -> str:
    """Resolve a child's parent id without falling back to top-level creation."""
    if not domain.parent_tag_key:
        return ""
    if domain.parent_tag_key in unavailable_tag_keys:
        raise OrchestratorError(
            f"Parent Discovery domain {domain.parent_tag_key!r} was not created."
        )
    parent_domain_id = domain.parent_domain_id or ws_helper.get_discovery_domain_id(
        domain.parent_tag_key
    )
    if not parent_domain_id:
        raise OrchestratorError(
            f"Parent Discovery domain id not available for {domain.parent_tag_key!r}."
        )
    return parent_domain_id


def _log_create_error(
    domain: DiscoveryDomain,
    error: DatabricksError | OrchestratorError,
    change_logger: ChangeLogger,
) -> None:
    """Record one failed domain creation and leave the remaining batch runnable."""
    change_logger.log_error(
        ExecutionError(
            context=f"Create Discovery domain '{domain.tag_key}'",
            exception=error,
        )
    )


def _execute_updates(
    ws_helper: WorkspaceHelper,
    diff: DiscoveryDomainDiff,
    change_logger: ChangeLogger,
    dry_run: bool,
) -> None:
    """Update managed domain descriptions and isolate failures per domain."""
    for domain in sorted(diff.to_update, key=lambda item: item.tag_key):
        old = diff.old_values.get(domain.tag_key)
        if not dry_run:
            try:
                ws_helper.update_discovery_domain(
                    domain,
                    update_mask="description",
                )
            except (DatabricksError, OrchestratorError) as error:
                change_logger.log_error(
                    ExecutionError(
                        context=f"Update Discovery domain '{domain.tag_key}'",
                        exception=error,
                    )
                )
                continue
        change_logger.log_discovery_domain_update(domain, old)


def execute_discovery_domain_diff(
    ws_helper: WorkspaceHelper,
    diff: DiscoveryDomainDiff,
    change_logger: ChangeLogger,
    dry_run: bool = False,
) -> None:
    """Create missing domains in hierarchy order, then update descriptions.

    Failures are isolated per domain. A failed or unresolved parent makes its
    descendants unavailable so they can never be created as top-level domains.
    Dry-runs only report the already-validated diff and therefore do not need
    server-generated parent ids.
    """
    domains = sorted(
        diff.to_create,
        key=lambda domain: (domain.tag_key.count("/"), domain.tag_key),
    )
    unavailable_tag_keys: set[str] = set()
    for domain in domains:
        if dry_run:
            change_logger.log_discovery_domain_create(domain)
            continue
        try:
            parent_domain_id = _get_parent_domain_id(
                ws_helper,
                domain,
                unavailable_tag_keys,
            )
            ws_helper.create_discovery_domain(
                domain.tag_key,
                description=domain.description,
                parent_domain_id=parent_domain_id,
            )
        except (DatabricksError, OrchestratorError) as error:
            unavailable_tag_keys.add(domain.tag_key)
            _log_create_error(domain, error, change_logger)
            continue
        change_logger.log_discovery_domain_create(domain)
    _execute_updates(ws_helper, diff, change_logger, dry_run)
