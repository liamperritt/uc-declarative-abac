from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_declarative_abac.logger import ChangeLogger
    from uc_declarative_abac.principals import PrincipalResolver

from uc_declarative_abac.governed_tags.state import (
    GovernedTag,
    GovernedTagDiff,
)
from uc_declarative_abac.utils import (
    ExecutionError,
    is_system_governed_tag,
    OrchestratorError,
    PrincipalValidationError,
)
from uc_declarative_abac.principals import (
    log_principal_resolution_failure,
    Principal,
)



def _resolve_governed_tag_assigners(
    tag: GovernedTag,
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
    ignore_unresolvable: frozenset[str] = frozenset(),
) -> GovernedTag:
    """Return a new GovernedTag with each principal in ``assigners``
    resolved against the workspace.

    Principals that fail to resolve are logged and dropped from the tag's
    assigners — consistent with the privileges differ. Dropping (rather than
    aborting) means an unresolvable principal won't trigger a phantom
    grant/revoke on every run. Actual-state (UC-side) principals route to a
    non-fatal warning (suppressed when the identifier is in
    ``ignore_unresolvable``); config-side principals route to a fatal error (see
    log_principal_resolution_failure).
    """
    resolved: set[Principal] = set()
    for principal in tag.assigners:
        try:
            resolved.add(resolver.resolve_principal(principal))
        except PrincipalValidationError as exc:
            log_principal_resolution_failure(
                change_logger,
                f"Resolve principal for ASSIGN on GOVERNED_TAG {tag.name}",
                principal,
                exc,
                ignore_unresolvable,
            )
            continue
    return GovernedTag(
        name=tag.name,
        description=tag.description,
        allowed_values=tag.allowed_values,
        assigners=frozenset(resolved),
    )


def _diff_governed_tag_creates(
    desired_by_name: dict[str, GovernedTag],
    actual_by_name: dict[str, GovernedTag],
    change_logger: ChangeLogger,
) -> set[GovernedTag]:
    """Desired tags absent from actual. User-defined tags are created; a system tag
    absent from the account is a fatal error (it can't be created)."""
    to_create: set[GovernedTag] = set()
    for name, gt in desired_by_name.items():
        if name in actual_by_name:
            continue
        if is_system_governed_tag(name):
            change_logger.log_error(ExecutionError(
                context=f"Governed tag '{name}'",
                exception=OrchestratorError(
                    f"System governed tag '{name}' is declared in config but does not "
                    "exist in the account; system tags cannot be created."
                ),
            ))
            continue
        to_create.add(gt)
    return to_create


def _diff_governed_tag_updates(
    desired_by_name: dict[str, GovernedTag],
    actual_by_name: dict[str, GovernedTag],
) -> tuple[set[GovernedTag], dict[str, GovernedTag]]:
    """Tags present on both sides that need updating. User-defined tags update on any
    field difference. System tags update only when assigners differ, and the emitted
    entry keeps actual's definition so the executor issues an assigners-only change
    (never a forbidden ``update_tag_policy`` on the Databricks-owned definition)."""
    to_update: set[GovernedTag] = set()
    old_values: dict[str, GovernedTag] = {}
    for name in desired_by_name.keys() & actual_by_name.keys():
        desired_gt = desired_by_name[name]
        actual_gt = actual_by_name[name]
        if is_system_governed_tag(name):
            if desired_gt.assigners != actual_gt.assigners:
                to_update.add(GovernedTag(
                    name=name,
                    description=actual_gt.description,
                    allowed_values=actual_gt.allowed_values,
                    assigners=desired_gt.assigners,
                ))
                old_values[name] = actual_gt
        elif desired_gt != actual_gt:
            to_update.add(desired_gt)
            old_values[name] = actual_gt
    return to_update, old_values


def _diff_governed_tag_deletes(
    desired_by_name: dict[str, GovernedTag],
    actual_by_name: dict[str, GovernedTag],
    enable_deletion: bool,
) -> set[GovernedTag]:
    """Actual tags absent from desired, when deletion is enabled. System tags are never
    deletion candidates — UC rejects deleting them, which would fail the run."""
    if not enable_deletion:
        return set()
    return {
        gt for name, gt in actual_by_name.items()
        if name not in desired_by_name and not is_system_governed_tag(name)
    }


def compute_governed_tag_diff(
    desired: set[GovernedTag],
    actual: set[GovernedTag],
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
    enable_deletion: bool = False,
    ignore_unresolvable: frozenset[str] = frozenset(),
) -> GovernedTagDiff:
    """Compute create / update / delete diff between desired and actual governed tags.

    Principals on both sides are resolved before comparison so the two sides
    speak the same dialect (config-side has display names; UC-side has
    identifiers). Tag policies present in ``actual`` but absent from ``desired``
    are left alone by default. When ``enable_deletion=True``, they flow into
    ``to_delete`` so the executor can issue ``delete_tag_policy`` calls — gated
    by interactive confirmation or ``--force`` at the orchestrator boundary.
    ``ignore_unresolvable`` silences the resolution-failure warning for the
    listed actual-state assigner identifiers (the assigner is still dropped).

    Databricks system-managed tags (name contains ``.``) are handled specially:
    they are never created (a system tag absent from the account is a fatal
    error) or deleted, and only their assigners are reconciled — their
    Databricks-owned definition is left untouched. See ``is_system_governed_tag``.
    """
    desired_resolved = {
        _resolve_governed_tag_assigners(t, resolver, change_logger, ignore_unresolvable) for t in desired
    }
    actual_resolved = {
        _resolve_governed_tag_assigners(t, resolver, change_logger, ignore_unresolvable) for t in actual
    }

    desired_by_name = {gt.name: gt for gt in desired_resolved}
    actual_by_name = {gt.name: gt for gt in actual_resolved}

    to_create = _diff_governed_tag_creates(desired_by_name, actual_by_name, change_logger)
    to_update, old_values = _diff_governed_tag_updates(desired_by_name, actual_by_name)
    to_delete = _diff_governed_tag_deletes(desired_by_name, actual_by_name, enable_deletion)

    return GovernedTagDiff(
        to_create=to_create,
        to_update=to_update,
        to_delete=to_delete,
        old_values=old_values,
    )
