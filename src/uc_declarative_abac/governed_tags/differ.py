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
    PrincipalValidationError,
)
from uc_declarative_abac.principals import Principal



def _resolve_governed_tag_assigners(
    tag: GovernedTag,
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
) -> GovernedTag:
    """Return a new GovernedTag with each principal in ``assigners``
    resolved against the workspace.

    Principals that fail to resolve are logged once via
    ``change_logger.log_error`` and dropped from the tag's assigners
    — consistent with the privileges differ. Dropping (rather than aborting)
    means an unresolvable principal won't trigger a phantom grant/revoke on
    every run; the operator surfaces the error and fixes the config.
    """
    resolved: set[Principal] = set()
    for principal in tag.assigners:
        try:
            resolved.add(resolver.resolve_principal(principal))
        except PrincipalValidationError as exc:
            change_logger.log_error(ExecutionError(
                context=f"Resolve principal for ASSIGN on GOVERNED_TAG {tag.name}",
                exception=exc,
            ))
            continue
    return GovernedTag(
        name=tag.name,
        description=tag.description,
        allowed_values=tag.allowed_values,
        assigners=frozenset(resolved),
    )


def compute_governed_tag_diff(
    desired: set[GovernedTag],
    actual: set[GovernedTag],
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
    enable_deletion: bool = False,
) -> GovernedTagDiff:
    """Compute create / update / delete diff between desired and actual governed tags.

    Principals on both sides are resolved before comparison so the two sides
    speak the same dialect (config-side has display names; UC-side has
    identifiers). Tag policies present in ``actual`` but absent from ``desired``
    are left alone by default. When ``enable_deletion=True``, they flow into
    ``to_delete`` so the executor can issue ``delete_tag_policy`` calls — gated
    by interactive confirmation or ``--force`` at the orchestrator boundary.
    """
    desired_resolved = {
        _resolve_governed_tag_assigners(t, resolver, change_logger) for t in desired
    }
    actual_resolved = {
        _resolve_governed_tag_assigners(t, resolver, change_logger) for t in actual
    }

    desired_by_name = {gt.name: gt for gt in desired_resolved}
    actual_by_name = {gt.name: gt for gt in actual_resolved}

    to_create = {gt for name, gt in desired_by_name.items() if name not in actual_by_name}

    update_names = {
        name for name in desired_by_name.keys() & actual_by_name.keys()
        if desired_by_name[name] != actual_by_name[name]
    }
    to_update = {desired_by_name[name] for name in update_names}
    old_values = {name: actual_by_name[name] for name in update_names}

    to_delete: set[GovernedTag] = set()
    if enable_deletion:
        to_delete = {gt for name, gt in actual_by_name.items() if name not in desired_by_name}

    return GovernedTagDiff(
        to_create=to_create,
        to_update=to_update,
        to_delete=to_delete,
        old_values=old_values,
    )
