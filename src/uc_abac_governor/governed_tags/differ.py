from __future__ import annotations

from uc_abac_governor.governed_tags.state import GovernedTag, GovernedTagDiff


def compute_governed_tag_diff(
    desired: set[GovernedTag],
    actual: set[GovernedTag],
    enable_deletion: bool = False,
) -> GovernedTagDiff:
    """Compute create / update / delete diff between desired and actual governed tags.

    Tag policies present in ``actual`` but absent from ``desired`` are left alone
    by default (no-delete invariant). When ``enable_deletion=True``, they flow into
    ``to_delete`` so the executor can issue ``delete_tag_policy`` calls — gated
    by interactive confirmation or ``--force`` at the governor boundary.
    """
    desired_by_name = {gt.name: gt for gt in desired}
    actual_by_name = {gt.name: gt for gt in actual}

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
