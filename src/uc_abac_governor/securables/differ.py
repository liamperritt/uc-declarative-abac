from __future__ import annotations

from uc_abac_governor.securables.state import (
    AttributeUpdate,
    SecurableAttributes,
    SecurableDiff,
    SecurableInfo,
)
from uc_abac_governor.types import Principal

_GOVERNED_ATTRIBUTES = ["owner"]


def compute_securable_diff(
    desired_attrs: set[SecurableAttributes],
    actual_attrs: set[SecurableAttributes],
    desired_securables: set[SecurableInfo],
    actual_securables: set[SecurableInfo],
    desired_owner_principals: dict[str, Principal] | None = None,
    actual_owner_principals: dict[str, Principal] | None = None,
) -> SecurableDiff:
    """Compute the diff between desired and actual securable state."""
    securables_to_create, securables_to_replace = _diff_securables(
        desired_securables, actual_securables
    )

    created_full_names = {s.full_name for s in securables_to_create}

    attributes_to_update = _diff_attributes(
        desired_attrs, actual_attrs, created_full_names,
        desired_owner_principals or {},
        actual_owner_principals or {},
    )

    return SecurableDiff(
        attributes_to_update=attributes_to_update,
        securables_to_create=securables_to_create,
        securables_to_replace=securables_to_replace,
    )


def _diff_securables(
    desired: set[SecurableInfo],
    actual: set[SecurableInfo],
) -> tuple[list[SecurableInfo], list[SecurableInfo]]:
    """Return (to_create, to_replace) lists by keying on full_name."""
    actual_by_name = {s.full_name: s for s in actual}

    to_create: list[SecurableInfo] = []
    to_replace: list[SecurableInfo] = []

    for desired_sec in desired:
        actual_sec = actual_by_name.get(desired_sec.full_name)
        if actual_sec is None:
            to_create.append(desired_sec)
        elif desired_sec != actual_sec:
            to_replace.append(desired_sec)

    return to_create, to_replace


def _diff_attributes(
    desired_attrs: set[SecurableAttributes],
    actual_attrs: set[SecurableAttributes],
    created_full_names: set[str],
    desired_owner_principals: dict[str, Principal],
    actual_owner_principals: dict[str, Principal],
) -> list[AttributeUpdate]:
    """Return attribute updates by comparing desired vs actual attributes.

    When principal mappings are provided for the owner attribute, comparison
    uses Principal.identifier and the AttributeUpdate values are Principal
    objects. Otherwise falls back to raw string comparison.

    Desired-only attributes are skipped unless the securable is being created.
    """
    actual_by_key = {
        (a.securable_type, a.full_name): a for a in actual_attrs
    }

    updates: list[AttributeUpdate] = []

    for desired in desired_attrs:
        key = (desired.securable_type, desired.full_name)
        actual = actual_by_key.get(key)

        if actual is None and desired.full_name not in created_full_names:
            continue

        for attr in _GOVERNED_ATTRIBUTES:
            new_raw = getattr(desired, attr)
            if new_raw is None:
                continue

            if attr == "owner" and desired.full_name in desired_owner_principals:
                new_principal = desired_owner_principals[desired.full_name]
                old_principal = actual_owner_principals.get(desired.full_name)
                if old_principal is not None and new_principal.identifier == old_principal.identifier:
                    continue
                updates.append(AttributeUpdate(
                    securable_type=desired.securable_type,
                    full_name=desired.full_name,
                    attribute=attr,
                    old_value=old_principal if old_principal is not None else "",
                    new_value=new_principal,
                ))
            else:
                old_value = getattr(actual, attr, None) if actual is not None else ""
                if old_value is None:
                    old_value = ""
                if new_raw != old_value:
                    updates.append(AttributeUpdate(
                        securable_type=desired.securable_type,
                        full_name=desired.full_name,
                        attribute=attr,
                        old_value=old_value,
                        new_value=new_raw,
                    ))

    return updates
