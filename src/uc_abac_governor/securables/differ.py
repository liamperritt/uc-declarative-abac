from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_abac_governor.logger import ChangeLogger
    from uc_abac_governor.principals.resolver import PrincipalResolver

from uc_abac_governor.securables.state import (
    AttributeUpdate,
    Function,
    SecurableAttributes,
    SecurableDiff,
    Securable,
)
from uc_abac_governor.types import ExecutionError, NonexistentSecurableError, PrincipalValidationError

_GOVERNED_ATTRIBUTES = ["owner"]


def compute_securable_diff(
    desired_attrs: set[SecurableAttributes],
    actual_attrs: set[SecurableAttributes],
    desired_securables: set[Securable],
    actual_securables: set[Securable],
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
) -> SecurableDiff:
    """Compute the diff between desired and actual securable state.

    Resolves owner Principals on both sides before diffing. Owner-resolution
    failures are logged via change_logger and clear the owner field on the
    affected row (the SecurableAttributes itself is retained so the securable's
    create/replace info isn't lost).
    """
    desired_attrs = _resolve_attribute_owners(desired_attrs, resolver, change_logger)
    actual_attrs = _resolve_attribute_owners(actual_attrs, resolver, change_logger)

    securables_to_create, securables_to_replace = _diff_securables(
        desired_securables, actual_securables
    )
    securables_to_create = _log_nonexistent_non_function_securables(
        securables_to_create, change_logger,
    )

    created_full_names = {s.full_name for s in securables_to_create}

    attributes_to_update = _diff_attributes(
        desired_attrs, actual_attrs, created_full_names,
    )

    return SecurableDiff(
        attributes_to_update=attributes_to_update,
        securables_to_create=securables_to_create,
        securables_to_replace=securables_to_replace,
    )


def _resolve_attribute_owners(
    unresolved: set[SecurableAttributes],
    resolver: PrincipalResolver,
    change_logger: ChangeLogger,
) -> set[SecurableAttributes]:
    """Resolve owner Principals on a set of SecurableAttributes.

    On failure, clears the owner field but retains the SecurableAttributes —
    dropping it would lose the securable's create/replace info.
    """
    result: set[SecurableAttributes] = set()
    for attr in unresolved:
        if attr.owner is None:
            result.add(attr)
            continue
        try:
            resolved_owner = resolver.resolve_principal(attr.owner)
        except PrincipalValidationError as exc:
            change_logger.log_error(ExecutionError(
                context=f"Resolve owner for {attr.securable_type.value} {attr.full_name}",
                exception=exc,
            ))
            result.add(SecurableAttributes(
                securable_type=attr.securable_type,
                full_name=attr.full_name,
                owner=None,
            ))
            continue
        result.add(SecurableAttributes(
            securable_type=attr.securable_type,
            full_name=attr.full_name,
            owner=resolved_owner,
        ))
    return result


def _diff_securables(
    desired: set[Securable],
    actual: set[Securable],
) -> tuple[list[Securable], list[Securable]]:
    """Return (to_create, to_replace) lists by keying on (securable_type, full_name)."""
    actual_by_key = {(s.securable_type, s.full_name): s for s in actual}

    to_create: list[Securable] = []
    to_replace: list[Securable] = []

    for desired_sec in desired:
        actual_sec = actual_by_key.get((desired_sec.securable_type, desired_sec.full_name))
        if actual_sec is None:
            to_create.append(desired_sec)
        elif desired_sec != actual_sec:
            to_replace.append(desired_sec)

    return to_create, to_replace


def _log_nonexistent_non_function_securables(
    to_create: list[Securable],
    change_logger: ChangeLogger,
) -> list[Securable]:
    """Log one ``NonexistentSecurableError`` per non-function securable in ``to_create``
    and return the list filtered down to Functions only.

    Functions are engine-created, so they legitimately flow through ``to_create`` for
    the executor to ``CREATE FUNCTION``. Any other type in ``to_create`` means the
    config references a UC object that does not yet exist; the engine does not
    support creating those today. We log each offender via ``ChangeLogger.log_error``
    (so the governor's final ``ExecutionBatchError`` gate surfaces them alongside
    any other accumulated errors) and drop them from the diff to prevent downstream
    executors from attempting to touch them.
    """
    nonexistent = sorted(
        [s for s in to_create if not isinstance(s, Function)],
        key=lambda s: (s.securable_type.value, s.full_name),
    )
    for sec in nonexistent:
        change_logger.log_error(ExecutionError(
            context=f"Existence check: {sec.securable_type.value} {sec.full_name}",
            exception=NonexistentSecurableError(sec.securable_type, sec.full_name),
        ))
    return [s for s in to_create if isinstance(s, Function)]


def _diff_attributes(
    desired_attrs: set[SecurableAttributes],
    actual_attrs: set[SecurableAttributes],
    created_full_names: set[str],
) -> list[AttributeUpdate]:
    """Return attribute updates by comparing desired vs actual attributes.

    For resolved Principals, equality uses dataclass field equality — two
    resolved principals with the same identifier + name + type compare equal.

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
            new_value = getattr(desired, attr)
            if new_value is None:
                continue

            old_value = getattr(actual, attr, None) if actual is not None else None
            if old_value == new_value:
                continue
            updates.append(AttributeUpdate(
                securable_type=desired.securable_type,
                full_name=desired.full_name,
                attribute=attr,
                old_value=old_value if old_value is not None else "",
                new_value=new_value,
            ))

    return updates
