from __future__ import annotations

from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from uc_declarative_abac.helpers.workspace import WorkspaceHelper

from uc_declarative_abac.principals.state import Principal
from uc_declarative_abac.types import GovernorError, PrincipalType, PrincipalValidationError


class PrincipalResolver:
    """Resolves Principal objects against the WorkspaceHelper principal cache.

    A Principal is resolved by looking up the workspace for the identifying
    string it carries:
    - name-only (identifier empty) → lookup by display name
    - identifier-only (name empty) → lookup by identifier
    - both set, type=UNKNOWN       → lookup by name
    - type != UNKNOWN              → already resolved, returned as-is

    Unknown principals raise PrincipalValidationError.
    """

    def __init__(self, ws_helper: WorkspaceHelper) -> None:
        self._ws_helper = ws_helper

    def resolve_principal(self, principal: Principal) -> Principal:
        """Resolve one Principal. Raises PrincipalValidationError on failure."""
        if principal.principal_type != PrincipalType.UNKNOWN:
            return principal
        if principal.name:
            return self._ws_helper.resolve_by_name(principal.name)
        return self._ws_helper.resolve_by_identifier(principal.identifier)

    def resolve_principals(self, principals: Iterable[Principal]) -> list[Principal]:
        """Resolve a batch of Principals. All-or-nothing.

        If any principal fails, raises a single PrincipalValidationError whose
        message lists every failure (never partial).
        """
        resolved: list[Principal] = []
        failures: list[tuple[Principal, PrincipalValidationError]] = []
        for p in principals:
            try:
                resolved.append(self.resolve_principal(p))
            except PrincipalValidationError as exc:
                failures.append((p, exc))
        if failures:
            raise PrincipalValidationError(_format_batch_failure(failures))
        return resolved


def ensure_resolved(principal: Principal) -> Principal:
    """Runtime guard: raise GovernorError if principal is not resolved."""
    if principal.principal_type == PrincipalType.UNKNOWN:
        raise GovernorError(
            f"Expected a resolved Principal but got UNKNOWN type: {principal!r}"
        )
    if not principal.name or not principal.identifier:
        raise GovernorError(
            f"Expected a resolved Principal with both name and identifier: {principal!r}"
        )
    return principal


def ensure_all_resolved(principals: Iterable[Principal]) -> list[Principal]:
    """Map ensure_resolved over a collection. Raises on the first unresolved."""
    return [ensure_resolved(p) for p in principals]


def _format_batch_failure(
    failures: list[tuple[Principal, PrincipalValidationError]],
) -> str:
    count = len(failures)
    descriptions = [_describe_failed_principal(p) for p, _ in failures]
    return f"Failed to resolve {count} principal(s): [{', '.join(descriptions)}]"


def _describe_failed_principal(principal: Principal) -> str:
    if principal.name:
        return f"'{principal.name}' (name)"
    return f"'{principal.identifier}' (identifier)"
