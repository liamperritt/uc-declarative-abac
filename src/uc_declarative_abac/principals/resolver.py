from __future__ import annotations

from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from uc_declarative_abac.helpers import WorkspaceHelper
    from uc_declarative_abac.logger import ChangeLogger

from uc_declarative_abac.principals.state import Principal
from uc_declarative_abac.utils import (
    ExecutionError,
    OrchestratorError,
    PrincipalValidationError,
)
from uc_declarative_abac.types import PrincipalType


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


def log_principal_resolution_failure(
    change_logger: "ChangeLogger",
    context: str,
    principal: Principal,
    exc: PrincipalValidationError,
    ignore_unresolvable: frozenset[str] = frozenset(),
) -> None:
    """Route a principal-resolution failure to the change logger.

    Actual-state (UC-side, identifier-only) principals are logged as non-fatal
    warnings: they aren't part of the config and can't be acted on — e.g.
    Databricks-managed system/application service principals (predictive
    optimization, scheduled dashboard refresh) that appear in system tables but
    aren't returned by SCIM. They are dropped from the diff without failing the
    run. Config-side (desired) failures — which carry a display name — remain
    fatal errors so config typos still surface loudly.

    ``ignore_unresolvable`` is the set of actual-state identifiers from
    ``--ignore-unresolvable-principals`` whose resolution-failure warning should
    be silenced. It affects only the warning (actual-state) branch — the row is
    still dropped from the diff, just without the log line. Config-side failures
    stay fatal regardless (the set holds identifiers; config principals carry a
    name and never match).
    """
    error = ExecutionError(context=context, exception=exc)
    if principal.identifier and not principal.name:
        if principal.identifier in ignore_unresolvable:
            return
        change_logger.log_warning(error)
    else:
        change_logger.log_error(error)


def ensure_resolved(principal: Principal) -> Principal:
    """Runtime guard: raise OrchestratorError if principal is not resolved."""
    if principal.principal_type == PrincipalType.UNKNOWN:
        raise OrchestratorError(
            f"Expected a resolved Principal but got UNKNOWN type: {principal!r}"
        )
    if not principal.name or not principal.identifier:
        raise OrchestratorError(
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
