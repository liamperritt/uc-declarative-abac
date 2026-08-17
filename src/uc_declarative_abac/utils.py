from __future__ import annotations

import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Literal, TypeVar

from uc_declarative_abac.types import SecurableType

T = TypeVar("T")
R = TypeVar("R")


def parallel_for_each(
    items: list[T],
    work_fn: Callable[[T], R],
    *,
    max_workers: int,
    on_complete: Callable[[T, R | None, Exception | None], None] | None = None,
) -> list[tuple[T, R | None, Exception | None]]:
    """Run ``work_fn`` on each item concurrently.

    The returned list of ``(item, result, error)`` triples is in **input order**,
    suitable for final aggregation. The optional ``on_complete`` callback fires
    once per item, **on the main thread**, the moment each worker finishes —
    use it to stream progress to the operator instead of waiting for the whole
    batch to drain. Workers themselves never touch shared state, so
    ``ChangeLogger`` does not need to be thread-safe.

    Falls through to sequential iteration when ``max_workers <= 1`` or when
    there is at most one item, avoiding ``ThreadPoolExecutor`` overhead.
    """
    if not items:
        return []
    if max_workers <= 1 or len(items) <= 1:
        results: list[tuple[T, R | None, Exception | None]] = []
        for item in items:
            triple = _invoke(item, work_fn)
            if on_complete is not None:
                on_complete(*triple)
            results.append(triple)
        return results
    by_index: dict[int, tuple[T, R | None, Exception | None]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_idx: dict = {
            pool.submit(work_fn, item): (idx, item) for idx, item in enumerate(items)
        }
        for future in as_completed(future_to_idx):
            idx, item = future_to_idx[future]
            error = future.exception()
            if error is not None:
                triple = (item, None, error)
            else:
                triple = (item, future.result(), None)
            if on_complete is not None:
                on_complete(*triple)
            by_index[idx] = triple
    return [by_index[i] for i in range(len(items))]


def _invoke(item: T, work_fn: Callable[[T], R]) -> tuple[T, R | None, Exception | None]:
    try:
        return (item, work_fn(item), None)
    except Exception as exc:  # noqa: BLE001 — capture any worker failure for the caller
        return (item, None, exc)


RfaDestinationKind = Literal["EMAIL", "URL", "GUID"]

_RFA_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_RFA_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_RFA_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def quote_securable(full_name: str) -> str:
    """Backtick-quote each segment of a dot-delimited securable name."""
    return ".".join(f"`{seg}`" for seg in full_name.split("."))


def catalog_of(full_name: str) -> str:
    """Return the catalog component of a UC ``full_name``.

    Splits on the first ``.`` so any full name shape — ``catalog``,
    ``catalog.schema``, ``catalog.schema.table``, ``catalog.schema.table.column`` —
    yields the catalog. Inputs without a ``.`` are returned unchanged.
    """
    return full_name.split(".", 1)[0]


def in_namespace_scope(full_name: str, scope: frozenset[str]) -> bool:
    """Return whether a UC ``full_name`` falls at or below any namespace in ``scope``.

    A namespace in ``scope`` is either a bare catalog name (covers everything
    under that catalog) or a qualified ``catalog.schema`` name (covers that schema
    and its children, but not the catalog above it). A ``full_name`` matches when
    its catalog is in ``scope`` or its two-segment ``catalog.schema`` prefix is in
    ``scope``. An empty ``scope`` matches nothing.
    """
    parts = full_name.split(".")
    if parts[0] in scope:
        return True
    return len(parts) >= 2 and ".".join(parts[:2]) in scope


def parse_namespace_filter(
    spec: str, configured_namespaces: set[str]
) -> frozenset[str]:
    """Parse a comma-separated namespace filter spec.

    Each entry is either a bare catalog name or a qualified ``catalog.schema``
    name. ``"*"`` expands to every configured catalog (whole-catalog scope, the
    default). Otherwise the spec is split on commas, whitespace-trimmed, and each
    entry validated against ``configured_namespaces`` — the set of configured
    catalog names plus every configured ``catalog.schema`` full name. Any entry
    not present raises ``ValueError`` listing every offender so typos surface early.
    """
    configured_catalogs = sorted(n for n in configured_namespaces if "." not in n)
    if spec.strip() == "*":
        return frozenset(configured_catalogs)
    names = [n.strip() for n in spec.split(",") if n.strip()]
    unknown = [n for n in names if n not in configured_namespaces]
    if unknown:
        configured_list = (
            ", ".join(configured_catalogs) if configured_catalogs else "(none)"
        )
        raise ValueError(
            f"Namespace filter references unknown catalog(s) or schema(s): "
            f"{', '.join(unknown)}. Configured catalogs: {configured_list}"
        )
    return frozenset(names)


def _match_rfa_destination(value: str) -> RfaDestinationKind | None:
    """Return the kind of RFA destination, or None if no regex matches."""
    if _RFA_EMAIL_RE.match(value):
        return "EMAIL"
    if _RFA_URL_RE.match(value):
        return "URL"
    if _RFA_GUID_RE.match(value):
        return "GUID"
    return None


def classify_rfa_destination(value: str) -> RfaDestinationKind:
    """Classify an RFA destination string as ``EMAIL``, ``URL``, or ``GUID``.

    Matches the three accepted forms by regex. Anything else raises
    ``ValueError`` whose message echoes the offending value so the operator
    can find and fix it in YAML.
    """
    kind = _match_rfa_destination(value)
    if kind is None:
        raise ValueError(
            f"Unrecognised RFA destination {value!r}: must be an email address, "
            f"an http(s) URL, or a Databricks notification destination UUID."
        )
    return kind


def validate_rfa_destinations(values: list[str]) -> list[str]:
    """Classify every entry in ``values``; raise once with all offenders listed.

    Returns the input list unchanged on success. On failure, raises a single
    ``ValueError`` whose message names every invalid entry so multiple typos
    surface together rather than one-at-a-time.
    """
    invalid = [v for v in values if _match_rfa_destination(v) is None]
    if invalid:
        offenders = ", ".join(repr(v) for v in invalid)
        raise ValueError(
            f"Unrecognised RFA destination(s): {offenders}. Each entry must be "
            f"an email address, an http(s) URL, or a Databricks notification "
            f"destination UUID."
        )
    return values


def is_system_governed_tag(name: str) -> bool:
    """Return True if a governed tag is Databricks system-managed.

    System governed tag keys always contain a ``.`` (e.g. ``class.email_address``,
    ``system.certification_status``); user-defined tag keys never do. System tags
    cannot be created, deleted, or have their definition (description/allowed_values)
    edited — only their assigners are managed. This is the single source of truth for
    that classification, shared by the config model and the governed-tags differ.
    """
    return "." in name


# Account-level system groups that are Databricks-owned: they cannot be deleted by
# this engine (and are near-universally useful as policy targets). Single source of
# truth, shared by the workspace helper (which surfaces them in workspace-SCIM mode)
# and the group differ (which excludes them from deletion candidates).
SYSTEM_ACCOUNT_GROUPS = frozenset({"account users", "account admins"})


def is_system_account_group(name: str) -> bool:
    """Return True if a group is a Databricks account system group.

    Account system groups (``account users``, ``account admins``) are Databricks-owned
    and cannot be deleted by this engine — like external (IdP-provisioned) groups, they
    are never group-deletion candidates. Matched case-insensitively.
    """
    return name.lower() in SYSTEM_ACCOUNT_GROUPS


def prompt_delete_confirmation(names: list[str], noun: str, warning: str) -> bool:
    """Show the items slated for deletion and require interactive confirmation.

    ``noun`` names the item type (e.g. ``"governed tag"``, ``"group"``) for the header,
    and ``warning`` is the one-line consequence shown before the prompt. Accepts ``y``
    or ``yes`` (case-insensitive) as affirmative; anything else aborts. Re-raises
    ``EOFError`` (e.g. a non-TTY input stream) as ``InteractiveConfirmationRequiredError``
    so CI contexts get a clear "set --force" directive instead of a silent skip. Shared
    by the governed-tag and group deletion executors.
    """
    print(f"\nAbout to delete {len(names)} {noun}(s):")
    for name in names:
        print(f"  - {name}")
    print()
    try:
        response = input(f"{warning} Confirm [y/N]: ")
    except EOFError as exc:
        raise InteractiveConfirmationRequiredError(
            "Cannot prompt for confirmation in a non-interactive context. "
            "Set --force to auto-confirm destructive actions."
        ) from exc
    return response.strip().lower() in {"y", "yes"}


class OrchestratorError(Exception):
    """Base exception for all orchestrator errors."""


class ResolutionError(OrchestratorError):
    """Raised when a $ref cannot be resolved (missing key, circular ref, etc.)."""


class DuplicateKeyError(OrchestratorError):
    """Raised when duplicate definition keys are found across YAML files."""


class DuplicateResourceError(OrchestratorError):
    """Raised when duplicate resource names are detected within the same parent."""


class UnreferencedDefinitionError(OrchestratorError):
    """Raised when definitions exist that are not referenced by any $ref."""


class TemplateVariableError(OrchestratorError):
    """Raised for template-variable (``$vars`` / ``{{ placeholder }}``) errors.

    Covers every failure mode of the template-variables feature: an incomplete
    definition ``$vars`` signature (a body placeholder left undeclared, or a
    declared variable the body never uses), a ``$ref`` that fails to supply a
    required variable (missing) or supplies one the template does not use
    (unused), a non-string ``$vars`` value, and a ``{{ placeholder }}`` in a
    value not bound by any ``$ref``.
    """


class PrincipalValidationError(OrchestratorError):
    """Raised when one or more principal names cannot be found in the account."""


class UngovernedTagError(OrchestratorError):
    """Raised when a policy references an ungoverned tag key — i.e. a key
    that is not declared as a governed tag in the config's desired governed
    tags nor present in UC's actual governed tags. Only the tag key is
    checked — values are not validated."""


class DisallowedTagValueError(OrchestratorError):
    """Raised when a securable tag assignment uses a governed tag key but the
    assigned value is not in the governed tag's ``allowed_values``. A governed
    tag with empty ``allowed_values`` accepts any value and does not trigger
    this error."""


class DuplicateServicePrincipalError(OrchestratorError):
    """Raised when two service principals share the same display name."""


class InteractiveConfirmationRequiredError(OrchestratorError):
    """Raised when the engine needs an interactive confirmation but no TTY is attached.

    Surfaces as a hard, immediate error (not accumulated via ChangeLogger) because the
    engine cannot safely proceed with a destructive action (e.g. governed-tag deletion)
    without an explicit human confirm. The caller must set ``--force`` in non-interactive
    contexts (CI, scripted runs) to auto-confirm.
    """


class NonexistentSecurableError(OrchestratorError):
    """Raised when a securable declared in config doesn't exist in UC.

    Functions are created by the engine and are excluded from this check; only
    catalogs, schemas, tables, and volumes can trigger this error. One instance
    carries a single (type, full_name) pair — the engine logs one per offender
    via ``ChangeLogger.log_error`` and the orchestrator surfaces them together via
    ``ExecutionBatchError`` at the end of the run.

    An optional ``hint`` string is appended to the stock message — used by the
    table-creation validator to explain why an otherwise-createable table can't
    be created (e.g. missing columns or missing column types).
    """

    def __init__(
        self,
        securable_type: SecurableType,
        full_name: str,
        hint: str | None = None,
    ) -> None:
        self.securable_type = securable_type
        self.full_name = full_name
        self.hint = hint
        base = (
            f"Nonexistent {securable_type.value} {full_name!r} declared in config but "
            f"not found in Unity Catalog."
        )
        if hint:
            # A hint means a downstream validator ran (typically with the
            # creation flag already on) and identified a specific blocker.
            # The hint is the actionable advice; suggesting the flag here
            # would be redundant (the user has already set it).
            message = f"{base} {hint}"
        else:
            message = (
                f"{base} Please add the --enable-taggable-creation flag to have "
                "the engine create it, or remove it from config."
            )
        super().__init__(message)


@dataclass(frozen=True)
class ExecutionError:
    """A single error that occurred during SQL execution."""

    context: str
    exception: Exception


class ExecutionBatchError(OrchestratorError):
    """Raised after execution completes when one or more SQL statements failed."""

    def __init__(self, errors: list[ExecutionError]) -> None:
        self.errors = errors
        super().__init__(self._build_message())

    def _build_message(self) -> str:
        lines = [f"{len(self.errors)} SQL statement(s) failed during execution:"]
        for err in self.errors:
            lines.append(f"  - {err.context}: {err.exception}")
        return "\n".join(lines)
