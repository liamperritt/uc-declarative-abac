from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from uc_declarative_abac.types import SecurableType


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


def parse_catalog_filter(spec: str, configured_catalogs: list[str]) -> frozenset[str]:
    """Parse a comma-separated catalog filter spec.

    ``"*"`` expands to every name in ``configured_catalogs``. Otherwise the spec
    is split on commas, whitespace-trimmed, and validated against
    ``configured_catalogs``. Any name not present raises ``ValueError`` listing
    every offender so typos surface early.
    """
    if spec.strip() == "*":
        return frozenset(configured_catalogs)
    names = [n.strip() for n in spec.split(",") if n.strip()]
    configured_set = set(configured_catalogs)
    unknown = [n for n in names if n not in configured_set]
    if unknown:
        configured_list = ", ".join(configured_catalogs) if configured_catalogs else "(none)"
        raise ValueError(
            f"Catalog filter references unknown catalog(s): {', '.join(unknown)}. "
            f"Configured catalogs: {configured_list}"
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
