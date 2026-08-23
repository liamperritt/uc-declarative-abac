from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any, Literal, TypeVar
from zoneinfo import ZoneInfo

import yaml

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


@dataclass(frozen=True)
class _ScopeEntry:
    """One parsed scope entry, retaining its source text for diagnostics.

    ``is_prefix`` entries came from a trailing ``*`` and match by ``startswith``
    on ``match_value`` (the text before the ``*``). Non-prefix entries match the
    exact ``match_value``; for ``hierarchical`` scopes they additionally match
    the entry's dotted subtree (downward inheritance).
    """

    source: str
    match_value: str
    is_prefix: bool
    hierarchical: bool

    def matches(self, identifier: str) -> bool:
        if self.is_prefix:
            return identifier.startswith(self.match_value)
        if identifier == self.match_value:
            return True
        return self.hierarchical and identifier.startswith(f"{self.match_value}.")


@dataclass(frozen=True)
class Scope:
    """Resolved per-feature scope: which resources a feature applies to.

    Built from a comma-separated spec via ``parse_hierarchical_scope`` (dotted
    securable full names, with downward inheritance) or ``parse_flat_scope``
    (atomic identifiers such as group display names / governed-tag names). An
    empty ``Scope`` (no entries) matches nothing — the representation of a
    disabled feature. ``"*"`` yields a single match-everything entry.
    """

    entries: tuple[_ScopeEntry, ...] = ()

    def is_active(self) -> bool:
        """True when the scope has any entry (i.e. the feature is enabled)."""
        return bool(self.entries)

    def matches(self, identifier: str) -> bool:
        """True when ``identifier`` is matched by any entry."""
        return any(entry.matches(identifier) for entry in self.entries)

    def unmatched_entries(self, universe: Iterable[str]) -> list[str]:
        """Return the source text of entries that match nothing in ``universe``.

        Used to warn (never fail) about likely typos in a new-style scope. Order
        follows the original spec; ``"*"`` only appears when ``universe`` is empty.
        """
        candidates = list(universe)
        return [
            entry.source
            for entry in self.entries
            if not any(entry.matches(item) for item in candidates)
        ]


def _parse_scope_entry(token: str, *, hierarchical: bool) -> _ScopeEntry:
    star_count = token.count("*")
    if star_count == 0:
        return _ScopeEntry(
            source=token, match_value=token, is_prefix=False, hierarchical=hierarchical
        )
    if star_count > 1 or not token.endswith("*"):
        raise ValueError(
            f"Invalid scope entry {token!r}: '*' is only allowed as the final "
            f"character (e.g. 'main.*' or 'main.salesforce*'). Leading or middle "
            f"wildcards are not supported."
        )
    return _ScopeEntry(
        source=token, match_value=token[:-1], is_prefix=True, hierarchical=hierarchical
    )


def _parse_scope(spec: str | None, *, hierarchical: bool) -> Scope:
    if not spec or not spec.strip():
        return Scope()
    entries = [
        _parse_scope_entry(token.strip(), hierarchical=hierarchical)
        for token in spec.split(",")
        if token.strip()
    ]
    return Scope(entries=tuple(entries))


def parse_hierarchical_scope(spec: str | None) -> Scope:
    """Parse a securable-domain scope spec (dotted full names, with inheritance).

    Empty/whitespace ⇒ disabled. ``"*"`` ⇒ everything. A trailing ``*`` is a raw
    string prefix (``main.*`` ⇒ descendants of ``main``; ``main.salesforce*`` ⇒
    the ``salesforce*`` schemas and their subtrees). An entry without ``*``
    matches the exact node and its subtree (``main`` ⇒ the catalog and everything
    under it, but not ``maintenance``). Wildcards are permitted only as the final
    character; leading/middle wildcards raise ``ValueError``.
    """
    return _parse_scope(spec, hierarchical=True)


def parse_flat_scope(spec: str | None) -> Scope:
    """Parse a flat-domain scope spec (group display names / governed-tag names).

    Identifiers are atomic — dots are literal and there is no inheritance. Empty
    ⇒ disabled; ``"*"`` ⇒ all; ``prefix*`` ⇒ names with that raw prefix; anything
    else ⇒ that exact name. Wildcards are permitted only as the final character.
    """
    return _parse_scope(spec, hierarchical=False)


def scope_from_namespace_tokens(tokens: Iterable[str]) -> Scope:
    """Build a hierarchical ``Scope`` from resolved legacy namespace tokens.

    Each token is a catalog or ``catalog.schema`` name (as validated/expanded by
    ``parse_namespace_filter``). The resulting scope is equivalent to the legacy
    ``in_namespace_scope`` predicate over the same token set — this is what lets
    the deprecated ``*-for-namespaces`` flags share the new matcher without any
    behaviour change.
    """
    return Scope(
        entries=tuple(
            _ScopeEntry(
                source=token, match_value=token, is_prefix=False, hierarchical=True
            )
            for token in tokens
        )
    )


def run_date_for_timezone(timezone: str) -> date:
    """Today's date in the given IANA timezone (e.g. 'Australia/Melbourne')."""
    return datetime.now(ZoneInfo(timezone)).date()


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
    """Raised for a duplicate mapping key in a YAML config.

    Covers a key repeated within a single file (caught at parse time by the strict
    loader, at any nesting depth) as well as duplicate definition keys found across
    files during the definitions/resources merge."""


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
    resource value (resources are the concrete instance layer — placeholders are
    bound by the enclosing definition's ``$vars`` and belong inside definitions).
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
                f"{base} Please add its namespace to --taggable-creation-scopes "
                "to have the engine create it, or remove it from config."
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


class UniqueKeySafeLoader(yaml.SafeLoader):
    """A ``SafeLoader`` that rejects duplicate mapping keys.

    PyYAML's default behaviour is to silently keep the last value when a mapping
    repeats a key — a dangerous footgun for a config-driven governance tool, where
    an accidental duplicate would deploy a silently-different result. This loader
    raises ``DuplicateKeyError`` on the first repeated key instead. The check runs
    inside ``construct_mapping``, which fires for *every* mapping node, so a
    duplicate is caught at any nesting depth (top level, ``definitions`` /
    ``resources``, a policy's ``tags``, a column map, etc.).
    """

    def construct_mapping(self, node, deep=False):  # type: ignore[override]
        seen: set = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                mark = key_node.start_mark
                raise DuplicateKeyError(
                    f"Duplicate key {key!r} at line {mark.line + 1}, "
                    f"column {mark.column + 1}"
                )
            seen.add(key)
        # Delegate to the base implementation for the actual, type-correct mapping
        # (it re-uses the objects already constructed above via PyYAML's cache).
        return super().construct_mapping(node, deep)


def load_yaml_file(path: Path) -> Any:
    """Parse a YAML file, failing loudly on duplicate mapping keys.

    A ``DuplicateKeyError`` raised by :class:`UniqueKeySafeLoader` is re-raised with
    the file path appended so the message points the author at the offending file
    and line. Other ``yaml.YAMLError`` variants (malformed YAML) propagate unchanged
    and are handled at the CLI boundary.
    """
    with open(path, encoding="utf-8") as f:
        try:
            return yaml.load(f, Loader=UniqueKeySafeLoader)
        except DuplicateKeyError as exc:
            raise DuplicateKeyError(f"{exc} in {path}") from exc
