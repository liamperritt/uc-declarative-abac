from __future__ import annotations

import re
from typing import Literal


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
