from __future__ import annotations


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
