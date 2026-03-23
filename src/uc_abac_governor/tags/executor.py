from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uc_abac_governor.helpers.unity_catalog import UnityCatalogHelper

from uc_abac_governor.tags.state import TagDiff


def execute_tag_diff(uc_helper: UnityCatalogHelper, diff: TagDiff) -> list[str]:
    """Generate and execute ALTER SET/UNSET TAGS SQL from a TagDiff.

    Batches tags per securable where possible.
    Returns the list of SQL statements executed.
    """
    raise NotImplementedError
