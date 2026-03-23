from __future__ import annotations

from uc_abac_governor.models import ConfigFile
from uc_abac_governor.tags.state import SecurableTag


def compile_desired_tags(config: ConfigFile) -> set[SecurableTag]:
    """Walk the resolved config and emit SecurableTag entries for all tagged objects.

    Produces tags for catalogs, schemas, tables, and volumes.
    Uses the dict key as the object name when name is omitted.
    """
    raise NotImplementedError
