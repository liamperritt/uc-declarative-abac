from __future__ import annotations

from uc_abac_governor.tags.state import SecurableTag, TagDiff


def compute_tag_diff(desired: set[SecurableTag], actual: set[SecurableTag]) -> TagDiff:
    """Compute the diff between desired and actual tags.

    Compares on (securable_type, securable_full_name, tag_name):
    - to_add: tag key not present in actual
    - to_update: tag key present in both but value differs (desired value shown)
    - to_remove: tag key present in actual but absent from desired
    """
    raise NotImplementedError
