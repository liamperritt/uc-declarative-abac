from __future__ import annotations

from uc_declarative_abac.tags.state import (
    SecurableTag,
    TagDiff,
)


def filter_retained_removals(
    diff: TagDiff, retain_prefixes: frozenset[str],
) -> tuple[TagDiff, set[SecurableTag]]:
    """Strip removals whose tag key starts with any retained prefix.

    Returns a new ``TagDiff`` whose ``to_remove`` excludes any tag whose
    ``tag_name`` starts with one of ``retain_prefixes``, together with the set
    of tags that were retained. ``to_add``, ``to_update`` and ``old_values`` are
    carried through untouched — retention only blocks removals, never additions
    or updates. An empty ``retain_prefixes`` is a no-op (the diff is returned
    unchanged and nothing is retained).
    """
    if not retain_prefixes:
        return diff, set()

    retained = {
        tag for tag in diff.to_remove
        if any(tag.tag_name.startswith(prefix) for prefix in retain_prefixes)
    }
    if not retained:
        return diff, set()

    new_diff = TagDiff(
        to_add=diff.to_add,
        to_update=diff.to_update,
        to_remove=diff.to_remove - retained,
        old_values=diff.old_values,
    )
    return new_diff, retained


def compute_tag_diff(desired: set[SecurableTag], actual: set[SecurableTag]) -> TagDiff:
    """Compute the diff between desired and actual tags.

    Compares on (securable_type, securable_full_name, tag_name):
    - to_add: tag key not present in actual
    - to_update: tag key present in both but value differs (desired value shown)
    - to_remove: tag key present in actual but absent from desired
    """
    def _tag_key(tag: SecurableTag) -> tuple:
        return (tag.securable_type, tag.securable_full_name, tag.tag_name)

    desired_by_key = {_tag_key(t): t for t in desired}
    actual_by_key = {_tag_key(t): t for t in actual}

    desired_keys = desired_by_key.keys()
    actual_keys = actual_by_key.keys()

    to_add = {desired_by_key[k] for k in desired_keys - actual_keys}
    to_remove = {actual_by_key[k] for k in actual_keys - desired_keys}
    update_keys = {
        k for k in desired_keys & actual_keys
        if desired_by_key[k].tag_value != actual_by_key[k].tag_value
    }
    to_update = {desired_by_key[k] for k in update_keys}
    old_values = {k: actual_by_key[k].tag_value for k in update_keys}

    return TagDiff(to_add=to_add, to_update=to_update, to_remove=to_remove, old_values=old_values)
