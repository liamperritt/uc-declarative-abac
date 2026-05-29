from __future__ import annotations

from uc_declarative_abac.configs import (
    ResourcesConfig,
    TaggableConfig,
)
from uc_declarative_abac.governed_tags import GovernedTag
from uc_declarative_abac.logger import ChangeLogger
from uc_declarative_abac.tags.state import SecurableTag
from uc_declarative_abac.types import SecurableType
from uc_declarative_abac.utils import (
    DisallowedTagValueError,
    ExecutionError,
)


def _emit_tags(
    securable_type: SecurableType,
    full_name: str,
    obj: TaggableConfig,
) -> set[SecurableTag]:
    """Return a SecurableTag for each tag on the object, or an empty set."""
    if not obj.tags:
        return set()
    return {
        SecurableTag(
            securable_type=securable_type,
            securable_full_name=full_name,
            tag_name=key,
            tag_value=value,
        )
        for key, value in obj.tags.items()
    }


def _allowed_values_by_name(
    governed_tags: set[GovernedTag],
) -> dict[str, frozenset[str]]:
    """Return ``name → allowed_values`` for governed tags that constrain values.

    Governed tags whose ``allowed_values`` is empty are omitted: an empty
    constraint means any value is allowed, so they don't participate in
    validation.
    """
    return {
        gt.name: gt.allowed_values
        for gt in governed_tags
        if gt.allowed_values
    }


def _is_value_allowed(
    tag: SecurableTag,
    allowed_by_name: dict[str, frozenset[str]],
) -> bool:
    """Whether ``tag`` passes governed-tag value validation.

    Tags whose name is not in ``allowed_by_name`` are unconstrained and pass.
    Otherwise the tag's value must be in the governed tag's allowed values.
    """
    allowed = allowed_by_name.get(tag.tag_name)
    if allowed is None:
        return True
    return tag.tag_value in allowed


def _log_disallowed_value(
    tag: SecurableTag,
    allowed: frozenset[str],
    change_logger: ChangeLogger,
) -> None:
    """Log one DisallowedTagValueError for an invalid governed-tag assignment."""
    context = (
        f"Tag '{tag.tag_name}' on {tag.securable_type.value} "
        f"{tag.securable_full_name}"
    )
    change_logger.log_error(ExecutionError(
        context=context,
        exception=DisallowedTagValueError(
            f"{context} uses value '{tag.tag_value}' which is not in "
            f"allowed_values {sorted(allowed)} for governed tag "
            f"'{tag.tag_name}'"
        ),
    ))


def _validate_against_governed(
    tags: set[SecurableTag],
    governed_tags: set[GovernedTag],
    change_logger: ChangeLogger,
) -> set[SecurableTag]:
    """Drop tags whose value violates a governed tag's allowed_values.

    Each offender is logged once via ``change_logger``. Tags that pass (or
    that don't reference any value-constrained governed tag) are returned
    unchanged.
    """
    allowed_by_name = _allowed_values_by_name(governed_tags)
    kept: set[SecurableTag] = set()
    for tag in tags:
        if _is_value_allowed(tag, allowed_by_name):
            kept.add(tag)
        else:
            _log_disallowed_value(tag, allowed_by_name[tag.tag_name], change_logger)
    return kept


def compile_desired_tags(
    config: ResourcesConfig,
    governed_tags: set[GovernedTag],
    change_logger: ChangeLogger,
) -> set[SecurableTag]:
    """Walk the resolved config and emit SecurableTag entries for all tagged objects.

    Produces tags for catalogs, schemas, tables, volumes, and columns.

    A tag whose key matches a governed tag with non-empty ``allowed_values``
    must use a value in that set — otherwise a ``DisallowedTagValueError`` is
    logged on ``change_logger`` and the offending tag is dropped from the
    returned set.
    """
    tags: set[SecurableTag] = set()

    for catalog in config.catalogs.values():
        tags |= _emit_tags(SecurableType.CATALOG, catalog.full_name, catalog)

        for schema in catalog.schemas or []:
            tags |= _emit_tags(SecurableType.SCHEMA, schema.full_name, schema)

            for table in schema.tables or []:
                tags |= _emit_tags(SecurableType.TABLE, table.full_name, table)
                for col in table.columns or []:
                    tags |= _emit_tags(SecurableType.COLUMN, col.full_name, col)

            for volume in schema.volumes or []:
                tags |= _emit_tags(SecurableType.VOLUME, volume.full_name, volume)

    return _validate_against_governed(tags, governed_tags, change_logger)
