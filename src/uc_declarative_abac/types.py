from __future__ import annotations

from enum import Enum


class SecurableType(str, Enum):
    CATALOG = "CATALOG"
    SCHEMA = "SCHEMA"
    TABLE = "TABLE"
    VOLUME = "VOLUME"
    FUNCTION = "FUNCTION"
    COLUMN = "COLUMN"


class PrivilegeType(str, Enum):
    SELECT = "select"
    MODIFY = "modify"
    CREATE_TABLE = "create_table"
    CREATE_SCHEMA = "create_schema"
    CREATE_FUNCTION = "create_function"
    CREATE_VOLUME = "create_volume"
    USE_CATALOG = "use_catalog"
    USE_SCHEMA = "use_schema"
    READ_VOLUME = "read_volume"
    WRITE_VOLUME = "write_volume"
    EXECUTE = "execute"
    ALL_PRIVILEGES = "all_privileges"
    EXTERNAL_USE_SCHEMA = "external_use_schema"
    MANAGE = "manage"
    REFRESH = "refresh"
    CREATE_MATERIALIZED_VIEW = "create_materialized_view"
    CREATE_MODEL = "create_model"
    CREATE_MODEL_VERSION = "create_model_version"
    BROWSE = "browse"


class AbstractedPrivilegeType(str, Enum):
    """Shorthand for a fixed set of UC privileges. Accepted anywhere a
    ``PrivilegeType`` is accepted in a grant policy's ``privileges:`` list."""
    READ = "read"
    EDIT = "edit"
    USE = "use"
    CREATE = "create"


class PolicyType(str, Enum):
    GRANT = "grant"
    MASK = "mask"
    FILTER = "filter"


class PrincipalType(str, Enum):
    USER = "USER"
    GROUP = "GROUP"
    SERVICE_PRINCIPAL = "SERVICE_PRINCIPAL"
    UNKNOWN = "UNKNOWN"  # marks an unresolved Principal


# Privileges valid for each securable type. Higher-level securables inherit
# all privileges from lower levels. Unknown privileges are allowed on all types.
_TABLE_PRIVILEGES = {PrivilegeType.SELECT, PrivilegeType.MODIFY}
_VOLUME_PRIVILEGES = {PrivilegeType.READ_VOLUME, PrivilegeType.WRITE_VOLUME}
_SCHEMA_PRIVILEGES = (
    _TABLE_PRIVILEGES
    | _VOLUME_PRIVILEGES
    | {
        PrivilegeType.USE_SCHEMA,
        PrivilegeType.CREATE_TABLE,
        PrivilegeType.CREATE_FUNCTION,
        PrivilegeType.CREATE_VOLUME,
        PrivilegeType.EXECUTE,
        PrivilegeType.EXTERNAL_USE_SCHEMA,
        PrivilegeType.CREATE_MATERIALIZED_VIEW,
        PrivilegeType.REFRESH,
        PrivilegeType.CREATE_MODEL,
        PrivilegeType.CREATE_MODEL_VERSION,
    }
)
_CATALOG_PRIVILEGES = _SCHEMA_PRIVILEGES | {PrivilegeType.USE_CATALOG, PrivilegeType.CREATE_SCHEMA, PrivilegeType.BROWSE}
_UNIVERSAL_PRIVILEGES = {PrivilegeType.ALL_PRIVILEGES, PrivilegeType.MANAGE}

SECURABLE_TYPE_PRIVILEGE_MAP: dict[SecurableType, set[PrivilegeType]] = {
    SecurableType.CATALOG: _CATALOG_PRIVILEGES | _UNIVERSAL_PRIVILEGES,
    SecurableType.SCHEMA: _SCHEMA_PRIVILEGES | _UNIVERSAL_PRIVILEGES,
    SecurableType.TABLE: _TABLE_PRIVILEGES | _UNIVERSAL_PRIVILEGES,
    SecurableType.VOLUME: _VOLUME_PRIVILEGES | _UNIVERSAL_PRIVILEGES,
    # Unity Catalog does not support column-level GRANT/REVOKE. Column tags are
    # excluded upstream in _build_tag_index, so a COLUMN securable never reaches
    # matching or this map. This empty set is kept as a defensive guard: were a
    # COLUMN target ever to appear, the compatibility filter in _emit_privileges
    # would drop every privilege targeted at it.
    SecurableType.COLUMN: frozenset(),
}

ABSTRACT_PRIVILEGE_MAP: dict[AbstractedPrivilegeType, frozenset[PrivilegeType]] = {
    AbstractedPrivilegeType.READ: frozenset({
        PrivilegeType.SELECT,
        PrivilegeType.READ_VOLUME,
        PrivilegeType.EXECUTE,
    }),
    AbstractedPrivilegeType.EDIT: frozenset({
        PrivilegeType.MODIFY,
        PrivilegeType.WRITE_VOLUME,
        PrivilegeType.REFRESH,
    }),
    AbstractedPrivilegeType.USE: frozenset({
        PrivilegeType.USE_CATALOG,
        PrivilegeType.USE_SCHEMA,
    }),
    AbstractedPrivilegeType.CREATE: frozenset({
        PrivilegeType.CREATE_TABLE,
        PrivilegeType.CREATE_SCHEMA,
        PrivilegeType.CREATE_FUNCTION,
        PrivilegeType.CREATE_VOLUME,
        PrivilegeType.CREATE_MATERIALIZED_VIEW,
        PrivilegeType.CREATE_MODEL,
        PrivilegeType.CREATE_MODEL_VERSION,
    }),
}
