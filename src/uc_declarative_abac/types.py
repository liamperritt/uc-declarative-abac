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
