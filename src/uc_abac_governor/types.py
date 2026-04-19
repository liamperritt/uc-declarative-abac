from __future__ import annotations

from dataclasses import dataclass
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


class PolicyType(str, Enum):
    GRANT = "grant"
    MASK = "mask"
    FILTER = "filter"


class PrincipalType(str, Enum):
    USER = "USER"
    GROUP = "GROUP"
    SERVICE_PRINCIPAL = "SERVICE_PRINCIPAL"
    UNKNOWN = "UNKNOWN"  # marks an unresolved Principal


class GovernorError(Exception):
    """Base exception for all governor errors."""


class ResolutionError(GovernorError):
    """Raised when a $ref cannot be resolved (missing key, circular ref, etc.)."""


class DuplicateKeyError(GovernorError):
    """Raised when duplicate definition keys are found across YAML files."""


class DuplicateResourceError(GovernorError):
    """Raised when duplicate resource names are detected within the same parent."""


class UnreferencedDefinitionError(GovernorError):
    """Raised when definitions exist that are not referenced by any $ref."""


class PrincipalValidationError(GovernorError):
    """Raised when one or more principal names cannot be found in the account."""


class DuplicateServicePrincipalError(GovernorError):
    """Raised when two service principals share the same display name."""


class InteractiveConfirmationRequiredError(GovernorError):
    """Raised when the engine needs an interactive confirmation but no TTY is attached.

    Surfaces as a hard, immediate error (not accumulated via ChangeLogger) because the
    engine cannot safely proceed with a destructive action (e.g. governed-tag deletion)
    without an explicit human confirm. The caller must set ``--force`` in non-interactive
    contexts (CI, scripted runs) to auto-confirm.
    """


class NonexistentSecurableError(GovernorError):
    """Raised when a securable declared in config doesn't exist in UC.

    Functions are created by the engine and are excluded from this check; only
    catalogs, schemas, tables, and volumes can trigger this error. One instance
    carries a single (type, full_name) pair — the engine logs one per offender
    via ``ChangeLogger.log_error`` and the governor surfaces them together via
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
        message = (
            f"Nonexistent {securable_type.value} {full_name!r} declared in config but "
            f"not found in Unity Catalog. Either create it in UC, or remove it from config."
        )
        if hint:
            message = f"{message} {hint}"
        super().__init__(message)


@dataclass(frozen=True)
class ExecutionError:
    """A single error that occurred during SQL execution."""

    context: str
    exception: Exception


class ExecutionBatchError(GovernorError):
    """Raised after execution completes when one or more SQL statements failed."""

    def __init__(self, errors: list[ExecutionError]) -> None:
        self.errors = errors
        super().__init__(self._build_message())

    def _build_message(self) -> str:
        lines = [f"{len(self.errors)} SQL statement(s) failed during execution:"]
        for err in self.errors:
            lines.append(f"  - {err.context}: {err.exception}")
        return "\n".join(lines)
