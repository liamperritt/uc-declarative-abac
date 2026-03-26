from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SecurableType(str, Enum):
    CATALOG = "CATALOG"
    SCHEMA = "SCHEMA"
    TABLE = "TABLE"
    VOLUME = "VOLUME"


class PrincipalType(str, Enum):
    USER = "USER"
    GROUP = "GROUP"
    SERVICE_PRINCIPAL = "SERVICE_PRINCIPAL"


@dataclass(frozen=True)
class Principal:
    """Represents a workspace principal with both its system identifier and display name.

    - User: identifier=username, display_name=display_name
    - Group: identifier=display_name, display_name=display_name
    - Service Principal: identifier=application_id, display_name=display_name
    """

    principal_type: PrincipalType
    identifier: str
    display_name: str


class GovernorError(Exception):
    """Base exception for all governor errors."""


class ResolutionError(GovernorError):
    """Raised when a $ref cannot be resolved (missing key, circular ref, etc.)."""


class DuplicateKeyError(GovernorError):
    """Raised when duplicate definition keys are found across YAML files."""


class PrincipalValidationError(GovernorError):
    """Raised when one or more principal names cannot be found in the account."""


class DuplicateServicePrincipalError(GovernorError):
    """Raised when two service principals share the same display name."""


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
