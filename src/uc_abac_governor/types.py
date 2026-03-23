from enum import Enum


class SecurableType(str, Enum):
    CATALOG = "CATALOG"
    SCHEMA = "SCHEMA"
    TABLE = "TABLE"
    VOLUME = "VOLUME"


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
