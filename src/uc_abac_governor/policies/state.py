from __future__ import annotations

from dataclasses import dataclass, field

from uc_abac_governor.principals.state import Principal
from uc_abac_governor.types import PolicyType, SecurableType


@dataclass(frozen=True)
class Policy:
    """A mask or filter policy on a UC securable.

    Identity is (securable_type, securable_full_name, name). Full equality
    determines whether an existing policy needs to be replaced.

    The to/except principals may be unresolved (principal_type=UNKNOWN) when
    emitted by the compiler or fetch helper, and are resolved before diffing.
    """

    securable_type: SecurableType
    securable_full_name: str
    name: str
    policy_type: PolicyType
    function_name: str
    to_principals: tuple[Principal, ...]
    except_principals: tuple[Principal, ...]
    when_condition: str | None
    match_columns: tuple[tuple[str, str], ...]
    on_column: str | None
    using_columns: tuple[str, ...]


@dataclass
class PolicyDiff:
    to_create: set[Policy] = field(default_factory=set)
    to_replace: set[Policy] = field(default_factory=set)
