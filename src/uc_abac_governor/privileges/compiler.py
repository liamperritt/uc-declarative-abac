from __future__ import annotations

from uc_abac_governor.models import ConfigFile
from uc_abac_governor.privileges.state import SecurablePrivilege
from uc_abac_governor.tags.state import SecurableTag


def compile_desired_privileges(
    config: ConfigFile,
    desired_tags: set[SecurableTag],
) -> set[SecurablePrivilege]:
    """Compute desired privileges by matching grant policies against desired tags.

    For each catalog's grant policies, finds objects whose tags are a superset
    of the policy's tags (AND semantics, exact value match). Emits a
    SecurablePrivilege for each (matching_object, principal, privilege_type).

    Takes desired_tags as input so it can match policies against the tag state
    without reaching into the tags domain's internals.
    """
    raise NotImplementedError
