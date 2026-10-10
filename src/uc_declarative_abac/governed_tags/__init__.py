from __future__ import annotations

from uc_declarative_abac.governed_tags.compiler import compile_desired_governed_tags
from uc_declarative_abac.governed_tags.differ import compute_governed_tag_diff
from uc_declarative_abac.governed_tags.executor import execute_governed_tag_diff
from uc_declarative_abac.governed_tags.references import collect_referenced_tag_keys
from uc_declarative_abac.governed_tags.state import (
    GovernedTag,
    GovernedTagDiff,
)

__all__ = [
    "GovernedTag",
    "GovernedTagDiff",
    "collect_referenced_tag_keys",
    "compile_desired_governed_tags",
    "compute_governed_tag_diff",
    "execute_governed_tag_diff",
]
