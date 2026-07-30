from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("uc-declarative-abac")
except PackageNotFoundError:
    __version__ = "0.0.0"

from uc_declarative_abac.cli.commands import main

__all__ = ["__version__", "main"]
