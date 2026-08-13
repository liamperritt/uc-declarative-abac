"""Terminal presentation primitives shared by every ``uc-abac`` command."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass

_RESET = "\x1b[0m"
_BOLD = "\x1b[1m"
_RED = "\x1b[31m"
_GREEN = "\x1b[32m"
_YELLOW = "\x1b[33m"
_CYAN = "\x1b[36m"

_UNICODE_SYMBOLS = {
    "success": "✔",
    "warning": "⚠",
    "error": "✖",
    "info": "ℹ",
}
_ASCII_SYMBOLS = {
    "success": "[OK]",
    "warning": "[WARN]",
    "error": "[ERROR]",
    "info": "[INFO]",
}
_ANSI_COLORS = {
    "success": _GREEN,
    "warning": _YELLOW,
    "error": _RED,
    "info": _CYAN,
}


def _is_tty(stream) -> bool:
    return bool(getattr(stream, "isatty", lambda: False)())


def _supports_color(stream) -> bool:
    return _is_tty(stream) and "NO_COLOR" not in os.environ


def _supports_unicode(stream, symbol: str) -> bool:
    encoding = getattr(stream, "encoding", None)
    if not _is_tty(stream) or not encoding:
        return False
    try:
        symbol.encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return False
    return True


def _style_help(text: str) -> str:
    styled: list[str] = []
    for line in text.splitlines():
        if line.endswith(":") and line.lstrip() == line:
            line = f"{_BOLD}{line}{_RESET}"
        elif line.startswith("UC Declarative ABAC"):
            line = f"{_BOLD}{_CYAN}{line}{_RESET}"
        elif line.startswith("  ") and not line.startswith("    "):
            body = line[2:]
            command, separator, rest = body.partition("  ")
            if separator and command and not command.startswith("-"):
                line = f"  {_CYAN}{command}{_RESET}{separator}{rest}"
        styled.append(line)
    return "\n".join(styled) + "\n"


def format_status(kind: str, message: str, *, stream=None) -> str:
    """Return one consistently styled status line for a terminal stream."""
    target = stream if stream is not None else sys.stderr
    if kind not in _UNICODE_SYMBOLS:
        raise ValueError(f"Unknown status kind: {kind!r}")

    symbol = (
        _UNICODE_SYMBOLS[kind]
        if _supports_unicode(target, _UNICODE_SYMBOLS[kind])
        else _ASCII_SYMBOLS[kind]
    )
    if _supports_color(target):
        symbol = f"{_ANSI_COLORS[kind]}{symbol}{_RESET}"
    return f"{symbol} {message}"


def format_error(message: str, *, hint: str | None = None, stream=None) -> str:
    """Return an actionable, consistently styled CLI error."""
    lines = [format_status("error", message, stream=stream)]
    if hint:
        lines.append(f"  Hint: {hint}")
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class HelpExample:
    """A copy-pasteable command example and its short explanation."""

    command: str
    description: str


class CliArgumentParser(argparse.ArgumentParser):
    """Argument parser with the project-wide help and error presentation."""

    def __init__(
        self,
        *args,
        product_name: str | None = None,
        version: str | None = None,
        examples: Sequence[HelpExample] = (),
        options_title: str = "GLOBAL OPTIONS:",
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._product_name = product_name
        self._version = version
        self._examples = tuple(examples)
        self._options_title = options_title

    def format_help(self) -> str:
        """Render help with compact branding and consistent section labels."""
        help_text = super().format_help()
        help_text = help_text.replace("usage:", "USAGE:", 1)
        help_text = help_text.replace("positional arguments:", "COMMANDS:", 1)
        help_text = help_text.replace("options:", self._options_title, 1)

        parts: list[str] = []
        if self._product_name:
            version = f" v{self._version}" if self._version else ""
            parts.append(f"{self._product_name}{version}\n")
        parts.append(help_text.rstrip())
        if self._examples:
            example_lines = ["", "EXAMPLES:"]
            for example in self._examples:
                example_lines.append(f"  {example.command}")
                example_lines.append(f"    {example.description}")
            parts.append("\n".join(example_lines))
        return "\n".join(parts) + "\n"

    def error(self, message: str) -> None:
        """Report a concise parsing failure without repeating the full help page."""
        self.exit(
            2,
            format_error(
                message,
                hint=f"Run `{self.prog.split()[0]} --help` to see available commands.",
                stream=sys.stderr,
            ),
        )

    def print_help(self, file=None) -> None:
        """Write colored help only when the destination supports it."""
        target = file if file is not None else sys.stdout
        help_text = self.format_help()
        target.write(_style_help(help_text) if _supports_color(target) else help_text)
