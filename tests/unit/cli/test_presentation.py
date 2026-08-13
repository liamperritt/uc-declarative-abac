from __future__ import annotations

from dataclasses import dataclass

from uc_declarative_abac.cli.presentation import format_status


@dataclass
class FakeTextStream:
    tty: bool
    encoding: str = "utf-8"

    def isatty(self) -> bool:
        return self.tty


def test_presentation_uses_ansi_only_for_color_capable_tty(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    tty_output = format_status(
        "success",
        "Configuration is valid",
        stream=FakeTextStream(tty=True),
    )
    non_tty_output = format_status(
        "success",
        "Configuration is valid",
        stream=FakeTextStream(tty=False),
    )

    monkeypatch.setenv("NO_COLOR", "1")
    no_color_output = format_status(
        "success",
        "Configuration is valid",
        stream=FakeTextStream(tty=True),
    )

    assert "\x1b[" in tty_output
    assert "Configuration is valid" in tty_output
    assert "\x1b[" not in non_tty_output
    assert "Configuration is valid" in non_tty_output
    assert "\x1b[" not in no_color_output
    assert "Configuration is valid" in no_color_output
