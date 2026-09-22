"""Rich theme definitions for V.SCAN (Matrix/Metasploit-style green on black)."""

from __future__ import annotations

from rich.console import Console
from rich.theme import Theme

# Green-on-black palette. Critical/high severities intentionally break the green theme.
VSCAN_THEME = Theme(
    {
        "info": "bold bright_green",
        "success": "bold green",
        "warning": "bold yellow",
        "critical": "bold bright_red",
        "high": "bold dark_orange",
        "banner": "bold bright_green",
        "banner.dot": "bold bright_green",
        "table.header": "bold bright_green",
        "muted": "dim green",
        "ip": "bright_green",
        "mac": "green",
        "vendor": "bright_green",
    }
)


def get_console(*, force_terminal: bool | None = None) -> Console:
    """Create a Console bound to the V.SCAN theme."""
    return Console(theme=VSCAN_THEME, force_terminal=force_terminal)
