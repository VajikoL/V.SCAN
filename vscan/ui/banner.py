"""ASCII banner rendering for V.SCAN — rotating upright styles + themed art."""

from __future__ import annotations

import random
from dataclasses import dataclass

from pyfiglet import Figlet
from rich.console import Console
from rich.text import Text

from vscan import __author__, __version__
from vscan.i18n import t


@dataclass(frozen=True)
class BannerStyle:
    """One Metasploit-like banner look."""

    name: str
    kind: str  # figlet | art
    font: str = "standard"
    width: int = 200
    art_key: str = ""


# Upright fonts only (no slant / italic).
# Mix of figlet wordmarks and hand-drawn themed logos.
BANNER_STYLES: tuple[BannerStyle, ...] = (
    BannerStyle("standard", "figlet", "standard", 200),
    BannerStyle("big", "figlet", "big", 220),
    BannerStyle("doom", "figlet", "doom", 200),
    BannerStyle("block", "figlet", "block", 220),
    BannerStyle("shadow", "figlet", "ansi_shadow", 220),
    BannerStyle("colossal", "figlet", "colossal", 240),
    BannerStyle("radar", "art", art_key="radar"),
    BannerStyle("shield", "art", art_key="shield"),
    BannerStyle("network", "art", art_key="network"),
    BannerStyle("terminal", "art", art_key="terminal"),
    BannerStyle("lock", "art", art_key="lock"),
)


# Themed ASCII logos — title embedded or beside the drawing.
_THEMED_ART: dict[str, str] = {
    "radar": r"""
          .-~~~~-.
        /  .--.  \      __      __   ____   ____    _    _   _
       /  /    \  \     \ \    / /  / ___| / ___|  / \  | \ | |
      |  |  ()  |  |     \ \  / /  | |     \___ \ / _ \ |  \| |
       \  \    /  /       \ \/ /   | |___   ___) / ___ \| |\  |
        \  '--'  /         \__/     \____| |____/_/   \_\_| \_|
         '-____-'
              \  |  /
               \ | /
            ~~~~ V.SCAN ~~~~
""",
    "shield": r"""
              _______
           .-'  ___  '-.
         .'   /     \   '.
        /    | V.SCAN |    \
       |     |  SEC   |     |
       |     |########|     |
        \     \_____/     /
         '.     |||     .'
           '-.  |||  .-'
              '-----'
           auth · assess · fix
""",
    "network": r"""
      (router)          V . S C A N
         [*]
        / | \
       /  |  \
    [*]- - - -[*]----[*]
     |         |      |
    [*]       [*]    [*]
   host      host   host

   ╔══════════════════════╗
   ║   V.SCAN  ·  NETMAP  ║
   ╚══════════════════════╝
""",
    "terminal": r"""
   ┌──────────────────────────────────────┐
   │ root@vscan:~# ./assess --lan         │
   │                                      │
   │   ██╗   ██╗   ███████╗ ██████╗       │
   │   ██║   ██║   ██╔════╝██╔════╝       │
   │   ██║   ██║   ███████╗██║            │
   │   ╚██╗ ██╔╝   ╚════██║██║            │
   │    ╚████╔╝    ███████║╚██████╗       │
   │     ╚═══╝     ╚══════╝ ╚═════╝       │
   │            V . S C A N               │
   │   [*] hosts up  [*] cve match        │
   └──────────────────────────────────────┘
""",
    "lock": r"""
          .------.
         /  .--.  \
        |  /    \  |
        | |      | |     V . S C A N
        | |      | |   ───────────────
         \ \    / /    auth · assess · fix
     .----'------'----.
    |   [##########]   |
    |   |  V.SCAN  |   |
    |   |__________|   |
     '----------------'
""",
}


def _figlet_lines(text: str, font: str, width: int = 200) -> list[str] | None:
    try:
        art = Figlet(font=font, width=width).renderText(text)
    except Exception:
        return None
    lines = art.rstrip("\n").splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    return lines or None


def _pad(lines: list[str], height: int) -> list[str]:
    return lines + [""] * (height - len(lines))


def _render_split_upright(font: str, width: int) -> list[Text]:
    """Upright V · SCAN wordmark with green accent between halves."""
    left = _figlet_lines("V", font, width) or ["V"]
    right = _figlet_lines("SCAN", font, width) or ["SCAN"]
    while left and not left[-1].strip():
        left.pop()
    while right and not right[-1].strip():
        right.pop()
    height = max(len(left), len(right))
    left, right = _pad(left, height), _pad(right, height)
    rows: list[Text] = []
    for l_line, r_line in zip(left, right, strict=True):
        if not l_line.strip() and not r_line.strip():
            continue
        row = Text()
        row.append(l_line.rstrip(), style="banner")
        row.append("  ·  ", style="banner.dot")
        row.append(r_line.rstrip(), style="banner")
        rows.append(row)
    return rows


def _colorize_art(lines: list[str]) -> list[Text]:
    """Colour themed art; highlight V.SCAN / V . SCAN fragments."""
    rows: list[Text] = []
    markers = ("V.SCAN", "V . S C A N", "V . SCAN", "V.SCAN")
    for raw in lines:
        line = raw.rstrip("\n")
        if not line.strip():
            rows.append(Text(""))
            continue
        row = Text()
        remaining = line
        # Greedy highlight of brand tokens
        while remaining:
            hit_at = None
            hit_token = None
            for token in markers:
                idx = remaining.find(token)
                if idx != -1 and (hit_at is None or idx < hit_at):
                    hit_at = idx
                    hit_token = token
            if hit_at is None or hit_token is None:
                row.append(remaining, style="banner")
                break
            if hit_at:
                row.append(remaining[:hit_at], style="banner")
            row.append(hit_token, style="banner.dot")
            remaining = remaining[hit_at + len(hit_token) :]
        rows.append(row)
    return rows


def _render_figlet(style: BannerStyle) -> list[Text]:
    rows = _render_split_upright(style.font, style.width)
    if rows:
        return rows
    for font in ("standard", "big", "doom", "block"):
        rows = _render_split_upright(font, style.width)
        if rows:
            return rows
    return _colorize_art(_THEMED_ART["terminal"].strip("\n").splitlines())


def _render_art(style: BannerStyle) -> list[Text]:
    art = _THEMED_ART.get(style.art_key) or _THEMED_ART["radar"]
    return _colorize_art(art.strip("\n").splitlines())


def pick_banner_style(name: str | None = None) -> BannerStyle:
    """Pick a banner style at random (or by name)."""
    if name:
        for style in BANNER_STYLES:
            if style.name == name:
                return style
    return random.choice(BANNER_STYLES)


def print_banner(console: Console, *, style_name: str | None = None) -> None:
    """
    Print a large upright V.SCAN banner.

    Style rotates randomly each run (Metasploit-style). Some styles are
    themed ASCII drawings with the brand inside or beside the art.
    """
    style = pick_banner_style(style_name)
    if style.kind == "art":
        rows = _render_art(style)
    else:
        rows = _render_figlet(style)

    console.print()
    for row in rows:
        console.print(row)
    console.print()
    console.print(Text(t("app.tagline"), style="info"))
    console.print(Text(f"v{__version__} · {__author__} · style:{style.name}", style="muted"))
    console.print(Text(t("app.disclaimer"), style="warning"))
    console.print(Text(t("banner.ready"), style="info"))
    console.print()
