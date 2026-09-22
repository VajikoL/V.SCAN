"""Local database updater (OUI + NVD CVE cache housekeeping).

Does not download exploit databases — V.SCAN focuses on identification
and remediation guidance.
"""

from __future__ import annotations

import shutil

from rich.console import Console

from vscan.config import CACHE_DIR, ensure_dirs
from vscan.core.discovery import ensure_oui_database
from vscan.i18n import t


def update_databases(console: Console, *, clear_cve_cache: bool = False) -> None:
    """Refresh offline caches used by discovery and CVE lookup."""
    console.print(f"[info]{t('update.start')}[/info]")
    ensure_oui_database(console, force=True)
    ensure_dirs()
    cve_dir = CACHE_DIR / "nvd"
    if clear_cve_cache and cve_dir.is_dir():
        shutil.rmtree(cve_dir)
        console.print(f"[muted]{t('update.cve_cache_cleared')}[/muted]")
    cve_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"[success]{t('update.complete')}[/success]")
