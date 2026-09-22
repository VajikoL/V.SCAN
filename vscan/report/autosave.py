"""Auto-save lightweight reports under ~/.vscan/reports/."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

from vscan.config import REPORTS_DIR, ensure_dirs
from vscan.core.discovery import Device
from vscan.core.findings import Finding
from vscan.i18n import t
from vscan.report.builder import build_report_data
from vscan.report.html_export import export_html
from vscan.report.txt_export import export_txt


def _safe_target(target: str) -> str:
    cleaned = re.sub(r"[^0-9A-Za-z._-]+", "_", target.strip())
    return cleaned.strip("_")[:48] or "scan"


def save_assessment_reports(
    *,
    target: str,
    profile: str,
    devices: list[Device],
    findings: list[Finding],
    scan_id: int | None,
    console: Console | None = None,
) -> dict[str, Path]:
    """
    Write HTML + TXT reports into ~/.vscan/reports/.

    Keeps V.SCAN light: plain files, no PDF/heavy deps.
    """
    ensure_dirs()
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    sid = scan_id or 0
    base = f"vscan-{sid}-{_safe_target(target)}-{stamp}"
    data = build_report_data(
        target=target,
        profile=profile,
        devices=devices,
        findings=findings,
        scan_id=sid,
    )
    html_path = REPORTS_DIR / f"{base}.html"
    txt_path = REPORTS_DIR / f"{base}.txt"
    export_html(data, html_path)
    export_txt(data, txt_path)
    if console is not None:
        console.print(f"[success]{t('report.autosaved_html', path=str(html_path))}[/success]")
        console.print(f"[success]{t('report.autosaved_txt', path=str(txt_path))}[/success]")
    return {"html": html_path, "txt": txt_path}
