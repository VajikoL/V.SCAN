"""Plain-text assessment report — light, Nessus-like host sections."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vscan import __app_name__, __author__, __version__
from vscan.i18n import t


def export_txt(data: dict[str, Any], path: Path) -> Path:
    lines: list[str] = []
    w = lines.append
    risk = float(data.get("risk_score") or 0)
    counts = data.get("counts") or {}

    w("=" * 72)
    w(f"  {__app_name__} — {t('report.title')}")
    w(f"  {__author__} · v{__version__}")
    w("=" * 72)
    w(f"{t('report.scan_id')}: #{data.get('id', 0)}")
    w(f"{t('history.when')}: {data.get('created_at', '')}")
    w(f"{t('history.target')}: {data.get('target', '')}")
    w(f"{t('history.profile')}: {data.get('profile', '')}")
    w(f"{t('report.devices')}: {data.get('device_count', 0)}")
    w(f"{t('report.vulns')}: {data.get('vuln_count', 0)}")
    w(f"{t('summary.risk_score', score=f'{risk:.1f}')}")
    w(
        f"  {t('vuln.critical')}: {counts.get('critical', 0)}  "
        f"{t('vuln.high')}: {counts.get('high', 0)}  "
        f"{t('vuln.medium')}: {counts.get('medium', 0)}  "
        f"{t('vuln.low')}: {counts.get('low', 0)}"
    )
    w("")
    w(t("app.disclaimer"))
    w("")

    hosts = data.get("hosts") or []
    if not hosts:
        w(t("scan.devices_found", count=0))
    for idx, host in enumerate(hosts, start=1):
        w("-" * 72)
        w(f"[{idx}] {t('report.host_section')}")
        w(f"  {t('table.ip')}:       {host.get('ip', '')}")
        w(f"  {t('table.mac')}:      {host.get('mac') or '—'}")
        w(f"  {t('table.hostname')}: {host.get('hostname') or host.get('name') or '—'}")
        w(f"  {t('table.vendor')}:   {host.get('vendor') or '—'}")
        w(f"  {t('table.device_type')}: {host.get('device_type') or '—'}")
        w(f"  {t('table.os_guess')}: {host.get('os_guess') or '—'}")
        w(f"  {t('table.open_ports')}: {host.get('open_ports') or '—'}")
        host_risk = float(host.get("host_risk") or 0)
        w(f"  {t('summary.risk_score', score=f'{host_risk:.1f}')}")
        w("")

        findings = host.get("findings") or []
        if not findings:
            w(f"  {t('report.host_clean')}")
            w("")
            continue

        w(f"  {t('report.vulns_title')} ({len(findings)}):")
        for n, v in enumerate(findings, start=1):
            plugin = v.get("plugin_id") or v.get("cve_id") or ""
            w(f"  ({n}) [{str(v.get('severity', '')).upper()}] {plugin}  CVSS {float(v.get('cvss') or 0):.1f}")
            w(f"      {t('table.port')}: {v.get('port', 0)}  {t('table.service')}: {v.get('service') or '—'}")
            title = v.get("title") or ""
            if title:
                w(f"      {title}")
            rem = v.get("remediation") or ""
            w(f"      {t('table.remediation')}: {rem}")
            if v.get("nvd_url"):
                w(f"      URL: {v['nvd_url']}")
            w("")

    w("=" * 72)
    w(f"{__app_name__} — {__author__}")
    w("=" * 72)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
