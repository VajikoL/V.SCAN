"""Build host-centric report payloads (Nessus-like, lightweight)."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from vscan.core.discovery import Device
from vscan.core.findings import Finding, compute_risk_score, findings_by_severity
from vscan.i18n import t


def build_report_data(
    *,
    target: str,
    profile: str,
    devices: list[Device],
    findings: list[Finding],
    scan_id: int | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Assemble a structured report dict grouped by host."""
    by_ip: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        by_ip[finding.ip].append(finding)

    hosts: list[dict[str, Any]] = []
    for device in devices:
        host_findings = sorted(
            by_ip.get(device.ip, []),
            key=lambda f: (-f.cvss, f.port, f.plugin_id),
        )
        hosts.append(
            {
                "ip": device.ip,
                "mac": device.mac or "",
                "hostname": device.hostname or "",
                "name": device.hostname or device.vendor or device.ip,
                "vendor": device.vendor or "",
                "device_type": t(device.device_type_key),
                "device_type_key": device.device_type_key,
                "os_guess": device.os_guess or "",
                "open_ports": ",".join(str(p) for p in device.open_ports),
                "services": [
                    {
                        "port": s.port,
                        "name": s.name,
                        "product": s.product,
                        "version": s.version,
                        "cpe": s.cpe,
                    }
                    for s in device.services
                ],
                "findings": [_finding_dict(f) for f in host_findings],
                "finding_count": len(host_findings),
                "host_risk": compute_risk_score(host_findings),
            }
        )

    # Orphan findings (no device record) — rare, still include
    known = {d.ip for d in devices}
    for ip, items in by_ip.items():
        if ip in known:
            continue
        hosts.append(
            {
                "ip": ip,
                "mac": "",
                "hostname": "",
                "name": ip,
                "vendor": "",
                "device_type": t("device.unknown"),
                "device_type_key": "device.unknown",
                "os_guess": "",
                "open_ports": "",
                "services": [],
                "findings": [_finding_dict(f) for f in items],
                "finding_count": len(items),
                "host_risk": compute_risk_score(items),
            }
        )

    hosts.sort(key=lambda h: (-h["host_risk"], h["ip"]))
    counts = findings_by_severity(findings)
    risk = compute_risk_score(findings)
    stamp = created_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "id": scan_id or 0,
        "created_at": stamp,
        "target": target,
        "profile": profile,
        "device_count": len(devices),
        "vuln_count": len(findings),
        "risk_score": risk,
        "counts": counts,
        "hosts": hosts,
        # flat lists kept for older exporters / CLI report command
        "devices": [
            {
                "ip": h["ip"],
                "mac": h["mac"],
                "vendor": h["vendor"],
                "hostname": h["hostname"],
                "device_type": h["device_type"],
                "os_guess": h["os_guess"],
                "open_ports": h["open_ports"],
                "services": h["services"],
            }
            for h in hosts
        ],
        "vulnerabilities": [_finding_dict(f) for f in findings],
    }


def _finding_dict(f: Finding) -> dict[str, Any]:
    return {
        "ip": f.ip,
        "port": f.port,
        "service": f.service,
        "product": f.product,
        "version": f.version,
        "cve_id": f.plugin_id,
        "plugin_id": f.plugin_id,
        "cvss": f.cvss,
        "severity": f.severity,
        "title": f.title,
        "description": f.description or f.evidence,
        "remediation": f.remediation,
        "nvd_url": f.nvd_url,
        "category": f.category,
        "evidence": f.evidence,
    }
