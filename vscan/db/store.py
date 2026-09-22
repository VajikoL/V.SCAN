"""Persist and load scan history."""

from __future__ import annotations

import json
from typing import Any

from vscan.core.discovery import Device
from vscan.core.vuln_scan import VulnerabilityFinding
from vscan.db.models import DeviceRecord, ScanRecord, VulnRecord, get_session_factory


def save_scan(
    *,
    target: str,
    profile: str,
    devices: list[Device],
    findings: list[VulnerabilityFinding],
    notes: str = "",
    risk_score: float = 0.0,
    categories: dict[str, str] | None = None,
) -> int:
    """Save a completed assessment; returns scan id."""
    cats = categories or {}
    Session = get_session_factory()
    with Session() as session:
        record = ScanRecord(
            target=target,
            profile=profile,
            device_count=len(devices),
            vuln_count=len(findings),
            risk_score=risk_score,
            notes=notes,
        )
        session.add(record)
        session.flush()

        for device in devices:
            services = [
                {
                    "port": s.port,
                    "name": s.name,
                    "product": s.product,
                    "version": s.version,
                    "cpe": s.cpe,
                }
                for s in device.services
            ]
            session.add(
                DeviceRecord(
                    scan_id=record.id,
                    ip=device.ip,
                    mac=device.mac,
                    vendor=device.vendor,
                    hostname=device.hostname,
                    device_type=device.device_type_key,
                    os_guess=device.os_guess,
                    open_ports=",".join(str(p) for p in device.open_ports),
                    services_json=json.dumps(services),
                )
            )

        for finding in findings:
            session.add(
                VulnRecord(
                    scan_id=record.id,
                    ip=finding.ip,
                    port=finding.port,
                    service=finding.service,
                    product=finding.product,
                    version=finding.version,
                    cve_id=finding.cve_id,
                    cvss=finding.cvss,
                    severity=finding.severity,
                    title=finding.title,
                    remediation=finding.remediation,
                    nvd_url=finding.nvd_url,
                    category=cats.get(finding.cve_id, "cve" if str(finding.cve_id).startswith("CVE-") else "plugin"),
                )
            )

        session.commit()
        return int(record.id)


def get_scan(scan_id: int) -> dict[str, Any] | None:
    """Load a scan as a plain dict suitable for export."""
    Session = get_session_factory()
    with Session() as session:
        record = session.get(ScanRecord, scan_id)
        if record is None:
            return None
        return {
            "id": record.id,
            "created_at": record.created_at.isoformat() if record.created_at else "",
            "target": record.target,
            "profile": record.profile,
            "device_count": record.device_count,
            "vuln_count": record.vuln_count,
            "risk_score": getattr(record, "risk_score", 0.0) or 0.0,
            "notes": record.notes,
            "devices": [
                {
                    "ip": d.ip,
                    "mac": d.mac,
                    "vendor": d.vendor,
                    "hostname": d.hostname,
                    "device_type": d.device_type,
                    "os_guess": d.os_guess,
                    "open_ports": d.open_ports,
                    "services": json.loads(d.services_json or "[]"),
                }
                for d in record.devices
            ],
            "vulnerabilities": [
                {
                    "ip": v.ip,
                    "port": v.port,
                    "service": v.service,
                    "product": v.product,
                    "version": v.version,
                    "cve_id": v.cve_id,
                    "plugin_id": v.cve_id,
                    "cvss": v.cvss,
                    "severity": v.severity,
                    "title": v.title,
                    "remediation": v.remediation,
                    "nvd_url": v.nvd_url,
                    "category": getattr(v, "category", "") or "",
                }
                for v in record.vulns
            ],
        }


def list_scans(limit: int = 20) -> list[dict[str, Any]]:
    Session = get_session_factory()
    with Session() as session:
        rows = (
            session.query(ScanRecord)
            .order_by(ScanRecord.id.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id": r.id,
                "created_at": r.created_at.isoformat() if r.created_at else "",
                "target": r.target,
                "profile": r.profile,
                "device_count": r.device_count,
                "vuln_count": r.vuln_count,
                "risk_score": getattr(r, "risk_score", 0.0) or 0.0,
            }
            for r in rows
        ]


def diff_scans(id1: int, id2: int) -> dict[str, Any]:
    """Compare two scans: new/missing hosts, new vulns, closed ports."""
    a = get_scan(id1)
    b = get_scan(id2)
    if a is None or b is None:
        missing = []
        if a is None:
            missing.append(id1)
        if b is None:
            missing.append(id2)
        raise KeyError(f"scan(s) not found: {missing}")

    devices_a = {d["ip"]: d for d in a["devices"]}
    devices_b = {d["ip"]: d for d in b["devices"]}
    new_devices = [devices_b[ip] for ip in sorted(set(devices_b) - set(devices_a))]
    missing_devices = [devices_a[ip] for ip in sorted(set(devices_a) - set(devices_b))]

    vulns_a = {(v["ip"], v["cve_id"], v["port"]) for v in a["vulnerabilities"]}
    vulns_b = {(v["ip"], v["cve_id"], v["port"]) for v in b["vulnerabilities"]}
    new_vuln_keys = vulns_b - vulns_a
    new_vulns = [
        v
        for v in b["vulnerabilities"]
        if (v["ip"], v["cve_id"], v["port"]) in new_vuln_keys
    ]

    closed_ports: list[dict[str, Any]] = []
    for ip in set(devices_a) & set(devices_b):
        ports_a = set(p for p in (devices_a[ip].get("open_ports") or "").split(",") if p)
        ports_b = set(p for p in (devices_b[ip].get("open_ports") or "").split(",") if p)
        for port in sorted(ports_a - ports_b, key=lambda x: int(x) if x.isdigit() else 0):
            closed_ports.append({"ip": ip, "port": port})

    return {
        "scan_a": id1,
        "scan_b": id2,
        "new_devices": new_devices,
        "missing_devices": missing_devices,
        "new_vulnerabilities": new_vulns,
        "closed_ports": closed_ports,
    }
