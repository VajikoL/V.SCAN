"""Lightweight XML report (Nessus-inspired structure, not .nessus proprietary)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from xml.dom import minidom

from vscan import __app_name__, __author__, __version__


def export_xml(data: dict[str, Any], path: Path) -> Path:
    root = ET.Element(
        "VScanReport",
        {
            "generator": __app_name__,
            "author": __author__,
            "version": __version__,
        },
    )
    meta = ET.SubElement(root, "Scan")
    for key in ("id", "created_at", "target", "profile", "device_count", "vuln_count", "risk_score"):
        if key in data:
            meta.set(key, str(data.get(key, "")))

    hosts = ET.SubElement(root, "Hosts")
    by_ip: dict[str, list[dict[str, Any]]] = {}
    for v in data.get("vulnerabilities") or []:
        by_ip.setdefault(str(v.get("ip")), []).append(v)

    for device in data.get("devices") or []:
        ip = str(device.get("ip"))
        host_el = ET.SubElement(
            hosts,
            "Host",
            {
                "ip": ip,
                "mac": str(device.get("mac") or ""),
                "hostname": str(device.get("hostname") or ""),
                "os": str(device.get("os_guess") or ""),
            },
        )
        for v in by_ip.get(ip, []):
            item = ET.SubElement(
                host_el,
                "ReportItem",
                {
                    "port": str(v.get("port") or 0),
                    "severity": str(v.get("severity") or ""),
                    "cvss": str(v.get("cvss") or 0),
                    "plugin_id": str(v.get("plugin_id") or v.get("cve_id") or ""),
                },
            )
            ET.SubElement(item, "name").text = str(v.get("title") or "")
            ET.SubElement(item, "description").text = str(v.get("description") or v.get("title") or "")
            ET.SubElement(item, "solution").text = str(v.get("remediation") or "")
            if v.get("nvd_url"):
                ET.SubElement(item, "see_also").text = str(v["nvd_url"])

    rough = ET.tostring(root, encoding="utf-8")
    pretty = minidom.parseString(rough).toprettyxml(indent="  ", encoding="utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pretty)
    return path
