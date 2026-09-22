"""CSV report export."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any


def export_csv(data: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "ip",
        "port",
        "plugin_id",
        "cve_id",
        "cvss",
        "severity",
        "title",
        "category",
        "service",
        "product",
        "version",
        "remediation",
        "nvd_url",
    ]
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for v in data.get("vulnerabilities") or []:
            writer.writerow(
                {
                    "ip": v.get("ip", ""),
                    "port": v.get("port", ""),
                    "plugin_id": v.get("plugin_id") or v.get("cve_id", ""),
                    "cve_id": v.get("cve_id", ""),
                    "cvss": v.get("cvss", ""),
                    "severity": v.get("severity", ""),
                    "title": v.get("title", ""),
                    "category": v.get("category", ""),
                    "service": v.get("service", ""),
                    "product": v.get("product", ""),
                    "version": v.get("version", ""),
                    "remediation": v.get("remediation", ""),
                    "nvd_url": v.get("nvd_url", ""),
                }
            )
    return path
