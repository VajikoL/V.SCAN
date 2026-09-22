"""Adapt CVE matches into unified Finding objects."""

from __future__ import annotations

from vscan.core.findings import Finding
from vscan.core.vuln_scan import VulnerabilityFinding


def vuln_to_finding(v: VulnerabilityFinding) -> Finding:
    return Finding(
        ip=v.ip,
        port=v.port,
        plugin_id=v.cve_id,
        title=v.title,
        severity=v.severity,
        cvss=v.cvss,
        remediation=v.remediation,
        category="cve",
        service=v.service,
        product=v.product,
        version=v.version,
        description=v.description,
        nvd_url=v.nvd_url,
        published=v.published,
    )


def finding_to_vuln(f: Finding) -> VulnerabilityFinding:
    """Back-compat for older UI/store expecting VulnerabilityFinding."""
    return VulnerabilityFinding(
        ip=f.ip,
        port=f.port,
        service=f.service,
        product=f.product,
        version=f.version,
        cve_id=f.plugin_id,
        cvss=f.cvss,
        severity=f.severity,
        title=f.title,
        description=f.description or f.evidence,
        remediation=f.remediation,
        nvd_url=f.nvd_url,
        published=f.published,
    )
