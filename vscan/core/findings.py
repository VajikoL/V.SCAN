"""Unified finding model — CVE + plugin checks (Nessus/OpenVAS-style)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def severity_style(severity: str) -> str:
    return {
        "critical": "critical",
        "high": "high",
        "medium": "warning",
        "low": "success",
        "none": "muted",
    }.get(severity, "muted")


def severity_i18n_key(severity: str) -> str:
    return {
        "critical": "vuln.critical",
        "high": "vuln.high",
        "medium": "vuln.medium",
        "low": "vuln.low",
        "none": "vuln.none",
    }.get(severity, "vuln.none")


SEVERITY_WEIGHT = {
    "critical": 10.0,
    "high": 5.0,
    "medium": 2.0,
    "low": 0.5,
    "none": 0.0,
}

# Category amplifies exposure-style findings slightly (Nessus-like emphasis).
CATEGORY_MULTIPLIER = {
    "exposure": 1.35,
    "auth": 1.25,
    "crypto": 1.15,
    "snmp": 1.2,
    "smb": 1.2,
    "ssh": 1.15,
    "web": 1.05,
    "dns": 1.1,
    "nse": 1.1,
    "cve": 1.2,
    "general": 1.0,
}

# Ports that typically mean broader blast radius when findings appear on them.
_EXPOSURE_PORTS = {
    21, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 2375, 27017, 11211, 6443,
}


@dataclass
class Finding:
    """One assessment finding (CVE match or local plugin check)."""

    ip: str
    port: int
    plugin_id: str
    title: str
    severity: str
    cvss: float
    remediation: str
    category: str = "general"
    service: str = ""
    product: str = ""
    version: str = ""
    description: str = ""
    evidence: str = ""
    nvd_url: str = ""
    published: str = ""

    @property
    def cve_id(self) -> str:
        return self.plugin_id


def finding_weight(finding: Finding) -> float:
    """Single-finding contribution used by risk scoring."""
    base = SEVERITY_WEIGHT.get(finding.severity, 0.0)
    base += max(0.0, finding.cvss) * 0.18
    base *= CATEGORY_MULTIPLIER.get(finding.category, 1.0)
    if finding.port in _EXPOSURE_PORTS:
        base *= 1.2
    if str(finding.plugin_id).upper().startswith("CVE-") and finding.cvss >= 9.0:
        base *= 1.15
    return base


def compute_risk_score(findings: Iterable[Finding]) -> float:
    """
    Aggregate 0–100 risk score (Nessus-like).

    Uses severity + CVSS + category + exposure-port boosts, with diminishing returns
    so the scanner stays interpretable without needing tens of thousands of plugins.
    """
    items = list(findings)
    if not items:
        return 0.0
    total = sum(finding_weight(f) for f in items)
    # Extra bump when many distinct hosts are affected
    hosts = {f.ip for f in items}
    total += max(0, len(hosts) - 1) * 1.5
    # Critical concentration
    criticals = sum(1 for f in items if f.severity == "critical")
    if criticals:
        total += criticals * 2.0
    score = 100.0 * (1.0 - pow(2.718281828, -total / 28.0))
    return round(min(100.0, score), 1)


def risk_breakdown(findings: Iterable[Finding]) -> dict[str, float]:
    """Per-category contribution (for CLI/report detail)."""
    buckets: dict[str, float] = {}
    for finding in findings:
        cat = finding.category or "general"
        buckets[cat] = buckets.get(cat, 0.0) + finding_weight(finding)
    return {k: round(v, 2) for k, v in sorted(buckets.items(), key=lambda x: -x[1])}


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Keep highest-severity duplicate of the same host/port/plugin."""
    best: dict[tuple[str, int, str], Finding] = {}
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
    for finding in findings:
        key = (finding.ip, finding.port, finding.plugin_id)
        prev = best.get(key)
        if prev is None or order.get(finding.severity, 0) > order.get(prev.severity, 0):
            best[key] = finding
        elif prev and finding.cvss > prev.cvss:
            best[key] = finding
    result = list(best.values())
    result.sort(key=lambda f: (-f.cvss, f.ip, f.port, f.plugin_id))
    return result


def findings_by_severity(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1
    return counts
