"""Vulnerability matching with remediation guidance (NVD / CVSS).

Flow:
1. Take service versions discovered via nmap ``-sV``
2. Query NVD API 2.0 (keyword / CPE), with on-disk cache
3. Attach CVSS v3 severity and defensive remediation advice

This module does not fetch or describe exploits / PoCs.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus

import requests
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeRemainingColumn

from vscan.config import CACHE_DIR, ensure_dirs
from vscan.core.discovery import Device, ServiceInfo
from vscan.i18n import t

logger = logging.getLogger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CVE_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"
CVE_CACHE_DIR = CACHE_DIR / "nvd"
MAX_CVES_PER_SERVICE = 8
# NVD public rate limit without API key is low; be polite.
NVD_MIN_INTERVAL_SEC = 6.0

_last_nvd_call = 0.0


@dataclass
class VulnerabilityFinding:
    """A CVE matched to a discovered service, with fix guidance."""

    ip: str
    port: int
    service: str
    product: str
    version: str
    cve_id: str
    cvss: float
    severity: str
    title: str
    description: str
    remediation: str
    nvd_url: str
    published: str = ""


@dataclass
class VulnScanResult:
    """Aggregate vulnerability assessment for a set of devices."""

    findings: list[VulnerabilityFinding] = field(default_factory=list)
    used_cache_only: bool = False
    offline: bool = False


def cvss_to_severity(score: float) -> str:
    """Map CVSS v3 base score to a severity bucket."""
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
    """Rich style name for a severity bucket (critical/high break green theme)."""
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


def build_search_query(service: ServiceInfo) -> str | None:
    """
    Build an NVD keyword query from a service fingerprint.

    Returns None when there is not enough versioned product data to search.
    """
    product = (service.product or "").strip()
    version = (service.version or "").strip()
    # Strip trailing junk often appended by nmap (e.g. "1.2.3 (Ubuntu)").
    version = re.split(r"[\s(]", version, maxsplit=1)[0].strip()
    if product and version:
        return f"{product} {version}"
    if service.cpe:
        # CPE URI like cpe:/a:apache:http_server:2.4.49 → keyword bits
        parts = re.split(r"[:/]", service.cpe)
        useful = [p for p in parts if p and p not in {"cpe", "a", "o", "h", "*", "-"}]
        if len(useful) >= 2:
            return " ".join(useful[:4])
    return None


def extract_cvss(metrics: dict[str, Any]) -> tuple[float, str]:
    """Extract best available CVSS v3 (prefer 3.1) score from NVD metrics block."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        data = entries[0].get("cvssData") or {}
        score = data.get("baseScore")
        severity = (data.get("baseSeverity") or "").lower()
        if score is None:
            continue
        try:
            score_f = float(score)
        except (TypeError, ValueError):
            continue
        if not severity:
            severity = cvss_to_severity(score_f)
        # Normalize NVD labels to our buckets.
        if severity in {"critical", "high", "medium", "low"}:
            return score_f, severity
        return score_f, cvss_to_severity(score_f)
    return 0.0, "none"


def build_remediation(
    *,
    product: str,
    version: str,
    service_name: str,
    port: int,
    cve_id: str,
    description: str,
) -> str:
    """
    Compose defensive remediation advice for a finding.

    Advice is limited to patching, upgrading, and reducing exposure —
    never exploitation steps.
    """
    product_label = product or service_name or "the affected software"
    version_label = version or "the detected version"
    nvd = NVD_CVE_URL.format(cve_id=cve_id)

    fixed_hint = ""
    fixed_match = re.search(
        r"(?:fixed in|upgrade to|before)\s+([0-9]+(?:\.[0-9A-Za-z\-]+)+)",
        description,
        flags=re.IGNORECASE,
    )
    if fixed_match:
        fixed_hint = t("vuln.remediation_upgrade_to", version=fixed_match.group(1))

    parts = [
        t(
            "vuln.remediation_upgrade",
            product=product_label,
            version=version_label,
        ),
    ]
    if fixed_hint:
        parts.append(fixed_hint)
    parts.append(t("vuln.remediation_expose", service=service_name or product_label, port=port))
    parts.append(t("vuln.remediation_vendor"))
    parts.append(t("vuln.remediation_nvd", url=nvd))
    return " ".join(parts)


def _cache_path(query: str) -> Path:
    digest = hashlib.sha256(query.encode("utf-8")).hexdigest()[:24]
    return CVE_CACHE_DIR / f"{digest}.json"


def _read_cache(query: str) -> dict[str, Any] | None:
    path = _cache_path(query)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_cache(query: str, payload: dict[str, Any]) -> None:
    ensure_dirs()
    CVE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = _cache_path(query)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _throttle_nvd() -> None:
    global _last_nvd_call
    elapsed = time.monotonic() - _last_nvd_call
    if elapsed < NVD_MIN_INTERVAL_SEC:
        time.sleep(NVD_MIN_INTERVAL_SEC - elapsed)
    _last_nvd_call = time.monotonic()


def fetch_nvd_cves(
    query: str,
    *,
    allow_network: bool = True,
) -> tuple[list[dict[str, Any]], bool]:
    """
    Fetch CVE items for *query* from cache or NVD.

    Returns ``(items, from_cache)``.
    """
    cached = _read_cache(query)
    if cached is not None:
        return list(cached.get("vulnerabilities") or []), True

    if not allow_network:
        return [], False

    _throttle_nvd()
    url = f"{NVD_API}?keywordSearch={quote_plus(query)}&resultsPerPage=20"
    try:
        response = requests.get(
            url,
            timeout=30,
            headers={"User-Agent": "V.SCAN/0.1 (authorized-assessment; remediation)"},
        )
        response.raise_for_status()
        payload = response.json()
        _write_cache(query, payload)
        return list(payload.get("vulnerabilities") or []), False
    except (requests.RequestException, ValueError, json.JSONDecodeError) as exc:
        logger.debug("NVD query failed for %s: %s", query, exc)
        return [], False


def parse_nvd_item(item: dict[str, Any]) -> tuple[str, float, str, str, str, str] | None:
    """
    Parse one NVD vulnerability wrapper into core fields.

    Returns ``(cve_id, cvss, severity, title, description, published)`` or None.
    """
    cve = item.get("cve") or {}
    cve_id = str(cve.get("id") or "")
    if not cve_id.startswith("CVE-"):
        return None

    descriptions = cve.get("descriptions") or []
    description = ""
    for entry in descriptions:
        if entry.get("lang") == "en" and entry.get("value"):
            description = str(entry["value"])
            break
    if not description and descriptions:
        description = str(descriptions[0].get("value") or "")

    score, severity = extract_cvss(cve.get("metrics") or {})
    if score <= 0:
        return None

    title = description.split(".")[0].strip()[:120] if description else cve_id
    published = str(cve.get("published") or "")[:10]
    return cve_id, score, severity, title, description, published


def findings_for_service(
    device: Device,
    service: ServiceInfo,
    *,
    allow_network: bool = True,
    max_per_service: int = MAX_CVES_PER_SERVICE,
) -> tuple[list[VulnerabilityFinding], bool]:
    """Match CVEs for one service. Returns findings and whether cache was used."""
    query = build_search_query(service)
    if not query:
        return [], False

    limit = max(1, max_per_service)
    items, from_cache = fetch_nvd_cves(query, allow_network=allow_network)
    findings: list[VulnerabilityFinding] = []

    for wrapped in items:
        parsed = parse_nvd_item(wrapped)
        if not parsed:
            continue
        cve_id, score, severity, title, description, published = parsed
        remediation = build_remediation(
            product=service.product,
            version=service.version,
            service_name=service.name,
            port=service.port,
            cve_id=cve_id,
            description=description,
        )
        findings.append(
            VulnerabilityFinding(
                ip=device.ip,
                port=service.port,
                service=service.name,
                product=service.product,
                version=service.version,
                cve_id=cve_id,
                cvss=score,
                severity=severity,
                title=title,
                description=description[:400],
                remediation=remediation,
                nvd_url=NVD_CVE_URL.format(cve_id=cve_id),
                published=published,
            )
        )
        if len(findings) >= limit:
            break

    findings.sort(key=lambda f: (-f.cvss, f.cve_id))
    return findings, from_cache


def run_vuln_scan(
    devices: list[Device],
    console: Console,
    *,
    allow_network: bool = True,
    max_per_service: int = MAX_CVES_PER_SERVICE,
) -> VulnScanResult:
    """
    Run CVE matching across all versioned services on *devices*.
    """
    console.print(f"[info]{t('vuln.scanning')}[/info]")

    # Collect work items first.
    jobs: list[tuple[Device, ServiceInfo]] = []
    for device in devices:
        for service in device.services:
            if build_search_query(service):
                jobs.append((device, service))

    if not jobs:
        console.print(f"[muted]{t('vuln.no_versioned_services')}[/muted]")
        return VulnScanResult(findings=[])

    result = VulnScanResult()
    all_findings: list[VulnerabilityFinding] = []
    any_network_attempt = False
    any_success_from_network = False
    limit = max(1, max_per_service)

    with Progress(
        SpinnerColumn(style="green"),
        TextColumn("[info]{task.description}[/info]"),
        BarColumn(bar_width=None, style="green", complete_style="bright_green"),
        TextColumn("[muted]{task.completed}/{task.total}[/muted]"),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task(t("vuln.progress"), total=len(jobs))
        for device, service in jobs:
            findings, from_cache = findings_for_service(
                device,
                service,
                allow_network=allow_network,
                max_per_service=limit,
            )
            if allow_network and not from_cache:
                any_network_attempt = True
                if findings or _cache_path(build_search_query(service) or "").is_file():
                    any_success_from_network = True
            elif from_cache:
                result.used_cache_only = True

            for finding in findings:
                all_findings.append(finding)
                console.print(
                    f"[{severity_style(finding.severity)}]"
                    f"{t('vuln.found', cve=finding.cve_id, score=f'{finding.cvss:.1f}')}"
                    f"[/{severity_style(finding.severity)}]"
                )
                console.print(f"[muted]{t('vuln.remediation', advice=finding.remediation)}[/muted]")
            progress.advance(task_id)

    if allow_network and any_network_attempt and not any_success_from_network and result.used_cache_only:
        console.print(f"[warning]{t('error.no_internet')}[/warning]")
        result.offline = True

    all_findings.sort(key=lambda f: (-f.cvss, f.ip, f.port, f.cve_id))
    result.findings = all_findings

    if not all_findings:
        console.print(f"[success]{t('vuln.no_findings')}[/success]")
    else:
        console.print(f"[info]{t('vuln.total_found', count=len(all_findings))}[/info]")
    return result
