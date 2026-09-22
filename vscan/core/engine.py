"""Assessment engine — discovery + plugins + CVE (OpenVAS/Nessus-class CLI)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml
from rich.console import Console

from vscan.core.adapters import finding_to_vuln, vuln_to_finding
from vscan.core.discovery import Device, nmap_available, run_discovery
from vscan.core.findings import Finding, compute_risk_score, dedupe_findings
from vscan.core.plugins import run_plugins
from vscan.core.profiles import ScanProfile
from vscan.core.vuln_scan import run_vuln_scan
from vscan.db.store import save_scan
from vscan.i18n import t
from vscan.report.autosave import save_assessment_reports


@dataclass
class AssessmentResult:
    target: str
    profile: str
    devices: list[Device] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    risk_score: float = 0.0
    scan_id: int | None = None
    report_paths: dict[str, Path] = field(default_factory=dict)


def load_credentials(path: str | Path | None) -> dict[str, str]:
    if not path:
        return {}
    p = Path(path)
    if not p.is_file():
        return {}
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items() if v is not None}


def run_assessment(
    target: str,
    profile: ScanProfile,
    console: Console,
    *,
    persist: bool = True,
    threads_override: int | None = None,
    credentials: dict[str, str] | None = None,
    do_plugins: bool | None = None,
    do_vuln: bool | None = None,
) -> AssessmentResult:
    """Run discovery + optional plugins + optional CVE matching."""
    if profile.probe_ports and not nmap_available():
        console.print(f"[critical]{t('error.nmap_missing')}[/critical]")
        raise RuntimeError("nmap missing")

    threads = threads_override if threads_override is not None else profile.threads
    devices = run_discovery(
        target,
        console,
        threads=threads,
        probe_ports=profile.probe_ports,
        version_detect=profile.version_detect,
        host_timeout=profile.host_timeout,
        full_ports=profile.full_ports,
        top_ports=profile.top_ports,
        os_detect=profile.os_detect,
        default_scripts=profile.default_scripts,
        udp=profile.udp,
        script_expr=profile.script_expr,
        max_mode=profile.max_mode,
    )

    findings: list[Finding] = []
    run_plugs = profile.do_plugins if do_plugins is None else do_plugins
    run_cve = profile.do_vuln if do_vuln is None else do_vuln

    if run_plugs and devices:
        findings.extend(
            run_plugins(
                devices,
                console,
                light=profile.light_plugins and not profile.max_mode,
                credentials=credentials or {},
                threads=max(2, min(threads, 16 if profile.max_mode else 8)),
                timeout=profile.plugin_timeout,
                max_mode=profile.max_mode,
                force_all_plugins=profile.max_mode,
            )
        )

    if run_cve and devices:
        cve_findings = run_vuln_scan(
            devices,
            console,
            max_per_service=profile.max_cves_per_service,
        ).findings
        findings.extend(vuln_to_finding(v) for v in cve_findings)

    findings = dedupe_findings(findings)
    risk = compute_risk_score(findings)
    if findings:
        console.print(f"[info]{t('summary.risk_score', score=f'{risk:.1f}')}[/info]")

    scan_id = None
    report_paths: dict[str, Path] = {}
    if persist:
        legacy = [finding_to_vuln(f) for f in findings]
        scan_id = save_scan(
            target=target,
            profile=profile.key,
            devices=devices,
            findings=legacy,
            notes=t("app.name"),
            risk_score=risk,
            categories={f.plugin_id: f.category for f in findings},
        )
        console.print(f"[success]{t('history.saved', id=scan_id)}[/success]")
        report_paths = save_assessment_reports(
            target=target,
            profile=profile.key,
            devices=devices,
            findings=findings,
            scan_id=scan_id,
            console=console,
        )

    return AssessmentResult(
        target=target,
        profile=profile.key,
        devices=devices,
        findings=findings,
        risk_score=risk,
        scan_id=scan_id,
        report_paths=report_paths,
    )
