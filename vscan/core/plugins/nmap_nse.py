"""nmap NSE defensive scripts → structured findings."""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess

from vscan.core.discovery import Device
from vscan.core.findings import Finding, cvss_to_severity
from vscan.core.plugins.base import PluginContext

logger = logging.getLogger(__name__)

# Defensive detection scripts only (no exploit/brute categories).
_LIGHT_SCRIPTS = [
    "ssl-cert",
    "ssl-date",
    "http-security-headers",
    "smb-protocols",
    "ssh2-enum-algos",
]
_DEEP_SCRIPTS = _LIGHT_SCRIPTS + [
    "ssl-enum-ciphers",
    "http-methods",
    "dns-recursion",
    "smb-security-mode",
    "vulners",
]
# Audit max: broad defensive NSE categories (still excludes exploit/brute/dos).
_AUDIT_SCRIPT_EXPR = "default,safe,vuln,auth,discovery,version"


class NmapNsePlugin:
    id = "nmap_nse"
    name = "nmap NSE defensive scripts"
    category = "nse"
    light = True

    def run(self, device: Device, ctx: PluginContext) -> list[Finding]:
        if not shutil.which("nmap") or not device.open_ports and not device.services:
            return []
        ports = sorted({s.port for s in device.services} | set(device.open_ports))
        if not ports:
            return []

        if ctx.max_mode:
            # All discovered ports, full defensive script categories.
            port_arg = ",".join(str(p) for p in ports)
            script_arg = _AUDIT_SCRIPT_EXPR
            timing = "-T3"
            run_timeout = max(600, int(ctx.timeout * 40))
        elif ctx.light:
            ports = ports[:30]
            port_arg = ",".join(str(p) for p in ports)
            script_arg = ",".join(_LIGHT_SCRIPTS)
            timing = "-T3"
            run_timeout = 120
        else:
            port_arg = ",".join(str(p) for p in ports[:80])
            script_arg = ",".join(_DEEP_SCRIPTS)
            timing = "-T4"
            run_timeout = 300

        args = [
            "nmap",
            "-Pn",
            timing,
            "-p",
            port_arg,
            "--script",
            script_arg,
            "-oX",
            "-",
            device.ip,
        ]
        if ctx.max_mode:
            args.extend(["--script-timeout", "60s"])
        if os.geteuid() == 0:
            args.insert(1, "-sS")
        else:
            args.insert(1, "-sT")

        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=run_timeout,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.debug("NSE run failed for %s: %s", device.ip, exc)
            return []

        return _parse_nse_xml(device.ip, proc.stdout)


def _parse_nse_xml(ip: str, xml_text: str) -> list[Finding]:
    findings: list[Finding] = []
    # Script blocks: <script id="..." output="...">
    for match in re.finditer(
        r'<script\s+id="([^"]+)"\s+output="([^"]*)"',
        xml_text,
    ):
        script_id, output = match.group(1), _xml_unescape(match.group(2))
        findings.extend(_script_to_findings(ip, script_id, output))

    # Also capture nested script elements with CDATA-ish free text via multiline
    for match in re.finditer(
        r'<script\s+id="([^"]+)"[^>]*>(.*?)</script>',
        xml_text,
        flags=re.DOTALL,
    ):
        script_id, body = match.group(1), match.group(2)
        # elem results
        for elem in re.finditer(r'key="([^"]+)"[^>]*>([^<]*)<', body):
            key, val = elem.group(1), elem.group(2).strip()
            if "vulners" in script_id or key.upper().startswith("CVE-"):
                cve = key if key.upper().startswith("CVE-") else val
                cvss_m = re.search(r"(\d+\.\d+)", val)
                cvss = float(cvss_m.group(1)) if cvss_m else 5.0
                if cve.upper().startswith("CVE-"):
                    findings.append(
                        Finding(
                            ip=ip,
                            port=0,
                            plugin_id=cve.upper(),
                            title=f"NSE vulners: {cve}",
                            severity=cvss_to_severity(cvss),
                            cvss=cvss,
                            remediation=(
                                f"Patch the affected service. Details: "
                                f"https://nvd.nist.gov/vuln/detail/{cve.upper()}"
                            ),
                            category="nse",
                            service="vulners",
                            nvd_url=f"https://nvd.nist.gov/vuln/detail/{cve.upper()}",
                            evidence=f"script={script_id}; {key}={val}"[:240],
                        )
                    )

    # CVE lines inside vulners output
    for cve, score in re.findall(r"(CVE-\d{4}-\d+)\s+(\d+\.\d+)", xml_text):
        cvss = float(score)
        findings.append(
            Finding(
                ip=ip,
                port=0,
                plugin_id=cve,
                title=f"NSE vulners: {cve}",
                severity=cvss_to_severity(cvss),
                cvss=cvss,
                remediation=f"Patch the affected service. Details: https://nvd.nist.gov/vuln/detail/{cve}",
                category="nse",
                service="vulners",
                nvd_url=f"https://nvd.nist.gov/vuln/detail/{cve}",
                evidence="nmap --script vulners",
            )
        )

    # Deduplicate within this plugin output
    seen: set[str] = set()
    unique: list[Finding] = []
    for f in findings:
        key = f"{f.plugin_id}:{f.port}:{f.title}"
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique


def _script_to_findings(ip: str, script_id: str, output: str) -> list[Finding]:
    out: list[Finding] = []
    low = output.lower()
    if script_id == "smb-protocols" and ("nt lm 0.12" in low or "smbv1" in low):
        out.append(
            Finding(
                ip=ip,
                port=445,
                plugin_id="VSCAN-NSE-SMBV1",
                title="NSE: SMBv1 enabled",
                severity=cvss_to_severity(8.1),
                cvss=8.1,
                remediation="Disable SMBv1; enforce SMB2/SMB3 with signing.",
                category="nse",
                service="smb",
                evidence=output[:240],
            )
        )
    if script_id == "ssl-enum-ciphers":
        if "sslv2" in low or "sslv3" in low or "tlsv1.0" in low or "tlsv1.1" in low:
            out.append(
                Finding(
                    ip=ip,
                    port=443,
                    plugin_id="VSCAN-NSE-WEAK-TLS",
                    title="NSE: Weak TLS protocol offered",
                    severity=cvss_to_severity(7.5),
                    cvss=7.5,
                    remediation="Disable SSLv2/SSLv3/TLS1.0/TLS1.1; require TLS 1.2+.",
                    category="nse",
                    service="ssl",
                    evidence=output[:240],
                )
            )
        if "weak" in low or "cbc" in low:
            out.append(
                Finding(
                    ip=ip,
                    port=443,
                    plugin_id="VSCAN-NSE-WEAK-CIPHER",
                    title="NSE: Weak TLS ciphers indicated",
                    severity=cvss_to_severity(5.3),
                    cvss=5.3,
                    remediation="Disable weak/CBC/export ciphers; prefer AEAD suites.",
                    category="nse",
                    service="ssl",
                    evidence=output[:240],
                )
            )
    if script_id == "http-security-headers" and "missing" in low:
        out.append(
            Finding(
                ip=ip,
                port=80,
                plugin_id="VSCAN-NSE-HTTP-HEADERS",
                title="NSE: Missing HTTP security headers",
                severity=cvss_to_severity(4.3),
                cvss=4.3,
                remediation="Add HSTS, CSP, X-Content-Type-Options, and frame protections.",
                category="nse",
                service="http",
                evidence=output[:240],
            )
        )
    if script_id == "ssh2-enum-algos" and ("diffie-hellman-group1" in low or "arcfour" in low):
        out.append(
            Finding(
                ip=ip,
                port=22,
                plugin_id="VSCAN-NSE-SSH-WEAK",
                title="NSE: Weak SSH algorithms offered",
                severity=cvss_to_severity(5.9),
                cvss=5.9,
                remediation="Disable weak KEX/ciphers/MACs in sshd_config; prefer modern algorithms.",
                category="nse",
                service="ssh",
                evidence=output[:240],
            )
        )
    return out


def _xml_unescape(value: str) -> str:
    return (
        value.replace("&quot;", '"')
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&#xa;", "\n")
    )
