"""SSH banner / version posture (unauthenticated, light)."""

from __future__ import annotations

import re
import socket

from vscan.core.discovery import Device
from vscan.core.findings import Finding, cvss_to_severity
from vscan.core.plugins.base import PluginContext

# Very old OpenSSH majors still commonly flagged in assessments.
_OLD_OPENSSH = re.compile(r"OpenSSH[_\s-](\d+)\.(\d+)", re.I)


class SshBannerPlugin:
    id = "ssh_banner"
    name = "SSH banner posture"
    category = "ssh"
    light = True

    def run(self, device: Device, ctx: PluginContext) -> list[Finding]:
        ports = set(device.open_ports) | {s.port for s in device.services}
        ssh_ports = [s.port for s in device.services if "ssh" in (s.name or "").lower()]
        candidates = sorted({p for p in ports if p in {22, 2222} or p in ssh_ports})
        if not candidates and 22 in ports:
            candidates = [22]
        if ctx.light and not ctx.max_mode:
            candidates = candidates[:2]

        findings: list[Finding] = []
        for port in candidates:
            banner = _read_banner(device.ip, port, ctx.timeout)
            if not banner:
                continue
            if "SSH-1." in banner:
                findings.append(
                    Finding(
                        ip=device.ip,
                        port=port,
                        plugin_id="VSCAN-SSH-PROTO1",
                        title="SSH protocol 1 advertised",
                        severity=cvss_to_severity(9.0),
                        cvss=9.0,
                        remediation="Disable SSH protocol 1; require SSH-2 only.",
                        category="ssh",
                        service="ssh",
                        evidence=banner[:120],
                    )
                )
            match = _OLD_OPENSSH.search(banner)
            if match:
                major, minor = int(match.group(1)), int(match.group(2))
                if major < 7 or (major == 7 and minor < 4):
                    findings.append(
                        Finding(
                            ip=device.ip,
                            port=port,
                            plugin_id="VSCAN-SSH-OLD",
                            title=f"Outdated OpenSSH banner ({major}.{minor})",
                            severity=cvss_to_severity(7.5),
                            cvss=7.5,
                            remediation="Upgrade OpenSSH to a current vendor-supported release.",
                            category="ssh",
                            service="ssh",
                            product="OpenSSH",
                            version=f"{major}.{minor}",
                            evidence=banner[:120],
                        )
                    )
            # Also use nmap product/version if present
            for svc in device.services:
                if svc.port != port:
                    continue
                blob = f"{svc.product} {svc.version}".lower()
                if "openssh" in blob:
                    m2 = re.search(r"(\d+)\.(\d+)", svc.version or "")
                    if m2 and int(m2.group(1)) < 7:
                        findings.append(
                            Finding(
                                ip=device.ip,
                                port=port,
                                plugin_id="VSCAN-SSH-OLD-SV",
                                title=f"nmap reports old OpenSSH {svc.version}",
                                severity=cvss_to_severity(7.5),
                                cvss=7.5,
                                remediation="Upgrade OpenSSH via the OS package manager.",
                                category="ssh",
                                service="ssh",
                                product=svc.product,
                                version=svc.version,
                                evidence=blob[:120],
                            )
                        )
        return findings


def _read_banner(ip: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((ip, port), timeout=min(timeout, 3.0)) as sock:
            sock.settimeout(min(timeout, 3.0))
            data = sock.recv(256)
            return data.decode("latin-1", errors="ignore").strip()
    except OSError:
        return ""
