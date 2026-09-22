"""SMB posture hints from nmap service fingerprints."""

from __future__ import annotations

from vscan.core.discovery import Device
from vscan.core.findings import Finding, cvss_to_severity
from vscan.core.plugins.base import PluginContext


class SmbChecksPlugin:
    id = "smb_checks"
    name = "SMB posture"
    category = "smb"
    light = True

    def run(self, device: Device, ctx: PluginContext) -> list[Finding]:
        findings: list[Finding] = []
        for svc in device.services:
            if svc.port not in {139, 445} and "smb" not in (svc.name or "").lower():
                continue
            blob = " ".join(
                p for p in (svc.name, svc.product, svc.version, svc.extrainfo, svc.cpe) if p
            ).lower()
            if "smbv1" in blob or "samba 1" in blob or "smb1" in blob:
                findings.append(
                    Finding(
                        ip=device.ip,
                        port=svc.port,
                        plugin_id="VSCAN-SMB-V1",
                        title="SMBv1 protocol indicated",
                        severity=cvss_to_severity(8.1),
                        cvss=8.1,
                        remediation="Disable SMBv1 on all hosts; enforce SMB 2.1+/3.x with signing.",
                        category="smb",
                        service=svc.name or "smb",
                        product=svc.product,
                        version=svc.version,
                        description="SMBv1 is obsolete and associated with wormable flaws.",
                        evidence=blob[:200],
                    )
                )
            if "windows xp" in blob or "windows 2003" in blob or "windows 2000" in blob:
                findings.append(
                    Finding(
                        ip=device.ip,
                        port=svc.port,
                        plugin_id="VSCAN-SMB-EOL-OS",
                        title="End-of-life OS indicated via SMB fingerprint",
                        severity=cvss_to_severity(9.0),
                        cvss=9.0,
                        remediation="Migrate off EOL operating systems; isolate until replaced.",
                        category="smb",
                        service=svc.name or "smb",
                        description=blob[:200],
                        evidence=blob[:200],
                    )
                )
        return findings
