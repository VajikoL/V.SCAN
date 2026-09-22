"""Expanded high-risk service exposure map (light, port-based)."""

from __future__ import annotations

from vscan.core.discovery import Device
from vscan.core.findings import Finding, cvss_to_severity
from vscan.core.plugins.base import PluginContext

# port → (plugin_id, title, cvss, remediation)
_RISKY: dict[int, tuple[str, str, float, str]] = {
    21: ("VSCAN-FTP-OPEN", "FTP service exposed", 5.3,
         "Prefer SFTP/FTPS; disable anonymous access; restrict by firewall."),
    23: ("VSCAN-TELNET", "Telnet service exposed (cleartext)", 9.1,
         "Disable Telnet; use SSH. Cleartext remote access is critical risk."),
    69: ("VSCAN-TFTP", "TFTP service exposed", 7.5,
         "Disable TFTP on production networks or isolate tightly."),
    111: ("VSCAN-RPCBIND", "RPC bind / portmapper exposed", 5.9,
          "Do not expose rpcbind to untrusted networks."),
    135: ("VSCAN-MSRPC", "MSRPC endpoint mapper exposed", 5.9,
          "Block TCP/135 from untrusted networks; use VPN for admin."),
    139: ("VSCAN-NETBIOS", "NetBIOS session service exposed", 5.0,
          "Disable SMBv1/NetBIOS where possible; restrict SMB."),
    161: ("VSCAN-SNMP", "SNMP service exposed", 5.9,
          "Restrict SNMP; use SNMPv3 with authPriv; never use community 'public'."),
    445: ("VSCAN-SMB", "SMB file sharing exposed", 6.5,
          "Restrict SMB to trusted hosts; disable SMBv1; require signing."),
    512: ("VSCAN-REXEC", "rexec service exposed", 9.8,
          "Disable rexec immediately; use SSH with key authentication."),
    513: ("VSCAN-RLOGIN", "rlogin service exposed", 9.8,
          "Disable rlogin immediately; use SSH."),
    514: ("VSCAN-RSH", "rsh service exposed", 9.8,
          "Disable rsh immediately; use SSH."),
    873: ("VSCAN-RSYNC", "rsync daemon exposed", 6.5,
          "Require authentication; bind to localhost or trusted nets only."),
    1433: ("VSCAN-MSSQL", "Microsoft SQL Server exposed", 7.5,
           "Do not expose MSSQL publicly; require VPN and strong auth."),
    1521: ("VSCAN-ORACLE", "Oracle listener exposed", 7.5,
           "Restrict Oracle listener to trusted networks only."),
    2375: ("VSCAN-DOCKER-API", "Docker API exposed without TLS", 9.8,
           "Never expose Docker API on 2375; use TLS (2376) + auth or disable remote API."),
    2376: ("VSCAN-DOCKER-TLS", "Docker API (TLS port) exposed", 6.5,
           "Ensure client cert auth is mandatory; restrict by firewall."),
    3306: ("VSCAN-MYSQL", "MySQL/MariaDB exposed", 7.5,
           "Bind database to localhost/private net; require strong auth and TLS."),
    3389: ("VSCAN-RDP", "Remote Desktop (RDP) exposed", 7.2,
           "Do not expose RDP publicly; use VPN/NLA; keep patched."),
    5432: ("VSCAN-POSTGRES", "PostgreSQL exposed", 7.5,
           "Bind PostgreSQL to private interfaces; require auth + TLS."),
    5601: ("VSCAN-KIBANA", "Kibana exposed", 6.5,
           "Require auth; do not expose Kibana to untrusted networks."),
    5900: ("VSCAN-VNC", "VNC remote desktop exposed", 8.1,
           "Disable public VNC; tunnel over SSH/VPN."),
    6379: ("VSCAN-REDIS", "Redis exposed", 9.1,
           "Never expose Redis publicly; require AUTH and bind to localhost."),
    6443: ("VSCAN-K8S-API", "Kubernetes API server port exposed", 8.1,
           "Restrict kube-apiserver to trusted nets; enforce RBAC and TLS auth."),
    9200: ("VSCAN-ELASTIC", "Elasticsearch HTTP API exposed", 8.8,
           "Enable auth (xpack/security); never expose Elasticsearch publicly."),
    11211: ("VSCAN-MEMCACHED", "Memcached exposed", 8.1,
            "Bind Memcached to localhost; disable UDP if unused (amplification risk)."),
    27017: ("VSCAN-MONGODB", "MongoDB exposed", 9.1,
            "Enable auth, bind to private interfaces, never expose publicly."),
}


class DangerousServicesPlugin:
    id = "dangerous_services"
    name = "High-risk service exposure"
    category = "exposure"
    light = True

    def run(self, device: Device, ctx: PluginContext) -> list[Finding]:
        ports = set(device.open_ports) | {s.port for s in device.services}
        findings: list[Finding] = []
        for port in sorted(ports):
            meta = _RISKY.get(port)
            if not meta:
                continue
            plugin_id, title, cvss, rem = meta
            svc = next((s.name for s in device.services if s.port == port), "")
            findings.append(
                Finding(
                    ip=device.ip,
                    port=port,
                    plugin_id=plugin_id,
                    title=title,
                    severity=cvss_to_severity(cvss),
                    cvss=cvss,
                    remediation=rem,
                    category="exposure",
                    service=svc or title.split()[0].lower(),
                    description=title,
                    evidence=f"open_port={port}",
                )
            )
        return findings
