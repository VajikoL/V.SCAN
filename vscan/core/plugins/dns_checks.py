"""DNS recursion / exposure checks."""

from __future__ import annotations

import socket
import struct

from vscan.core.discovery import Device
from vscan.core.findings import Finding, cvss_to_severity
from vscan.core.plugins.base import PluginContext


class DnsChecksPlugin:
    id = "dns_checks"
    name = "DNS exposure"
    category = "dns"
    light = True

    def run(self, device: Device, ctx: PluginContext) -> list[Finding]:
        ports = set(device.open_ports) | {s.port for s in device.services}
        names = {s.name.lower() for s in device.services}
        if 53 not in ports and "domain" not in names and "dns" not in names:
            return []
        if _recursion_available(device.ip, ctx.timeout):
            return [
                Finding(
                    ip=device.ip,
                    port=53,
                    plugin_id="VSCAN-DNS-RECURSION",
                    title="DNS server allows recursion",
                    severity=cvss_to_severity(5.3),
                    cvss=5.3,
                    remediation="Disable recursion for untrusted clients or restrict with ACLs; mitigate amplification risk.",
                    category="dns",
                    service="dns",
                    description="Open/recursive DNS can be abused for amplification.",
                    evidence="recursion_available=true",
                )
            ]
        return []


def _recursion_available(ip: str, timeout: float) -> bool:
    """Send a minimal DNS query with RD=1 and check RA bit in response."""
    # Query A for example.com
    txid = 0x1337
    flags = 0x0100  # RD
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    qname = b"".join(len(p).to_bytes(1, "big") + p.encode() for p in "example.com".split(".")) + b"\x00"
    question = qname + struct.pack("!HH", 1, 1)
    packet = header + question
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (ip, 53))
        data, _ = sock.recvfrom(512)
        sock.close()
    except OSError:
        return False
    if len(data) < 4:
        return False
    resp_flags = struct.unpack("!H", data[2:4])[0]
    # RA bit is 0x0080
    return bool(resp_flags & 0x0080)
