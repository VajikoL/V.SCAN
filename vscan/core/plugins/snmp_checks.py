"""SNMP community exposure check (default 'public' only — no brute force)."""

from __future__ import annotations

import socket

from vscan.core.discovery import Device
from vscan.core.findings import Finding, cvss_to_severity
from vscan.core.plugins.base import PluginContext


class SnmpChecksPlugin:
    id = "snmp_checks"
    name = "SNMP default community"
    category = "snmp"
    light = True

    def run(self, device: Device, ctx: PluginContext) -> list[Finding]:
        ports = set(device.open_ports) | {s.port for s in device.services}
        names = " ".join(s.name for s in device.services).lower()
        if 161 not in ports and "snmp" not in names:
            return []
        if _snmp_public_responds(device.ip, ctx.timeout):
            return [
                Finding(
                    ip=device.ip,
                    port=161,
                    plugin_id="VSCAN-SNMP-PUBLIC",
                    title="SNMP responds to community 'public'",
                    severity=cvss_to_severity(7.5),
                    cvss=7.5,
                    remediation=(
                        "Disable SNMPv1/v2c or change the community string; prefer SNMPv3 authPriv; "
                        "restrict SNMP by ACL/firewall."
                    ),
                    category="snmp",
                    service="snmp",
                    description="Default community strings allow information disclosure.",
                    evidence="community=public",
                )
            ]
        return []


def _snmp_public_responds(ip: str, timeout: float) -> bool:
    """Minimal SNMPv2c GET for sysDescr.0 with community public."""
    # SNMP GET PDU (simplified BER) for 1.3.6.1.2.1.1.1.0
    community = b"public"
    # Version=1 (SNMPv2c), community, GET request
    oid = bytes([0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
    varbind = bytes([0x30, len(oid) + 2, *oid, 0x05, 0x00])  # NULL
    varbind_list = bytes([0x30, len(varbind), *varbind])
    pdu_body = bytes([0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]) + varbind_list
    pdu = bytes([0xA0, len(pdu_body), *pdu_body])
    body = bytes([0x02, 0x01, 0x01, 0x04, len(community), *community]) + pdu
    packet = bytes([0x30, len(body), *body])
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(min(timeout, 3.0))
        sock.sendto(packet, (ip, 161))
        data, _ = sock.recvfrom(2048)
        sock.close()
        return len(data) > 10
    except OSError:
        return False
