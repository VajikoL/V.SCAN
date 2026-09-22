"""TLS/SSL configuration checks (certificate + protocol posture)."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from vscan.core.discovery import Device
from vscan.core.findings import Finding, cvss_to_severity
from vscan.core.plugins.base import PluginContext

_TLS_PORTS = {443, 8443, 9443, 993, 995, 465, 636, 3389, 5986}


class SslTlsPlugin:
    id = "ssl_tls"
    name = "TLS/SSL posture"
    category = "crypto"
    light = True

    def run(self, device: Device, ctx: PluginContext) -> list[Finding]:
        findings: list[Finding] = []
        ports = {s.port for s in device.services} | set(device.open_ports)
        candidates = sorted(p for p in ports if p in _TLS_PORTS or _looks_tls(device, p))
        if ctx.light and not ctx.max_mode:
            candidates = candidates[:4]
        for port in candidates:
            findings.extend(self._check_port(device.ip, port, ctx.timeout))
        return findings

    def _check_port(self, ip: str, port: int, timeout: float) -> list[Finding]:
        out: list[Finding] = []
        # Prefer modern TLS; also probe for legacy acceptance.
        try:
            cert = _fetch_cert(ip, port, timeout, minimum_version=ssl.TLSVersion.TLSv1_2)
        except ssl.SSLError:
            # Server may only speak older TLS — flag that.
            out.append(
                _finding(
                    ip,
                    port,
                    "VSCAN-TLS-LEGACY",
                    "Server negotiates legacy TLS only",
                    7.5,
                    "Disable TLS 1.0/1.1; require TLS 1.2+ with modern cipher suites.",
                    "Handshake failed with TLS 1.2 minimum.",
                )
            )
            try:
                cert = _fetch_cert(ip, port, timeout, minimum_version=None)
            except Exception:
                return out
        except (OSError, TimeoutError, ValueError):
            return out

        if not cert:
            return out

        not_after = cert.get("notAfter")
        if not_after:
            try:
                expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                days = (expires - datetime.now(timezone.utc)).days
                if days < 0:
                    out.append(
                        _finding(
                            ip,
                            port,
                            "VSCAN-TLS-EXPIRED",
                            "TLS certificate expired",
                            8.1,
                            "Renew the certificate immediately and automate renewal (ACME/Let's Encrypt or enterprise PKI).",
                            f"notAfter={not_after}",
                        )
                    )
                elif days <= 30:
                    out.append(
                        _finding(
                            ip,
                            port,
                            "VSCAN-TLS-EXPIRE-SOON",
                            "TLS certificate expires within 30 days",
                            5.3,
                            "Schedule certificate renewal before expiry; enable monitoring alerts.",
                            f"days_left={days}; notAfter={not_after}",
                        )
                    )
            except ValueError:
                pass

        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        if subject and issuer and subject == issuer:
            out.append(
                _finding(
                    ip,
                    port,
                    "VSCAN-TLS-SELF-SIGNED",
                    "Self-signed TLS certificate",
                    5.0,
                    "Replace with a certificate from a trusted CA for production services.",
                    f"subject={subject.get('commonName', '')}",
                )
            )
        return out


def _looks_tls(device: Device, port: int) -> bool:
    for svc in device.services:
        if svc.port != port:
            continue
        blob = f"{svc.name} {svc.product}".lower()
        return any(tok in blob for tok in ("ssl", "tls", "https", "https-alt"))
    return False


def _fetch_cert(
    ip: str,
    port: int,
    timeout: float,
    *,
    minimum_version: ssl.TLSVersion | None,
) -> dict:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if minimum_version is not None:
        context.minimum_version = minimum_version
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=ip) as ssock:
            return ssock.getpeercert()


def _finding(
    ip: str,
    port: int,
    plugin_id: str,
    title: str,
    cvss: float,
    remediation: str,
    evidence: str,
) -> Finding:
    return Finding(
        ip=ip,
        port=port,
        plugin_id=plugin_id,
        title=title,
        severity=cvss_to_severity(cvss),
        cvss=cvss,
        remediation=remediation,
        category="crypto",
        service="ssl/tls",
        description=title,
        evidence=evidence,
    )
