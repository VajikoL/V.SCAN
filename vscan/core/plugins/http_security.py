"""HTTP security header / exposure checks."""

from __future__ import annotations

import requests
import urllib3

from vscan.core.discovery import Device
from vscan.core.findings import Finding, cvss_to_severity
from vscan.core.plugins.base import PluginContext

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 3000, 5000}
_IMPORTANT = (
    ("strict-transport-security", "VSCAN-HTTP-HSTS", "Missing Strict-Transport-Security", 5.3,
     "Enable HSTS (Strict-Transport-Security) on HTTPS endpoints."),
    ("content-security-policy", "VSCAN-HTTP-CSP", "Missing Content-Security-Policy", 4.3,
     "Add a Content-Security-Policy tailored to the application."),
    ("x-frame-options", "VSCAN-HTTP-XFO", "Missing X-Frame-Options / frame-ancestors", 4.0,
     "Set X-Frame-Options DENY/SAMEORIGIN or CSP frame-ancestors."),
    ("x-content-type-options", "VSCAN-HTTP-XCTO", "Missing X-Content-Type-Options", 3.7,
     "Set X-Content-Type-Options: nosniff."),
)


class HttpSecurityPlugin:
    id = "http_security"
    name = "HTTP security headers"
    category = "web"
    light = True

    def run(self, device: Device, ctx: PluginContext) -> list[Finding]:
        findings: list[Finding] = []
        ports = sorted(
            {s.port for s in device.services if _is_http(s.name, s.port)}
            | {p for p in device.open_ports if p in _HTTP_PORTS}
        )
        if ctx.light and not ctx.max_mode:
            ports = ports[:3]
        for port in ports:
            findings.extend(self._check(device.ip, port, ctx.timeout))
        return findings

    def _check(self, ip: str, port: int, timeout: float) -> list[Finding]:
        out: list[Finding] = []
        schemes = ("https", "http") if port in {443, 8443, 9443} else ("http", "https")
        headers = None
        used = ""
        for scheme in schemes:
            url = f"{scheme}://{ip}:{port}/"
            try:
                resp = requests.get(
                    url,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": "V.SCAN/0.3 (authorized-assessment)"},
                )
                headers = {k.lower(): v for k, v in resp.headers.items()}
                used = scheme
                # Server banner disclosure
                server = headers.get("server")
                if server and any(ch.isdigit() for ch in server):
                    out.append(
                        Finding(
                            ip=ip,
                            port=port,
                            plugin_id="VSCAN-HTTP-BANNER",
                            title="HTTP Server banner discloses version",
                            severity=cvss_to_severity(3.1),
                            cvss=3.1,
                            remediation="Suppress or generalize the Server header; keep software patched.",
                            category="web",
                            service="http",
                            description=server,
                            evidence=f"Server: {server}",
                        )
                    )
                break
            except requests.RequestException:
                continue
        if not headers:
            return out

        # HSTS only meaningful on HTTPS
        for header, plugin_id, title, cvss, fix in _IMPORTANT:
            if header == "strict-transport-security" and used != "https":
                continue
            if header not in headers:
                # CSP alternative via frame-ancestors covered separately for XFO
                if header == "x-frame-options" and "content-security-policy" in headers:
                    if "frame-ancestors" in headers["content-security-policy"].lower():
                        continue
                out.append(
                    Finding(
                        ip=ip,
                        port=port,
                        plugin_id=plugin_id,
                        title=title,
                        severity=cvss_to_severity(cvss),
                        cvss=cvss,
                        remediation=fix,
                        category="web",
                        service="http",
                        description=title,
                        evidence=f"url={used}://{ip}:{port}/",
                    )
                )
        return out


def _is_http(name: str, port: int) -> bool:
    n = (name or "").lower()
    return port in _HTTP_PORTS or n in {"http", "https", "http-proxy", "http-alt"}
