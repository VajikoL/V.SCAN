"""Unauthenticated service posture probes (detection only, short timeouts)."""

from __future__ import annotations

import socket

import requests
import urllib3

from vscan.core.discovery import Device
from vscan.core.findings import Finding, cvss_to_severity
from vscan.core.plugins.base import PluginContext

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class UnauthServicePlugin:
    id = "unauth_services"
    name = "Unauthenticated service probes"
    category = "exposure"
    light = True

    def run(self, device: Device, ctx: PluginContext) -> list[Finding]:
        findings: list[Finding] = []
        ports = set(device.open_ports) | {s.port for s in device.services}
        timeout = min(ctx.timeout, 3.0)

        if 21 in ports and _ftp_anonymous(device.ip, timeout):
            findings.append(
                _f(
                    device.ip,
                    21,
                    "VSCAN-FTP-ANON",
                    "Anonymous FTP login allowed",
                    7.5,
                    "Disable anonymous FTP; require authenticated SFTP/FTPS.",
                    "USER anonymous accepted",
                )
            )

        if 6379 in ports and _redis_unauth(device.ip, timeout):
            findings.append(
                _f(
                    device.ip,
                    6379,
                    "VSCAN-REDIS-UNAUTH",
                    "Redis accepts commands without AUTH",
                    9.8,
                    "Enable requirepass / ACL; bind to localhost; block port 6379 externally.",
                    "PING -> PONG",
                )
            )

        if 11211 in ports and _memcached_unauth(device.ip, timeout):
            findings.append(
                _f(
                    device.ip,
                    11211,
                    "VSCAN-MEMCACHED-UNAUTH",
                    "Memcached responds without authentication",
                    8.1,
                    "Bind to localhost; disable UDP; put behind firewall.",
                    "stats",
                )
            )

        if 9200 in ports and _elastic_unauth(device.ip, timeout):
            findings.append(
                _f(
                    device.ip,
                    9200,
                    "VSCAN-ELASTIC-UNAUTH",
                    "Elasticsearch API reachable without auth",
                    8.8,
                    "Enable security features; require credentials; do not expose publicly.",
                    "GET /",
                )
            )

        if 2375 in ports and _docker_unauth(device.ip, timeout):
            findings.append(
                _f(
                    device.ip,
                    2375,
                    "VSCAN-DOCKER-UNAUTH",
                    "Docker Engine API reachable without auth",
                    10.0,
                    "Disable remote Docker API or require mutual TLS; treat as critical.",
                    "GET /version",
                )
            )

        return findings


def _f(ip: str, port: int, plugin_id: str, title: str, cvss: float, rem: str, evidence: str) -> Finding:
    return Finding(
        ip=ip,
        port=port,
        plugin_id=plugin_id,
        title=title,
        severity=cvss_to_severity(cvss),
        cvss=cvss,
        remediation=rem,
        category="exposure",
        service=title.split()[0].lower(),
        description=title,
        evidence=evidence,
    )


def _ftp_anonymous(ip: str, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, 21), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.recv(256)
            sock.sendall(b"USER anonymous\r\n")
            resp = sock.recv(256).decode("latin-1", errors="ignore")
            if resp.startswith("230"):
                return True
            if not resp.startswith("331"):
                return False
            sock.sendall(b"PASS anonymous@example.com\r\n")
            resp2 = sock.recv(256).decode("latin-1", errors="ignore")
            return resp2.startswith("230")
    except OSError:
        return False


def _redis_unauth(ip: str, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, 6379), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"PING\r\n")
            data = sock.recv(64).decode("latin-1", errors="ignore")
            return "PONG" in data
    except OSError:
        return False


def _memcached_unauth(ip: str, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, 11211), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"stats\r\n")
            data = sock.recv(256).decode("latin-1", errors="ignore")
            return "STAT" in data
    except OSError:
        return False


def _elastic_unauth(ip: str, timeout: float) -> bool:
    try:
        resp = requests.get(
            f"http://{ip}:9200/",
            timeout=timeout,
            headers={"User-Agent": "V.SCAN/0.3"},
        )
        if resp.status_code == 200 and ("cluster_name" in resp.text or "tagline" in resp.text):
            return True
    except requests.RequestException:
        pass
    return False


def _docker_unauth(ip: str, timeout: float) -> bool:
    try:
        resp = requests.get(
            f"http://{ip}:2375/version",
            timeout=timeout,
            headers={"User-Agent": "V.SCAN/0.3"},
        )
        if resp.status_code == 200 and ("ApiVersion" in resp.text or "Version" in resp.text):
            return True
    except requests.RequestException:
        pass
    return False
