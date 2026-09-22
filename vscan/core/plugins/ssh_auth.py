"""Credentialed SSH audit — packages, OS, sshd posture, kernel (remediation only)."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess

from vscan.core.discovery import Device
from vscan.core.findings import Finding, cvss_to_severity
from vscan.core.plugins.base import PluginContext
from vscan.core.vuln_scan import fetch_nvd_cves, parse_nvd_item

logger = logging.getLogger(__name__)

_MAX_PACKAGES = 35
_MAX_CVES_PER_PKG = 4
_MAX_CVE_FINDINGS = 35
_MAX_PACKAGES_AUDIT = 120
_MAX_CVES_PER_PKG_AUDIT = 10
_MAX_CVE_FINDINGS_AUDIT = 120

_PRIORITY = re.compile(
    r"^(openssh|openssl|apache|nginx|curl|wget|python3?|php|mysql|mariadb|"
    r"postgresql|bind9?|docker|containerd|sudo|systemd|libc6|linux-image|kernel)",
    re.I,
)


class SshAuthAuditPlugin:
    id = "ssh_auth_audit"
    name = "Credentialed SSH package & config audit"
    category = "auth"
    light = False

    def run(self, device: Device, ctx: PluginContext) -> list[Finding]:
        user = ctx.credentials.get("ssh_user") or ctx.credentials.get("username")
        key = ctx.credentials.get("ssh_key") or ctx.credentials.get("identity_file")
        if not user or not shutil.which("ssh"):
            return []

        ports = set(device.open_ports) | {s.port for s in device.services}
        ssh_ports = [s.port for s in device.services if (s.name or "").lower() == "ssh"]
        if 22 not in ports and not ssh_ports:
            return []

        port = ssh_ports[0] if ssh_ports else 22
        blob = _ssh_collect(device.ip, port, user, key, ctx.timeout)
        if not blob:
            return []

        findings: list[Finding] = []
        findings.extend(_config_findings(device.ip, port, blob))
        findings.extend(_os_kernel_findings(device.ip, port, blob, ctx.allow_network))

        packages = _parse_packages(blob.get("packages", ""))
        max_pkgs = _MAX_PACKAGES_AUDIT if ctx.max_mode else _MAX_PACKAGES
        max_cves_pkg = _MAX_CVES_PER_PKG_AUDIT if ctx.max_mode else _MAX_CVES_PER_PKG
        max_cve_findings = _MAX_CVE_FINDINGS_AUDIT if ctx.max_mode else _MAX_CVE_FINDINGS

        if packages:
            findings.append(
                Finding(
                    ip=device.ip,
                    port=port,
                    plugin_id="VSCAN-AUTH-SSH-OK",
                    title=f"Credentialed SSH audit collected {len(packages)} packages",
                    severity="low",
                    cvss=0.0,
                    remediation="Keep package inventories current and apply security updates promptly.",
                    category="auth",
                    service="ssh",
                    evidence=f"packages={len(packages)}; os={blob.get('os', '')[:80]}",
                )
            )

        cve_count = 0
        for name, version in packages[:max_pkgs]:
            if cve_count >= max_cve_findings:
                break
            items, _ = fetch_nvd_cves(f"{name} {version}", allow_network=ctx.allow_network)
            matched = 0
            for wrapped in items:
                parsed = parse_nvd_item(wrapped)
                if not parsed:
                    continue
                cve_id, score, severity, title, description, published = parsed
                findings.append(
                    Finding(
                        ip=device.ip,
                        port=port,
                        plugin_id=cve_id,
                        title=f"[auth] {title}",
                        severity=severity,
                        cvss=score,
                        remediation=(
                            f"Update package {name} (installed {version}) via the OS package manager. "
                            f"Details: https://nvd.nist.gov/vuln/detail/{cve_id}"
                        ),
                        category="auth",
                        service="ssh-package",
                        product=name,
                        version=version,
                        description=description[:400],
                        nvd_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        published=published,
                    )
                )
                matched += 1
                cve_count += 1
                if matched >= max_cves_pkg or cve_count >= max_cve_findings:
                    break
        return findings


def _ssh_collect(ip: str, port: int, user: str, key: str | None, timeout: float) -> dict[str, str]:
    remote = r"""
echo '###OS###'
(cat /etc/os-release 2>/dev/null || true)
echo '###KERNEL###'
uname -r 2>/dev/null || true
echo '###SSHD###'
(sshd -T 2>/dev/null || grep -E '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|Protocol|X11Forwarding|PermitEmptyPasswords)\b' /etc/ssh/sshd_config 2>/dev/null || true)
echo '###PKGS###'
if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${Package} ${Version}\n';
elif command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n';
elif command -v pacman >/dev/null 2>&1; then pacman -Q; fi
""".strip()
    cmd = [
        "ssh",
        "-p",
        str(port),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        f"ConnectTimeout={max(1, int(timeout))}",
    ]
    if key:
        cmd.extend(["-i", key])
    cmd.extend([f"{user}@{ip}", remote])
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(20.0, timeout * 4),
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("ssh audit failed for %s: %s", ip, exc)
        return {}
    if proc.returncode != 0 and not proc.stdout:
        return {}
    return _split_sections(proc.stdout)


def _split_sections(stdout: str) -> dict[str, str]:
    sections: dict[str, str] = {"os": "", "kernel": "", "sshd": "", "packages": ""}
    current = None
    mapping = {"###OS###": "os", "###KERNEL###": "kernel", "###SSHD###": "sshd", "###PKGS###": "packages"}
    for line in stdout.splitlines():
        key = mapping.get(line.strip())
        if key:
            current = key
            continue
        if current:
            sections[current] += line + "\n"
    return sections


def _parse_packages(text: str) -> list[tuple[str, str]]:
    packages: list[tuple[str, str]] = []
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            packages.append((parts[0], parts[1]))
    packages.sort(key=lambda p: (0 if _PRIORITY.search(p[0]) else 1, p[0]))
    return packages


def _config_findings(ip: str, port: int, blob: dict[str, str]) -> list[Finding]:
    text = blob.get("sshd", "").lower()
    if not text.strip():
        return []
    out: list[Finding] = []

    def has(opt: str, values: tuple[str, ...]) -> bool:
        for line in text.splitlines():
            line = line.strip()
            if line.startswith(opt.lower()):
                return any(v in line for v in values)
        return False

    if has("permitrootlogin", ("yes",)):
        out.append(
            Finding(
                ip=ip,
                port=port,
                plugin_id="VSCAN-AUTH-ROOT-LOGIN",
                title="sshd PermitRootLogin is yes",
                severity=cvss_to_severity(7.2),
                cvss=7.2,
                remediation="Set PermitRootLogin no (or prohibit-password) in sshd_config and reload sshd.",
                category="auth",
                service="ssh",
                evidence="PermitRootLogin yes",
            )
        )
    if has("passwordauthentication", ("yes",)):
        out.append(
            Finding(
                ip=ip,
                port=port,
                plugin_id="VSCAN-AUTH-PASSWD-LOGIN",
                title="sshd PasswordAuthentication is yes",
                severity=cvss_to_severity(5.3),
                cvss=5.3,
                remediation="Prefer key-based auth: PasswordAuthentication no; ensure keys are deployed first.",
                category="auth",
                service="ssh",
                evidence="PasswordAuthentication yes",
            )
        )
    if has("permitemptypasswords", ("yes",)):
        out.append(
            Finding(
                ip=ip,
                port=port,
                plugin_id="VSCAN-AUTH-EMPTY-PASS",
                title="sshd PermitEmptyPasswords is yes",
                severity=cvss_to_severity(9.1),
                cvss=9.1,
                remediation="Set PermitEmptyPasswords no immediately.",
                category="auth",
                service="ssh",
                evidence="PermitEmptyPasswords yes",
            )
        )
    if has("protocol", ("1",)) and "2" not in text:
        out.append(
            Finding(
                ip=ip,
                port=port,
                plugin_id="VSCAN-AUTH-SSH-PROTO1",
                title="sshd Protocol includes SSH-1",
                severity=cvss_to_severity(9.0),
                cvss=9.0,
                remediation="Use Protocol 2 only (or modern OpenSSH defaults).",
                category="auth",
                service="ssh",
                evidence="Protocol 1",
            )
        )
    return out


def _os_kernel_findings(ip: str, port: int, blob: dict[str, str], allow_network: bool) -> list[Finding]:
    out: list[Finding] = []
    os_text = blob.get("os", "")
    kernel = blob.get("kernel", "").strip().splitlines()
    kernel_ver = kernel[0].strip() if kernel else ""

    pretty = ""
    for line in os_text.splitlines():
        if line.startswith("PRETTY_NAME="):
            pretty = line.split("=", 1)[1].strip().strip('"')
            break

    if pretty:
        out.append(
            Finding(
                ip=ip,
                port=port,
                plugin_id="VSCAN-AUTH-OS-INFO",
                title=f"Remote OS: {pretty}",
                severity="low",
                cvss=0.0,
                remediation="Keep the OS on a supported release and apply security updates.",
                category="auth",
                service="ssh",
                evidence=pretty[:160],
            )
        )
        # EOL hints (lightweight heuristics)
        low = pretty.lower()
        if any(x in low for x in ("ubuntu 16.", "ubuntu 18.04", "centos linux 7", "debian gnu/linux 9", "windows xp")):
            out.append(
                Finding(
                    ip=ip,
                    port=port,
                    plugin_id="VSCAN-AUTH-OS-EOL",
                    title=f"Possibly end-of-life OS: {pretty}",
                    severity=cvss_to_severity(8.5),
                    cvss=8.5,
                    remediation="Migrate to a vendor-supported OS release; isolate until upgraded.",
                    category="auth",
                    service="ssh",
                    evidence=pretty[:160],
                )
            )

    if kernel_ver and allow_network:
        items, _ = fetch_nvd_cves(f"linux kernel {kernel_ver.split('-')[0]}", allow_network=True)
        matched = 0
        for wrapped in items:
            parsed = parse_nvd_item(wrapped)
            if not parsed:
                continue
            cve_id, score, severity, title, description, published = parsed
            if score < 7.0:
                continue
            out.append(
                Finding(
                    ip=ip,
                    port=port,
                    plugin_id=cve_id,
                    title=f"[kernel] {title}",
                    severity=severity,
                    cvss=score,
                    remediation=(
                        f"Update the kernel (running {kernel_ver}) via the OS package manager and reboot. "
                        f"Details: https://nvd.nist.gov/vuln/detail/{cve_id}"
                    ),
                    category="auth",
                    service="kernel",
                    product="linux_kernel",
                    version=kernel_ver,
                    description=description[:400],
                    nvd_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    published=published,
                )
            )
            matched += 1
            if matched >= 3:
                break
    return out
