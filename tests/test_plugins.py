"""Tests for plugin findings and risk scoring."""

from __future__ import annotations

from vscan.core.discovery import Device, ServiceInfo
from vscan.core.findings import Finding, compute_risk_score, dedupe_findings
from vscan.core.plugins.dangerous_services import DangerousServicesPlugin
from vscan.core.plugins.base import PluginContext
from vscan.core.plugins import list_plugins, select_plugins
from vscan.i18n import init_i18n


def test_list_plugins_nonempty() -> None:
    plugins = list_plugins()
    ids = {p.id for p in plugins}
    assert "dangerous_services" in ids
    assert "ssl_tls" in ids
    assert "http_security" in ids
    assert "unauth_services" in ids
    assert "snmp_checks" in ids
    assert "ssh_banner" in ids


def test_select_plugins_light_skips_auth() -> None:
    light = select_plugins(light=True, include_auth=False)
    assert all(p.light for p in light)
    assert all(p.id != "ssh_auth_audit" for p in light)


def test_dangerous_services_flags_telnet_and_docker() -> None:
    init_i18n("en")
    device = Device(ip="10.0.0.9", open_ports=[23, 2375, 80])
    findings = DangerousServicesPlugin().run(device, PluginContext())
    ids = {f.plugin_id for f in findings}
    assert "VSCAN-TELNET" in ids
    assert "VSCAN-DOCKER-API" in ids


def test_risk_score_increases_with_critical() -> None:
    from vscan.core.findings import risk_breakdown

    low = [Finding(ip="1.1.1.1", port=1, plugin_id="A", title="a", severity="low", cvss=2.0, remediation="x")]
    crit = low + [
        Finding(
            ip="1.1.1.1",
            port=6379,
            plugin_id="B",
            title="b",
            severity="critical",
            cvss=9.8,
            remediation="x",
            category="exposure",
        )
    ]
    assert compute_risk_score(crit) > compute_risk_score(low)
    assert "exposure" in risk_breakdown(crit)


def test_dedupe_keeps_higher_severity() -> None:
    a = Finding(ip="1.1.1.1", port=80, plugin_id="X", title="t", severity="low", cvss=2.0, remediation="r")
    b = Finding(ip="1.1.1.1", port=80, plugin_id="X", title="t", severity="high", cvss=8.0, remediation="r")
    out = dedupe_findings([a, b])
    assert len(out) == 1
    assert out[0].severity == "high"


def test_smb_plugin_smbv1() -> None:
    from vscan.core.plugins.smb_checks import SmbChecksPlugin

    device = Device(
        ip="10.0.0.8",
        services=[ServiceInfo(port=445, name="microsoft-ds", product="Windows", extrainfo="SMBv1")],
    )
    findings = SmbChecksPlugin().run(device, PluginContext())
    assert any(f.plugin_id == "VSCAN-SMB-V1" for f in findings)


def test_ssh_banner_old_openssh(monkeypatch) -> None:
    from vscan.core.plugins import ssh_banner as mod

    monkeypatch.setattr(mod, "_read_banner", lambda ip, port, timeout: "SSH-2.0-OpenSSH_6.6p1")
    device = Device(ip="10.0.0.7", open_ports=[22])
    findings = mod.SshBannerPlugin().run(device, PluginContext())
    assert any(f.plugin_id == "VSCAN-SSH-OLD" for f in findings)


def test_ssh_auth_config_findings() -> None:
    from vscan.core.plugins.ssh_auth import _config_findings

    blob = {"sshd": "permitrootlogin yes\npasswordauthentication yes\n"}
    findings = _config_findings("10.0.0.5", 22, blob)
    ids = {f.plugin_id for f in findings}
    assert "VSCAN-AUTH-ROOT-LOGIN" in ids
    assert "VSCAN-AUTH-PASSWD-LOGIN" in ids
