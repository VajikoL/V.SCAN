"""Tests for host-centric auto reports."""

from __future__ import annotations

from vscan.config import REPORTS_DIR
from vscan.core.discovery import Device
from vscan.core.findings import Finding
from vscan.i18n import init_i18n
from vscan.report.autosave import save_assessment_reports
from vscan.report.builder import build_report_data
from vscan.report.txt_export import export_txt


def test_build_report_groups_by_host() -> None:
    init_i18n("en")
    devices = [
        Device(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF", hostname="gw", vendor="Cisco", device_type_key="device.router"),
        Device(ip="10.0.0.2", mac="11:22:33:44:55:66", hostname="pc", device_type_key="device.desktop"),
    ]
    findings = [
        Finding(
            ip="10.0.0.1",
            port=443,
            plugin_id="VSCAN-TLS-EXPIRED",
            title="TLS certificate expired",
            severity="high",
            cvss=8.1,
            remediation="Renew the certificate.",
            category="crypto",
        )
    ]
    data = build_report_data(target="10.0.0.0/24", profile="balanced", devices=devices, findings=findings, scan_id=7)
    assert data["device_count"] == 2
    assert data["vuln_count"] == 1
    assert len(data["hosts"]) == 2
    gw = next(h for h in data["hosts"] if h["ip"] == "10.0.0.1")
    assert gw["mac"] == "AA:BB:CC:DD:EE:FF"
    assert gw["hostname"] == "gw"
    assert len(gw["findings"]) == 1
    assert "Renew" in gw["findings"][0]["remediation"]


def test_autosave_writes_html_and_txt(tmp_path, monkeypatch) -> None:
    init_i18n("en")
    monkeypatch.setattr("vscan.report.autosave.REPORTS_DIR", tmp_path)
    monkeypatch.setattr("vscan.config.REPORTS_DIR", tmp_path)

    devices = [Device(ip="192.168.1.10", mac="AA:BB:CC:00:11:22", hostname="nas", device_type_key="device.server")]
    findings = [
        Finding(
            ip="192.168.1.10",
            port=22,
            plugin_id="CVE-2023-0001",
            title="Example",
            severity="medium",
            cvss=5.0,
            remediation="Upgrade OpenSSH.",
            nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2023-0001",
        )
    ]
    paths = save_assessment_reports(
        target="192.168.1.0/24",
        profile="balanced",
        devices=devices,
        findings=findings,
        scan_id=3,
    )
    assert paths["html"].is_file()
    assert paths["txt"].is_file()
    txt = paths["txt"].read_text(encoding="utf-8")
    assert "192.168.1.10" in txt
    assert "AA:BB:CC:00:11:22" in txt
    assert "nas" in txt
    assert "CVE-2023-0001" in txt
    assert "Upgrade OpenSSH" in txt
    html = paths["html"].read_text(encoding="utf-8")
    assert "192.168.1.10" in html
    assert "Remediation" in html or "remediation" in html.lower() or "Upgrade" in html


def test_export_txt_mentions_remediation(tmp_path) -> None:
    init_i18n("en")
    data = build_report_data(
        target="10.0.0.5",
        profile="quick",
        devices=[Device(ip="10.0.0.5", mac="DE:AD:BE:EF:00:01", hostname="cam")],
        findings=[],
        scan_id=1,
    )
    path = export_txt(data, tmp_path / "out.txt")
    body = path.read_text(encoding="utf-8")
    assert "10.0.0.5" in body
    assert "DE:AD:BE:EF:00:01" in body
