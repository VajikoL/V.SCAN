"""History / diff tests."""

from __future__ import annotations

from vscan.core.discovery import Device
from vscan.core.vuln_scan import VulnerabilityFinding
from vscan.db import store
from vscan.i18n import init_i18n


def test_save_and_diff(tmp_path, monkeypatch) -> None:
    init_i18n("en")
    db_path = tmp_path / "history.db"
    monkeypatch.setattr("vscan.db.models.HISTORY_DB", db_path)
    monkeypatch.setattr("vscan.config.HISTORY_DB", db_path)
    # Reset engine singleton
    store_mod = store
    import vscan.db.models as models

    models._engine = None
    models._Session = None

    d1 = Device(ip="192.168.1.10", hostname="a", open_ports=[80, 443])
    d2 = Device(ip="192.168.1.11", hostname="b", open_ports=[22])
    f1 = VulnerabilityFinding(
        ip="192.168.1.10",
        port=80,
        service="http",
        product="Apache",
        version="2.4.49",
        cve_id="CVE-2021-41773",
        cvss=9.8,
        severity="critical",
        title="test",
        description="test",
        remediation="upgrade",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
    )

    id1 = store.save_scan(target="192.168.1.0/24", profile="balanced", devices=[d1, d2], findings=[f1])
    id2 = store.save_scan(
        target="192.168.1.0/24",
        profile="balanced",
        devices=[Device(ip="192.168.1.10", open_ports=[80]), Device(ip="192.168.1.12", open_ports=[445])],
        findings=[],
    )

    diff = store.diff_scans(id1, id2)
    assert any(d["ip"] == "192.168.1.12" for d in diff["new_devices"])
    assert any(d["ip"] == "192.168.1.11" for d in diff["missing_devices"])
    assert any(p["port"] == "443" for p in diff["closed_ports"])
