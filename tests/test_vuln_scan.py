"""Tests for vulnerability matching and nmap XML parsing."""

from __future__ import annotations

from vscan.core.discovery import Device, ServiceInfo, parse_nmap_xml
from vscan.core.vuln_scan import (
    build_remediation,
    build_search_query,
    cvss_to_severity,
    extract_cvss,
    findings_for_service,
    parse_nvd_item,
)
from vscan.i18n import init_i18n


SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.49" method="probed">
          <cpe>cpe:/a:apache:http_server:2.4.49</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.x" accuracy="90"/>
    </os>
  </host>
</nmaprun>
"""


def test_parse_nmap_xml_open_services_only() -> None:
    services, os_guess = parse_nmap_xml(SAMPLE_NMAP_XML)
    assert os_guess == "Linux 5.x"
    assert [s.port for s in services] == [80, 443]
    http = services[0]
    assert http.name == "http"
    assert http.product == "Apache httpd"
    assert http.version == "2.4.49"
    assert "apache" in http.cpe


def test_cvss_severity_buckets() -> None:
    assert cvss_to_severity(9.8) == "critical"
    assert cvss_to_severity(7.5) == "high"
    assert cvss_to_severity(5.0) == "medium"
    assert cvss_to_severity(2.1) == "low"
    assert cvss_to_severity(0.0) == "none"


def test_extract_cvss_prefers_v31() -> None:
    metrics = {
        "cvssMetricV30": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}],
        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
    }
    score, severity = extract_cvss(metrics)
    assert score == 9.8
    assert severity == "critical"


def test_build_search_query() -> None:
    svc = ServiceInfo(port=80, name="http", product="Apache httpd", version="2.4.49")
    assert build_search_query(svc) == "Apache httpd 2.4.49"
    assert build_search_query(ServiceInfo(port=80, name="http")) is None


def test_build_remediation_mentions_upgrade_and_nvd() -> None:
    init_i18n("en")
    advice = build_remediation(
        product="Apache httpd",
        version="2.4.49",
        service_name="http",
        port=80,
        cve_id="CVE-2021-41773",
        description="Path traversal fixed in 2.4.51 before authentication.",
    )
    assert "Upgrade" in advice or "upgrade" in advice.lower() or "Patch" in advice or "patch" in advice.lower()
    assert "CVE-2021-41773" in advice
    assert "2.4.51" in advice


def test_parse_nvd_item() -> None:
    item = {
        "cve": {
            "id": "CVE-2021-41773",
            "published": "2021-10-05T00:00:00.000",
            "descriptions": [
                {"lang": "en", "value": "Apache HTTP Server path traversal. Fixed in 2.4.51."}
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                        }
                    }
                ]
            },
        }
    }
    parsed = parse_nvd_item(item)
    assert parsed is not None
    cve_id, score, severity, title, description, published = parsed
    assert cve_id == "CVE-2021-41773"
    assert score == 7.5
    assert severity == "high"
    assert "path traversal" in description.lower()
    assert published.startswith("2021")


def test_findings_for_service_uses_cache(tmp_path, monkeypatch) -> None:
    init_i18n("en")
    from vscan.core import vuln_scan as vs

    monkeypatch.setattr(vs, "CVE_CACHE_DIR", tmp_path)
    monkeypatch.setattr(vs, "CACHE_DIR", tmp_path)

    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-41773",
                    "published": "2021-10-05T00:00:00.000",
                    "descriptions": [
                        {"lang": "en", "value": "Path traversal fixed in 2.4.51."}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                        ]
                    },
                }
            }
        ]
    }

    def fake_fetch(query: str, *, allow_network: bool = True):
        return payload["vulnerabilities"], True

    monkeypatch.setattr(vs, "fetch_nvd_cves", fake_fetch)

    device = Device(ip="192.168.1.10")
    service = ServiceInfo(port=80, name="http", product="Apache httpd", version="2.4.49")
    findings, from_cache = findings_for_service(device, service)
    assert from_cache is True
    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2021-41773"
    assert findings[0].severity == "critical"
    assert "nvd.nist.gov" in findings[0].nvd_url
    assert findings[0].remediation
