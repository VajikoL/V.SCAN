"""HTML report — host-centric (IP / MAC / name / vulns / remediation)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Template

from vscan import __app_name__, __author__, __version__
from vscan.i18n import t
from vscan.report.builder import build_report_data

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{{ app }} — {{ t_report_title }} #{{ scan.id }}</title>
<style>
:root {
  --bg:#0a0f0a; --fg:#c8f0c8; --accent:#33ff66; --muted:#5a8a5a;
  --critical:#ff3333; --high:#ff8800; --medium:#e6c200; --low:#33cc66;
  --card:#101810; --border:#1e3a1e; --card2:#0d140d;
}
*{box-sizing:border-box}
body{margin:0;font-family:ui-monospace,"Cascadia Code","Share Tech Mono",monospace;
 background:var(--bg);color:var(--fg);padding:1.5rem;line-height:1.45}
h1,h2,h3{color:var(--accent);letter-spacing:.03em;margin:0 0 .6rem}
.meta,.footer{color:var(--muted)}
.banner{font-size:1.5rem;color:var(--accent);margin:0 0 .8rem;letter-spacing:.2em}
.summary{display:flex;flex-wrap:wrap;gap:.8rem 1.2rem;margin:1rem 0 1.5rem;padding:1rem;
 background:var(--card);border:1px solid var(--border)}
.summary span{white-space:nowrap}
.host{margin:1.4rem 0;padding:1rem 1.1rem;background:var(--card);border:1px solid var(--border)}
.host h2{font-size:1.15rem;margin-bottom:.5rem}
.host-meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.35rem .9rem;
 margin-bottom:1rem;color:var(--muted);font-size:.92rem}
.host-meta b{color:var(--fg)}
.finding{margin:.7rem 0;padding:.75rem .85rem;background:var(--card2);border-left:3px solid var(--muted)}
.finding.sev-critical{border-left-color:var(--critical)}
.finding.sev-high{border-left-color:var(--high)}
.finding.sev-medium{border-left-color:var(--medium)}
.finding.sev-low{border-left-color:var(--low)}
.finding .head{font-weight:700;margin-bottom:.35rem}
.sev-critical{color:var(--critical)} .sev-high{color:var(--high)}
.sev-medium{color:var(--medium)} .sev-low{color:var(--low)}
.rem{margin-top:.4rem;padding:.5rem .6rem;border:1px dashed var(--border);color:var(--fg)}
.rem label{color:var(--accent);font-size:.85rem;display:block;margin-bottom:.2rem}
a{color:var(--accent)}
.clean{color:var(--low);margin:.4rem 0}
.footer{margin-top:2rem;font-size:.85rem}
</style>
</head>
<body>
<div class="banner">V . SCAN</div>
<h1>{{ t_report_title }}</h1>
<p class="meta">{{ author }} · v{{ version }} · {{ t_tagline }}</p>
<p class="meta">{{ t_scan_id }}: #{{ scan.id }} · {{ scan.created_at }} · {{ scan.target }} · {{ scan.profile }}</p>

<div class="summary">
  <span>{{ t_devices }}: <b>{{ scan.device_count }}</b></span>
  <span>{{ t_vulns }}: <b>{{ scan.vuln_count }}</b></span>
  <span>{{ t_risk_label }}: <b>{{ '%.1f'|format(scan.risk_score|default(0)) }}/100</b></span>
  <span class="sev-critical">{{ counts.critical }} {{ t_critical }}</span>
  <span class="sev-high">{{ counts.high }} {{ t_high }}</span>
  <span class="sev-medium">{{ counts.medium }} {{ t_medium }}</span>
  <span class="sev-low">{{ counts.low }} {{ t_low }}</span>
</div>

{% for host in scan.hosts %}
<section class="host">
  <h2>{{ host.name or host.ip }}</h2>
  <div class="host-meta">
    <div>{{ t_ip }}: <b>{{ host.ip }}</b></div>
    <div>{{ t_mac }}: <b>{{ host.mac or '—' }}</b></div>
    <div>{{ t_hostname }}: <b>{{ host.hostname or '—' }}</b></div>
    <div>{{ t_vendor }}: <b>{{ host.vendor or '—' }}</b></div>
    <div>{{ t_type }}: <b>{{ host.device_type or '—' }}</b></div>
    <div>{{ t_os }}: <b>{{ host.os_guess or '—' }}</b></div>
    <div>{{ t_ports }}: <b>{{ host.open_ports or '—' }}</b></div>
    <div>{{ t_risk_label }}: <b>{{ '%.1f'|format(host.host_risk|default(0)) }}/100</b></div>
  </div>

  {% if host.findings %}
  <h3>{{ t_vulns_title }} ({{ host.findings|length }})</h3>
  {% for v in host.findings %}
  <div class="finding sev-{{ v.severity }}">
    <div class="head">
      <span class="sev-{{ v.severity }}">[{{ v.severity|upper }}]</span>
      {% if v.nvd_url %}<a href="{{ v.nvd_url }}">{{ v.plugin_id or v.cve_id }}</a>{% else %}{{ v.plugin_id or v.cve_id }}{% endif %}
      · CVSS {{ '%.1f'|format(v.cvss|default(0)) }}
      · {{ t_port }} {{ v.port }}
    </div>
    {% if v.title %}<div>{{ v.title }}</div>{% endif %}
    {% if v.description %}<div class="meta">{{ v.description }}</div>{% endif %}
    <div class="rem">
      <label>{{ t_remediation }}</label>
      {{ v.remediation }}
    </div>
  </div>
  {% endfor %}
  {% else %}
  <p class="clean">{{ t_host_clean }}</p>
  {% endif %}
</section>
{% else %}
<p class="meta">{{ t_no_devices }}</p>
{% endfor %}

<p class="footer">{{ t_disclaimer }}</p>
<p class="footer">{{ app }} — {{ author }}</p>
</body>
</html>
"""


def export_html(data: dict[str, Any], path: Path) -> Path:
    """Write a host-centric HTML report. Accepts builder or legacy flat payloads."""
    if "hosts" not in data:
        # Rebuild from flat devices + vulnerabilities if needed
        from vscan.core.adapters import vuln_to_finding
        from vscan.core.discovery import Device, ServiceInfo
        from vscan.core.vuln_scan import VulnerabilityFinding

        devices: list[Device] = []
        for d in data.get("devices") or []:
            services = [
                ServiceInfo(
                    port=int(s.get("port") or 0),
                    name=str(s.get("name") or ""),
                    product=str(s.get("product") or ""),
                    version=str(s.get("version") or ""),
                    cpe=str(s.get("cpe") or ""),
                )
                for s in (d.get("services") or [])
            ]
            ports = []
            raw_ports = d.get("open_ports") or ""
            if isinstance(raw_ports, str) and raw_ports:
                ports = [int(p) for p in raw_ports.split(",") if p.strip().isdigit()]
            devices.append(
                Device(
                    ip=str(d.get("ip") or ""),
                    mac=str(d.get("mac") or ""),
                    vendor=str(d.get("vendor") or ""),
                    hostname=str(d.get("hostname") or ""),
                    device_type_key=str(d.get("device_type") or "device.unknown"),
                    os_guess=str(d.get("os_guess") or ""),
                    open_ports=ports,
                    services=services,
                )
            )
        findings = []
        for v in data.get("vulnerabilities") or []:
            findings.append(
                vuln_to_finding(
                    VulnerabilityFinding(
                        ip=str(v.get("ip") or ""),
                        port=int(v.get("port") or 0),
                        service=str(v.get("service") or ""),
                        product=str(v.get("product") or ""),
                        version=str(v.get("version") or ""),
                        cve_id=str(v.get("plugin_id") or v.get("cve_id") or ""),
                        cvss=float(v.get("cvss") or 0),
                        severity=str(v.get("severity") or "none"),
                        title=str(v.get("title") or ""),
                        description=str(v.get("description") or ""),
                        remediation=str(v.get("remediation") or ""),
                        nvd_url=str(v.get("nvd_url") or ""),
                    )
                )
            )
            findings[-1].category = str(v.get("category") or findings[-1].category)
        data = build_report_data(
            target=str(data.get("target") or ""),
            profile=str(data.get("profile") or ""),
            devices=devices,
            findings=findings,
            scan_id=int(data.get("id") or 0),
            created_at=str(data.get("created_at") or ""),
        )

    counts = data.get("counts") or {"critical": 0, "high": 0, "medium": 0, "low": 0}
    html = Template(_TEMPLATE).render(
        app=__app_name__,
        author=__author__,
        version=__version__,
        scan=data,
        counts=counts,
        t_report_title=t("report.title"),
        t_tagline=t("app.tagline"),
        t_scan_id=t("report.scan_id"),
        t_devices=t("report.devices"),
        t_vulns=t("report.vulns"),
        t_risk_label=t("report.risk_label"),
        t_critical=t("vuln.critical"),
        t_high=t("vuln.high"),
        t_medium=t("vuln.medium"),
        t_low=t("vuln.low"),
        t_vulns_title=t("report.vulns_title"),
        t_ip=t("table.ip"),
        t_mac=t("table.mac"),
        t_vendor=t("table.vendor"),
        t_hostname=t("table.hostname"),
        t_type=t("table.device_type"),
        t_os=t("table.os_guess"),
        t_ports=t("table.open_ports"),
        t_port=t("table.port"),
        t_remediation=t("table.remediation"),
        t_host_clean=t("report.host_clean"),
        t_no_devices=t("scan.devices_found", count=0),
        t_disclaimer=t("app.disclaimer"),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return path
