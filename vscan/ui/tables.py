"""Rich table helpers for device inventory and vulnerability output."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from vscan.core.discovery import Device
from vscan.core.findings import Finding, severity_i18n_key, severity_style
from vscan.i18n import t


def devices_table(devices: list[Device]) -> Table:
    """Build the main discovery results table."""
    table = Table(
        title=t("scan.devices_found", count=len(devices)),
        show_header=True,
        header_style="table.header",
        border_style="green",
        title_style="banner",
    )
    table.add_column(t("table.ip"), style="ip", no_wrap=True)
    table.add_column(t("table.mac"), style="mac", no_wrap=True)
    table.add_column(t("table.vendor"), style="vendor")
    table.add_column(t("table.hostname"), style="info")
    table.add_column(t("table.device_type"), style="success")
    table.add_column(t("table.os_guess"), style="muted")
    table.add_column(t("table.open_ports"), style="muted")

    for device in devices:
        if device.services:
            ports = ", ".join(s.label for s in device.services[:8])
            if len(device.services) > 8:
                ports += f" (+{len(device.services) - 8})"
        elif device.open_ports:
            ports = ", ".join(str(p) for p in device.open_ports)
        else:
            ports = "—"
        table.add_row(
            device.ip,
            device.mac or "—",
            device.vendor or "—",
            device.hostname or "—",
            t(device.device_type_key),
            device.os_guess or "—",
            ports,
        )
    return table


def vulns_table(findings: list[Finding]) -> Table:
    """Build the findings table with severity colouring."""
    table = Table(
        title=t("vuln.total_found", count=len(findings)),
        show_header=True,
        header_style="table.header",
        border_style="green",
        title_style="banner",
    )
    table.add_column(t("table.ip"), style="ip", no_wrap=True)
    table.add_column(t("table.port"), style="muted", no_wrap=True)
    table.add_column(t("table.service"), style="info")
    table.add_column(t("table.plugin"), no_wrap=True)
    table.add_column(t("table.cvss"), no_wrap=True)
    table.add_column(t("table.severity"), no_wrap=True)
    table.add_column(t("table.remediation"), overflow="fold")

    for finding in findings:
        style = severity_style(finding.severity)
        sev_label = t(severity_i18n_key(finding.severity))
        product = " ".join(
            p for p in (finding.product or finding.service, finding.version) if p
        ) or finding.category or "—"
        table.add_row(
            finding.ip,
            str(finding.port),
            product,
            Text(finding.plugin_id, style=style),
            Text(f"{finding.cvss:.1f}", style=style),
            Text(sev_label, style=style),
            finding.remediation,
        )
    return table


def print_devices(console: Console, devices: list[Device]) -> None:
    console.print(devices_table(devices))


def print_vulns(console: Console, findings: list[Finding]) -> None:
    if not findings:
        console.print(f"[success]{t('vuln.no_findings')}[/success]")
        return
    console.print(vulns_table(findings))
