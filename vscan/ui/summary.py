"""Nessus-like severity summary panel."""

from __future__ import annotations

from collections import Counter

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vscan import __app_name__, __author__, __tagline__, __version__
from vscan.core.findings import Finding, compute_risk_score, risk_breakdown, severity_i18n_key, severity_style
from vscan.i18n import t


def print_about(console: Console) -> None:
    body = Text()
    body.append(f"{__app_name__} v{__version__}\n", style="banner")
    body.append(f"{__author__}\n", style="info")
    body.append(f"{__tagline__}\n\n", style="muted")
    body.append(t("about.body") + "\n\n", style="info")
    body.append(t("app.disclaimer"), style="warning")
    console.print(Panel(body, border_style="green", title=t("about.title")))


def print_severity_summary(console: Console, findings: list[Finding]) -> None:
    counts = Counter(f.severity for f in findings)
    risk = compute_risk_score(findings)
    table = Table(
        title=t("summary.title"),
        show_header=True,
        header_style="table.header",
        border_style="green",
    )
    table.add_column(t("table.severity"))
    table.add_column(t("summary.count"), justify="right")

    for sev in ("critical", "high", "medium", "low"):
        style = severity_style(sev)
        table.add_row(
            Text(t(severity_i18n_key(sev)), style=style),
            Text(str(counts.get(sev, 0)), style=style),
        )
    console.print(table)
    console.print(f"[info]{t('summary.risk_score', score=f'{risk:.1f}')}[/info]")
    breakdown = risk_breakdown(findings)
    if breakdown:
        parts = ", ".join(f"{cat}={val:.1f}" for cat, val in list(breakdown.items())[:6])
        console.print(f"[muted]{t('summary.risk_breakdown', parts=parts)}[/muted]")
