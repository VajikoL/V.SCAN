"""Assessment plugins package — Nessus/OpenVAS-style checks without a web GUI."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeRemainingColumn

from vscan.core.discovery import Device
from vscan.core.findings import Finding, dedupe_findings
from vscan.core.plugins.base import Plugin, PluginContext
from vscan.core.plugins.dangerous_services import DangerousServicesPlugin
from vscan.core.plugins.dns_checks import DnsChecksPlugin
from vscan.core.plugins.http_security import HttpSecurityPlugin
from vscan.core.plugins.nmap_nse import NmapNsePlugin
from vscan.core.plugins.smb_checks import SmbChecksPlugin
from vscan.core.plugins.snmp_checks import SnmpChecksPlugin
from vscan.core.plugins.ssh_auth import SshAuthAuditPlugin
from vscan.core.plugins.ssh_banner import SshBannerPlugin
from vscan.core.plugins.ssl_tls import SslTlsPlugin
from vscan.core.plugins.unauth_services import UnauthServicePlugin
from vscan.i18n import t

_ALL_PLUGINS: list[Plugin] = [
    DangerousServicesPlugin(),
    UnauthServicePlugin(),
    SslTlsPlugin(),
    HttpSecurityPlugin(),
    DnsChecksPlugin(),
    SmbChecksPlugin(),
    SnmpChecksPlugin(),
    SshBannerPlugin(),
    NmapNsePlugin(),
    SshAuthAuditPlugin(),
]


def list_plugins() -> list[Plugin]:
    return list(_ALL_PLUGINS)


def select_plugins(
    *,
    light: bool,
    include_auth: bool,
    force_all: bool = False,
) -> list[Plugin]:
    """Select plugins. ``force_all`` (audit) runs every registered plugin."""
    if force_all:
        return list(_ALL_PLUGINS)
    selected: list[Plugin] = []
    for plugin in _ALL_PLUGINS:
        if plugin.id == "ssh_auth_audit" and not include_auth:
            continue
        if light and not plugin.light:
            continue
        selected.append(plugin)
    return selected


def run_plugins(
    devices: list[Device],
    console: Console,
    *,
    light: bool = True,
    credentials: dict[str, str] | None = None,
    threads: int = 8,
    timeout: float = 4.0,
    max_mode: bool = False,
    force_all_plugins: bool = False,
) -> list[Finding]:
    """Run selected plugins across devices with bounded parallelism."""
    creds = credentials or {}
    include_auth = bool(creds.get("ssh_user") or creds.get("username")) or force_all_plugins
    plugins = select_plugins(
        light=light and not max_mode,
        include_auth=include_auth,
        force_all=force_all_plugins or max_mode,
    )
    if not plugins or not devices:
        return []

    console.print(f"[info]{t('plugins.running', count=len(plugins))}[/info]")
    if max_mode:
        console.print(f"[warning]{t('plugins.audit_max')}[/warning]")

    ctx = PluginContext(
        timeout=timeout,
        light=False if max_mode else light,
        allow_network=True,
        credentials=creds,
        max_mode=max_mode,
    )

    jobs = [(p, d) for d in devices for p in plugins]
    findings: list[Finding] = []

    with Progress(
        SpinnerColumn(style="green"),
        TextColumn("[info]{task.description}[/info]"),
        BarColumn(bar_width=None, style="green", complete_style="bright_green"),
        TextColumn("[muted]{task.completed}/{task.total}[/muted]"),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task(t("plugins.progress"), total=len(jobs))
        workers = max(1, min(threads, 16 if max_mode else (8 if light else 12)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(_safe_run, plugin, device, ctx): (plugin, device)
                for plugin, device in jobs
            }
            for fut in as_completed(futures):
                plugin, device = futures[fut]
                try:
                    findings.extend(fut.result())
                except Exception as exc:  # noqa: BLE001
                    console.print(
                        f"[warning]{t('plugins.failed', plugin=plugin.id, ip=device.ip, reason=str(exc))}[/warning]"
                    )
                finally:
                    progress.advance(task_id)

    return dedupe_findings(findings)


def _safe_run(plugin: Plugin, device: Device, ctx: PluginContext) -> list[Finding]:
    return plugin.run(device, ctx) or []
