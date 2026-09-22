"""V.SCAN CLI — Vazha Lomtatidze."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import click
from rich.prompt import Prompt

from vscan import __app_name__, __author__, __version__
from vscan.config import SUPPORTED_LANGS, load_config, save_config, set_lang
from vscan.core.discovery import TargetValidationError
from vscan.core.engine import run_assessment
from vscan.core.networks import list_reachable_networks
from vscan.core.profiles import DEFAULT_PROFILE, PROFILES, get_profile
from vscan.core.updater import update_databases
from vscan.db.store import diff_scans, get_scan, list_scans
from vscan.i18n import init_i18n, t
from vscan.report.html_export import export_html
from vscan.report.json_export import export_json
from vscan.ui.banner import print_banner
from vscan.ui.helptext import print_help
from vscan.ui.launcher import run_launcher
from vscan.ui.summary import print_about, print_severity_summary
from vscan.ui.tables import print_devices, print_vulns
from vscan.ui.theme import get_console

_TARGET_RE = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3})(?:/\d{1,2})?$")


def _looks_like_target(value: str) -> bool:
    return bool(_TARGET_RE.match(value.strip()))


class VscanGroup(click.Group):
    """Send bare CIDR/IP to ``scan`` so commands like ``help`` keep working."""

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        if args and not args[0].startswith("-") and args[0] not in self.commands:
            if _looks_like_target(args[0]):
                args = ["scan", *args]
        return super().parse_args(ctx, args)


def _maybe_first_run_lang(lang_flag: str | None) -> str:
    cfg = load_config()
    if lang_flag:
        return init_i18n(lang_flag)

    if not cfg.get("first_run_completed"):
        console = get_console()
        choice = Prompt.ask(
            "[info]Select language / Выберите язык / აირჩიეთ ენა[/info]",
            choices=list(SUPPORTED_LANGS),
            default="en",
            console=console,
        )
        set_lang(choice)
        cfg = load_config()
        cfg["first_run_completed"] = True
        save_config(cfg)
        return init_i18n(choice)

    return init_i18n(None)


def _run_named_assessment(
    console,
    *,
    target: str | None,
    profile_key: str,
    threads: int | None = None,
    top_ports: int | None = None,
    udp: bool | None = None,
    do_vuln: bool | None = None,
    do_plugins: bool | None = None,
    credentials_file: str | None = None,
    all_nets: bool = False,
) -> None:
    """Shared scan path for ``vscan <cidr>`` and ``vscan scan``."""
    from dataclasses import replace

    from vscan.core.engine import load_credentials

    print_banner(console)
    console.print(f"[warning]{t('scan.need_permission')}[/warning]")

    profile = get_profile(profile_key)
    if top_ports is not None:
        profile = replace(profile, top_ports=top_ports, full_ports=False)
    if udp is not None:
        profile = replace(profile, udp=udp)
    if do_vuln is not None:
        profile = replace(profile, do_vuln=do_vuln)
    if do_plugins is not None:
        profile = replace(profile, do_plugins=do_plugins)

    creds = load_credentials(credentials_file)

    targets: list[str] = []
    if all_nets:
        targets = [n.cidr for n in list_reachable_networks() if n.is_scannable]
    elif target:
        targets = [target]
    else:
        nets = [n for n in list_reachable_networks() if n.is_scannable]
        targets = [nets[0].cidr] if nets else []

    if not targets:
        console.print(f"[critical]{t('launcher.no_networks')}[/critical]")
        sys.exit(2)

    for tgt in targets:
        console.print(f"[info]{t('launcher.scanning_target', target=tgt)}[/info]")
        try:
            result = run_assessment(
                tgt,
                profile,
                console,
                threads_override=threads,
                credentials=creds,
            )
        except (TargetValidationError, RuntimeError) as exc:
            console.print(f"[critical]{exc}[/critical]")
            continue
        print_devices(console, result.devices)
        if result.findings:
            print_severity_summary(console, result.findings)
            print_vulns(console, result.findings)


@click.group(
    cls=VscanGroup,
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(f"{__version__} · {__author__}", prog_name=__app_name__)
@click.option(
    "--lang",
    "lang_flag",
    type=click.Choice(SUPPORTED_LANGS, case_sensitive=False),
    default=None,
    help="UI language for this run (en|ka|ru|de|fr|es).",
)
@click.option("--all-nets", is_flag=True, default=False, help="Scan all reachable networks.")
@click.pass_context
def main(ctx: click.Context, lang_flag: str | None, all_nets: bool) -> None:
    """Lightweight vulnerability scanner by Vazha Lomtatidze.

    \b
      vscan                      interactive launcher
      vscan 192.168.1.0/24       scan a network
      vscan help                 full guide
      vscan -h / --help          short CLI help
    """
    ctx.ensure_object(dict)
    ctx.obj["lang"] = _maybe_first_run_lang(lang_flag)
    ctx.obj["console"] = get_console()
    if ctx.invoked_subcommand is not None:
        return
    if all_nets:
        _run_named_assessment(
            ctx.obj["console"],
            target=None,
            profile_key=DEFAULT_PROFILE,
            all_nets=True,
        )
        return
    run_launcher(ctx.obj["console"])


@main.command("help")
@click.pass_context
def help_cmd(ctx: click.Context) -> None:
    """Full explanation of V.SCAN (commands, profiles, VLANs, safety)."""
    print_help(ctx.obj["console"])


@main.command("about")
@click.pass_context
def about_cmd(ctx: click.Context) -> None:
    """About V.SCAN and the author."""
    console = ctx.obj["console"]
    print_banner(console)
    print_about(console)


@main.command("nets")
@click.option(
    "--discover-vlans/--no-discover-vlans",
    default=True,
    help="Detect local/observed VLANs (passive).",
)
@click.pass_context
def nets_cmd(ctx: click.Context, discover_vlans: bool) -> None:
    """List local + routed networks and discovered VLANs."""
    from vscan.ui.launcher import _show_networks

    console = ctx.obj["console"]
    print_banner(console)
    if discover_vlans:
        console.print(f"[info]{t('launcher.discovering_vlans')}[/info]")
    nets = list_reachable_networks(discover_vlans=discover_vlans, passive_seconds=3.0)
    _show_networks(console, nets)


@main.command("quick")
@click.argument("target", required=False)
@click.pass_context
def quick_cmd(ctx: click.Context, target: str | None) -> None:
    """Fast inventory profile (ARP/ping only)."""
    console = ctx.obj["console"]
    print_banner(console)
    if not target:
        nets = [n for n in list_reachable_networks() if n.is_scannable]
        target = nets[0].cidr if nets else None
    if not target:
        console.print(f"[critical]{t('launcher.no_networks')}[/critical]")
        sys.exit(2)
    try:
        result = run_assessment(target, get_profile("quick"), console)
    except (TargetValidationError, RuntimeError) as exc:
        console.print(f"[critical]{exc}[/critical]")
        sys.exit(2)
    print_devices(console, result.devices)


@main.command("scan")
@click.argument("target", required=False)
@click.option(
    "--profile",
    "profile_key",
    type=click.Choice(list(PROFILES.keys()), case_sensitive=False),
    default=DEFAULT_PROFILE,
    show_default=True,
    help="Assessment intensity.",
)
@click.option("--threads", default=None, type=int, help="Override profile thread count.")
@click.option("--top-ports", type=int, default=None, help="Optional port cap.")
@click.option("--udp/--no-udp", default=None, help="Override UDP scanning.")
@click.option("--vuln/--no-vuln", "do_vuln", default=None, help="Override CVE/NVD matching.")
@click.option("--plugins/--no-plugins", "do_plugins", default=None, help="Override plugin checks.")
@click.option(
    "--creds",
    "credentials_file",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="YAML with ssh_user / ssh_key for credentialed audit.",
)
@click.option("--all-nets", is_flag=True, default=False, help="Scan all reachable nets.")
@click.pass_context
def scan_cmd(
    ctx: click.Context,
    target: str | None,
    profile_key: str,
    threads: int | None,
    top_ports: int | None,
    udp: bool | None,
    do_vuln: bool | None,
    do_plugins: bool | None,
    credentials_file: str | None,
    all_nets: bool,
) -> None:
    """Run an assessment (default profile: balanced)."""
    _run_named_assessment(
        ctx.obj["console"],
        target=target,
        profile_key=profile_key,
        threads=threads,
        top_ports=top_ports,
        udp=udp,
        do_vuln=do_vuln,
        do_plugins=do_plugins,
        credentials_file=credentials_file,
        all_nets=all_nets,
    )


@main.command("update-db")
@click.option("--clear-cve-cache", is_flag=True, default=False)
@click.pass_context
def update_db_cmd(ctx: click.Context, clear_cve_cache: bool) -> None:
    """Refresh OUI database and optionally clear CVE cache."""
    console = ctx.obj["console"]
    print_banner(console)
    update_databases(console, clear_cve_cache=clear_cve_cache)


@main.command("config")
@click.option("--set-lang", "set_lang_code", type=click.Choice(SUPPORTED_LANGS, case_sensitive=False))
@click.pass_context
def config_cmd(ctx: click.Context, set_lang_code: str | None) -> None:
    """View or update persistent configuration."""
    console = ctx.obj["console"]
    if set_lang_code:
        set_lang(set_lang_code)
        init_i18n(set_lang_code)
        console.print(f"[success]{t('config.lang_set', lang=set_lang_code)}[/success]")
        return
    cfg = load_config()
    for key, value in cfg.items():
        console.print(f"[muted]{key}[/muted]=[info]{value}[/info]")


@main.command("history")
@click.option("--limit", default=20, show_default=True)
@click.pass_context
def history_cmd(ctx: click.Context, limit: int) -> None:
    """List saved assessments."""
    from rich.table import Table

    console = ctx.obj["console"]
    rows = list_scans(limit=limit)
    table = Table(title=t("history.title"), header_style="table.header", border_style="green")
    table.add_column("ID", style="info")
    table.add_column(t("history.when"), style="muted")
    table.add_column(t("history.target"), style="ip")
    table.add_column(t("history.profile"), style="success")
    table.add_column(t("report.devices"), justify="right")
    table.add_column(t("report.vulns"), justify="right")
    for row in rows:
        table.add_row(
            str(row["id"]),
            row["created_at"],
            row["target"],
            row["profile"],
            str(row["device_count"]),
            str(row["vuln_count"]),
        )
    console.print(table)


@main.command("report")
@click.argument("scan_id", type=int)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "html", "csv", "xml", "txt"], case_sensitive=False),
    default="html",
)
@click.option("--out", "out_path", type=click.Path(), default=None)
@click.pass_context
def report_cmd(ctx: click.Context, scan_id: int, fmt: str, out_path: str | None) -> None:
    """Export a saved scan (default: ~/.vscan/reports/)."""
    from vscan.config import REPORTS_DIR, ensure_dirs
    from vscan.report.csv_export import export_csv
    from vscan.report.txt_export import export_txt
    from vscan.report.xml_export import export_xml
    from vscan.report.builder import build_report_data
    from vscan.core.adapters import vuln_to_finding
    from vscan.core.discovery import Device, ServiceInfo
    from vscan.core.vuln_scan import VulnerabilityFinding

    console = ctx.obj["console"]
    data = get_scan(scan_id)
    if data is None:
        console.print(f"[critical]{t('history.not_found', id=scan_id)}[/critical]")
        sys.exit(2)

    # Rebuild host-centric payload for html/txt quality
    devices = []
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
        raw_ports = d.get("open_ports") or ""
        ports = [int(p) for p in str(raw_ports).split(",") if p.strip().isdigit()]
        dtype = str(d.get("device_type") or "device.unknown")
        if not dtype.startswith("device."):
            dtype = "device.unknown"
        devices.append(
            Device(
                ip=str(d.get("ip") or ""),
                mac=str(d.get("mac") or ""),
                vendor=str(d.get("vendor") or ""),
                hostname=str(d.get("hostname") or ""),
                device_type_key=dtype,
                os_guess=str(d.get("os_guess") or ""),
                open_ports=ports,
                services=services,
            )
        )
    findings = []
    for v in data.get("vulnerabilities") or []:
        f = vuln_to_finding(
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
        f.category = str(v.get("category") or f.category)
        findings.append(f)
    payload = build_report_data(
        target=str(data.get("target") or ""),
        profile=str(data.get("profile") or ""),
        devices=devices,
        findings=findings,
        scan_id=int(data.get("id") or scan_id),
        created_at=str(data.get("created_at") or ""),
    )

    ensure_dirs()
    dest = Path(out_path) if out_path else REPORTS_DIR / f"vscan-report-{scan_id}.{fmt}"
    console.print(f"[info]{t('report.exporting', fmt=fmt)}[/info]")
    exporters = {
        "json": export_json,
        "html": export_html,
        "csv": export_csv,
        "xml": export_xml,
        "txt": export_txt,
    }
    # json/csv/xml use flat-compatible payload; html/txt prefer hosts
    path = exporters[fmt](payload if fmt in {"html", "txt"} else {**data, **payload}, dest)
    console.print(f"[success]{t('report.saved', path=str(path))}[/success]")
    console.print(f"[muted]{t('report.dir_hint', path=str(REPORTS_DIR))}[/muted]")


@main.command("plugins")
@click.pass_context
def plugins_cmd(ctx: click.Context) -> None:
    """List built-in assessment plugins."""
    from vscan.core.plugins import list_plugins

    console = ctx.obj["console"]
    print_banner(console)
    for plugin in list_plugins():
        mode = "light" if plugin.light else "deep"
        console.print(
            f"[success]{plugin.id}[/success]  [muted]{plugin.category}/{mode}[/muted]  {plugin.name}"
        )


@main.command("diff")
@click.argument("id1", type=int)
@click.argument("id2", type=int)
@click.pass_context
def diff_cmd(ctx: click.Context, id1: int, id2: int) -> None:
    """Compare two historical scans."""
    console = ctx.obj["console"]
    try:
        result = diff_scans(id1, id2)
    except KeyError as exc:
        console.print(f"[critical]{t('error.generic', message=str(exc))}[/critical]")
        sys.exit(2)

    console.print(f"[info]{t('diff.new_devices')}: {len(result['new_devices'])}[/info]")
    for d in result["new_devices"]:
        console.print(f"  + {d['ip']} {d.get('hostname') or ''}")
    console.print(f"[warning]{t('diff.missing_devices')}: {len(result['missing_devices'])}[/warning]")
    for d in result["missing_devices"]:
        console.print(f"  - {d['ip']} {d.get('hostname') or ''}")
    console.print(f"[critical]{t('diff.new_vulns')}: {len(result['new_vulnerabilities'])}[/critical]")
    for v in result["new_vulnerabilities"]:
        console.print(f"  + {v['ip']}:{v['port']} {v['cve_id']} CVSS {v['cvss']}")
    console.print(f"[success]{t('diff.closed_ports')}: {len(result['closed_ports'])}[/success]")
    for p in result["closed_ports"]:
        console.print(f"  · {p['ip']}:{p['port']}")


if __name__ == "__main__":
    main()
