"""Interactive launcher for bare ``vscan`` (Vazha Lomtatidze)."""

from __future__ import annotations

from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table

from vscan.core.discovery import TargetValidationError, validate_target
from vscan.core.engine import run_assessment
from vscan.core.networks import NetworkSegment, list_reachable_networks, primary_network
from vscan.core.profiles import DEFAULT_PROFILE, PROFILES, get_profile
from vscan.i18n import t
from vscan.ui.banner import print_banner
from vscan.ui.summary import print_about, print_severity_summary
from vscan.ui.tables import print_devices, print_vulns


def _show_networks(console: Console, nets: list[NetworkSegment]) -> None:
    table = Table(
        title=t("launcher.networks_title"),
        header_style="table.header",
        border_style="green",
    )
    table.add_column("#", style="muted")
    table.add_column(t("launcher.cidr"), style="ip")
    table.add_column("VLAN", style="warning")
    table.add_column(t("launcher.iface"), style="info")
    table.add_column(t("launcher.source"), style="muted")
    table.add_column(t("launcher.label"), style="success")
    for idx, seg in enumerate(nets, start=1):
        table.add_row(
            str(idx),
            seg.cidr or t("launcher.cidr_needed"),
            str(seg.vlan_id) if seg.vlan_id is not None else "—",
            seg.interface or "—",
            seg.source,
            seg.label,
        )
    # Extra row hint for manual CIDR
    table.add_row(
        "c",
        t("launcher.custom_cidr_row"),
        "—",
        "—",
        "custom",
        t("launcher.custom_cidr_hint"),
    )
    console.print(table)
    if not nets:
        console.print(f"[warning]{t('launcher.no_networks')}[/warning]")
    console.print(f"[muted]{t('launcher.vlan_note')}[/muted]")
    console.print(f"[muted]{t('launcher.pick_help')}[/muted]")


def _ask_custom_cidr(console: Console, *, hint: str = "") -> str | None:
    message = t("launcher.enter_target")
    if hint:
        message = f"{message} ({hint})"
    raw = Prompt.ask(message, console=console).strip()
    if not raw:
        return None
    try:
        return validate_target(raw)
    except TargetValidationError as exc:
        console.print(f"[critical]{exc}[/critical]")
        return None


def _resolve_choice_part(
    part: str,
    nets: list[NetworkSegment],
    console: Console,
) -> list[str]:
    """Resolve one token from the pick prompt into concrete CIDR(s)."""
    part = part.strip()
    if not part:
        return []

    if part in {"c", "custom", "manual"}:
        cidr = _ask_custom_cidr(console)
        return [cidr] if cidr else []

    if part.isdigit():
        idx = int(part)
        if not (1 <= idx <= len(nets)):
            console.print(f"[warning]{t('launcher.bad_index', index=part, max=len(nets))}[/warning]")
            cidr = _ask_custom_cidr(console, hint=t("launcher.type_cidr_instead"))
            return [cidr] if cidr else []
        seg = nets[idx - 1]
        if seg.is_scannable:
            return [seg.cidr]
        # VLAN seen but no address — ask for CIDR
        console.print(f"[info]{t('launcher.vlan_needs_cidr', vlan=seg.vlan_id)}[/info]")
        cidr = _ask_custom_cidr(
            console,
            hint=t("launcher.vlan_cidr_hint", vlan=seg.vlan_id),
        )
        return [cidr] if cidr else []

    # Direct CIDR / IP typed by the user
    try:
        return [validate_target(part)]
    except TargetValidationError as exc:
        console.print(f"[critical]{exc}[/critical]")
        return []


def _pick_targets(console: Console, nets: list[NetworkSegment]) -> list[str]:
    if not nets:
        cidr = _ask_custom_cidr(console)
        return [cidr] if cidr else []

    primary = primary_network()
    default = "1" if nets else "c"
    choice = Prompt.ask(
        t("launcher.pick_networks"),
        default=default,
        console=console,
    ).strip().lower()

    if choice in {"a", "all", "*"}:
        selected: list[str] = []
        for seg in nets:
            if seg.is_scannable:
                selected.append(seg.cidr)
            else:
                console.print(
                    f"[muted]{t('launcher.skip_unscannable', label=seg.label)}[/muted]"
                )
        # After "all", offer to add a custom network too
        if Confirm.ask(t("launcher.add_custom_after"), default=False, console=console):
            extra = _ask_custom_cidr(console)
            if extra:
                selected.append(extra)
        return list(dict.fromkeys(selected))

    if choice in {"c", "custom", "manual"}:
        cidr = _ask_custom_cidr(console)
        return [cidr] if cidr else []

    selected = []
    for part in choice.replace(";", ",").split(","):
        selected.extend(_resolve_choice_part(part, nets, console))

    # Deduplicate, keep order
    selected = list(dict.fromkeys(selected))
    if not selected and primary and primary.is_scannable:
        selected = [primary.cidr]
    return selected


def _pick_profile(console: Console) -> str:
    table = Table(title=t("launcher.profiles_title"), header_style="table.header", border_style="green")
    table.add_column("key", style="info")
    table.add_column(t("launcher.profile"), style="success")
    table.add_column(t("launcher.profile_desc"), style="muted")
    for key, prof in PROFILES.items():
        table.add_row(key, t(prof.title_key), t(prof.description_key))
    console.print(table)
    return Prompt.ask(
        t("launcher.pick_profile"),
        choices=list(PROFILES.keys()),
        default=DEFAULT_PROFILE,
        console=console,
    )


def run_launcher(console: Console) -> None:
    """Interactive Nessus-like start when user runs plain ``vscan``."""
    print_banner(console)
    print_about(console)

    if not Confirm.ask(t("scan.need_permission"), default=True, console=console):
        console.print(f"[warning]{t('launcher.aborted')}[/warning]")
        return

    discover = Confirm.ask(t("launcher.discover_vlans"), default=True, console=console)
    if discover:
        console.print(f"[info]{t('launcher.discovering_vlans')}[/info]")

    nets = list_reachable_networks(discover_vlans=discover, passive_seconds=3.0)
    _show_networks(console, nets)

    targets = _pick_targets(console, nets)
    if not targets:
        console.print(f"[warning]{t('launcher.aborted')}[/warning]")
        return

    console.print(f"[success]{t('launcher.targets_chosen', targets=', '.join(targets))}[/success]")

    profile_key = _pick_profile(console)
    profile = get_profile(profile_key)

    all_devices = []
    all_findings = []
    last_id = None
    for target in targets:
        console.print(f"[banner]{'─' * 40}[/banner]")
        console.print(f"[info]{t('launcher.scanning_target', target=target)}[/info]")
        try:
            result = run_assessment(target, profile, console, persist=True)
        except Exception as exc:  # noqa: BLE001
            console.print(f"[critical]{t('error.generic', message=str(exc))}[/critical]")
            continue
        print_devices(console, result.devices)
        if result.findings:
            print_severity_summary(console, result.findings)
            print_vulns(console, result.findings)
        all_devices.extend(result.devices)
        all_findings.extend(result.findings)
        last_id = result.scan_id

    console.print(
        f"[success]{t('launcher.done', devices=len(all_devices), vulns=len(all_findings))}[/success]"
    )
    if last_id is not None:
        console.print(f"[muted]{t('launcher.report_hint', id=last_id)}[/muted]")
