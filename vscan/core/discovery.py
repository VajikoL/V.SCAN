"""Network device discovery for authorized inventory.

Capabilities (inventory / assessment only):
- Live-host discovery via ARP (scapy) with subprocess arp-scan fallback
- Offline IEEE OUI vendor lookup
- Hostname via reverse DNS, optional NetBIOS and mDNS probes
- Lightweight device-type heuristics (ports + vendor + hostname)
- Optional open-port listing via nmap when available

This module does not implement exploitation, evasion, or attack techniques.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

import requests
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeRemainingColumn

from vscan.config import DEFAULT_THREADS, OUI_PATH, ensure_dirs
from vscan.i18n import t

logger = logging.getLogger(__name__)

OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"

# Port → likely role hints used only for inventory classification.
_PORT_HINTS: dict[int, str] = {
    80: "device.server",
    443: "device.server",
    22: "device.server",
    3389: "device.desktop",
    445: "device.desktop",
    139: "device.desktop",
    9100: "device.printer",
    515: "device.printer",
    631: "device.printer",
    1883: "device.iot",
    5683: "device.iot",
    554: "device.iot",
    53: "device.router",
    67: "device.router",
    161: "device.router",
}

_VENDOR_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"cisco|mikrotik|ubiquiti|tp-?link|netgear|asus|d-?link|huawei|zyxel", re.I), "device.router"),
    (re.compile(r"hewlett.?packard|epson|canon|brother|xerox|ricoh", re.I), "device.printer"),
    (re.compile(r"raspberry|espressif|tuya|shelly|philips.?lighting|nest|ring", re.I), "device.iot"),
    (re.compile(r"apple|samsung|xiaomi|oneplus|huawei|google", re.I), "device.mobile"),
    (re.compile(r"vmware|qemu|virtualbox|microsoft|dell|lenovo|hp.?inc", re.I), "device.desktop"),
]

_HOSTNAME_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"router|gateway|gw-|ap-|wifi|mikrotik|edge", re.I), "device.router"),
    (re.compile(r"print|hp-|epson|brother|canon", re.I), "device.printer"),
    (re.compile(r"iphone|android|pixel|galaxy|mobile", re.I), "device.mobile"),
    (re.compile(r"nas|server|srv-|docker|k8s|proxmox", re.I), "device.server"),
    (re.compile(r"desktop|laptop|pc-|workstation|macbook", re.I), "device.desktop"),
    (re.compile(r"cam|camera|bulb|sensor|smart|iot|thermostat", re.I), "device.iot"),
]


@dataclass
class ServiceInfo:
    """Service detected on an open port (from nmap -sV when available)."""

    port: int
    protocol: str = "tcp"
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: str = ""

    @property
    def label(self) -> str:
        """Compact human-readable label for tables."""
        bits = [str(self.port)]
        if self.name:
            bits.append(self.name)
        detail = " ".join(p for p in (self.product, self.version) if p).strip()
        if detail:
            bits.append(detail)
        return "/".join(bits[:2]) + (f" ({detail})" if detail else "")


@dataclass
class Device:
    """Discovered network device inventory record."""

    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    device_type_key: str = "device.unknown"
    os_guess: str = ""
    open_ports: list[int] = field(default_factory=list)
    services: list[ServiceInfo] = field(default_factory=list)


class TargetValidationError(ValueError):
    """Raised when the scan target is not a valid IP or CIDR."""


def validate_target(target: str) -> str:
    """Validate and normalize an IP address or CIDR network string."""
    target = target.strip()
    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            return str(net)
        ip = ipaddress.ip_address(target)
        return str(ip)
    except ValueError as exc:
        raise TargetValidationError(t("scan.invalid_target", target=target)) from exc


def ensure_oui_database(
    console: Console | None = None,
    *,
    force: bool = False,
) -> Path:
    """
    Ensure the IEEE OUI database exists under ~/.vscan/oui.txt.

    Downloads once; subsequent runs use the cache. Offline mode keeps the cache.
    """
    ensure_dirs()
    if OUI_PATH.is_file() and not force and OUI_PATH.stat().st_size > 0:
        if console:
            console.print(f"[muted]{t('oui.cached')}[/muted]")
        return OUI_PATH

    if console:
        console.print(f"[info]{t('oui.downloading')}[/info]")

    try:
        response = requests.get(OUI_URL, timeout=60)
        response.raise_for_status()
        OUI_PATH.write_text(response.text, encoding="utf-8")
        count = sum(1 for line in response.text.splitlines() if "(hex)" in line)
        if console:
            console.print(f"[success]{t('oui.ready', count=count)}[/success]")
    except requests.RequestException:
        if OUI_PATH.is_file() and OUI_PATH.stat().st_size > 0:
            if console:
                console.print(f"[warning]{t('oui.offline')}[/warning]")
        else:
            # Minimal empty file so lookups degrade gracefully.
            OUI_PATH.write_text("", encoding="utf-8")
            if console:
                console.print(f"[warning]{t('error.no_internet')}[/warning]")
    return OUI_PATH


class OUIDatabase:
    """Offline MAC → vendor lookup using IEEE OUI text format."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or OUI_PATH
        self._map: dict[str, str] = {}
        self._loaded = False

    def load(self) -> None:
        if self._loaded:
            return
        self._map.clear()
        if not self.path.is_file():
            self._loaded = True
            return
        for line in self.path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if "(hex)" not in line:
                continue
            # Example: "28-6F-B9   (hex)		Nokia Shanghai Bell Co., Ltd."
            parts = line.split("(hex)", 1)
            if len(parts) != 2:
                continue
            prefix = parts[0].strip().upper().replace("-", "").replace(":", "")
            vendor = parts[1].strip()
            if len(prefix) >= 6:
                self._map[prefix[:6]] = vendor
        self._loaded = True

    def lookup(self, mac: str) -> str:
        """Return vendor name for *mac*, or empty string if unknown."""
        self.load()
        cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
        if len(cleaned) < 6:
            return ""
        return self._map.get(cleaned[:6], "")


def _arp_scan_scapy(network: str) -> list[tuple[str, str]]:
    """ARP-scan *network* using scapy. Requires appropriate privileges."""
    try:
        from scapy.all import ARP, Ether, conf, srp  # type: ignore
    except ImportError:
        return []

    conf.verb = 0
    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
        answered, _ = srp(packet, timeout=3, retry=1)
    except Exception as exc:  # noqa: BLE001 — scapy raises various low-level errors
        logger.debug("scapy ARP scan failed: %s", exc)
        return []

    results: list[tuple[str, str]] = []
    for _, received in answered:
        results.append((received.psrc, received.hwsrc))
    return results


def _arp_scan_arpscan(network: str) -> list[tuple[str, str]]:
    """ARP-scan via the system ``arp-scan`` binary if present."""
    binary = shutil.which("arp-scan")
    if not binary:
        return []
    try:
        proc = subprocess.run(
            [binary, "--quiet", "--ignoredups", network],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("arp-scan failed: %s", exc)
        return []

    results: list[tuple[str, str]] = []
    for line in proc.stdout.splitlines():
        # Typical: "192.168.1.10  aa:bb:cc:dd:ee:ff  Vendor Name"
        match = re.match(
            r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{11,17})\b",
            line.strip(),
        )
        if match:
            results.append((match.group(1), match.group(2)))
    return results


def _ping_sweep(network: str) -> list[tuple[str, str]]:
    """
    Fallback host discovery using ICMP ping (no MAC addresses).

    Used when ARP methods are unavailable (e.g. missing privileges / tools).
    """
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return []

    # Cap sweep size for safety on huge ranges.
    hosts = list(net.hosts())[:256]
    results: list[tuple[str, str]] = []

    def _ping(ip: str) -> str | None:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
        try:
            completed = subprocess.run(cmd, capture_output=True, timeout=3, check=False)
            return ip if completed.returncode == 0 else None
        except (subprocess.TimeoutExpired, OSError):
            return None

    with ThreadPoolExecutor(max_workers=32) as pool:
        futures = {pool.submit(_ping, str(ip)): str(ip) for ip in hosts}
        for fut in as_completed(futures):
            ip = fut.result()
            if ip:
                results.append((ip, ""))
    return results


def discover_live_hosts(target: str) -> list[tuple[str, str]]:
    """
    Discover live hosts for *target* (IP or CIDR).

    Returns a list of ``(ip, mac)`` pairs. MAC may be empty for ping fallback.
    """
    normalized = validate_target(target)
    if "/" not in normalized:
        # Single host — treat as /32 equivalent.
        return [(normalized, "")]

    hosts = _arp_scan_scapy(normalized)
    if not hosts:
        hosts = _arp_scan_arpscan(normalized)
    if not hosts:
        hosts = _ping_sweep(normalized)

    # Deduplicate by IP, prefer entries that have a MAC.
    by_ip: dict[str, str] = {}
    for ip, mac in hosts:
        if ip not in by_ip or (mac and not by_ip[ip]):
            by_ip[ip] = mac
    return sorted(by_ip.items(), key=lambda item: ipaddress.ip_address(item[0]))


def resolve_hostname(ip: str) -> str:
    """Resolve hostname via reverse DNS, NetBIOS, and mDNS (best-effort)."""
    names: list[str] = []

    # Reverse DNS
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        if host:
            names.append(host.rstrip("."))
    except (socket.herror, socket.gaierror, OSError):
        pass

    # NetBIOS name query via nmblookup if available
    nmb = shutil.which("nmblookup")
    if nmb:
        try:
            proc = subprocess.run(
                [nmb, "-A", ip],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            for line in proc.stdout.splitlines():
                match = re.search(r"^\s*(\S+)\s+<00>\s+-\s+B", line)
                if match and match.group(1) not in ("__MSBROWSE__",):
                    names.append(match.group(1))
                    break
        except (subprocess.TimeoutExpired, OSError):
            pass

    # mDNS via avahi-resolve-address if available
    avahi = shutil.which("avahi-resolve-address")
    if avahi:
        try:
            proc = subprocess.run(
                [avahi, ip],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            # Output like: "192.168.1.10   hostname.local"
            parts = proc.stdout.strip().split()
            if len(parts) >= 2:
                names.append(parts[-1].rstrip("."))
        except (subprocess.TimeoutExpired, OSError):
            pass

    # Prefer shortest non-IP-looking name; join unique sources with " / ".
    unique: list[str] = []
    for name in names:
        if name and name not in unique and name != ip:
            unique.append(name)
    return " / ".join(unique[:3])


def classify_device(
    *,
    vendor: str = "",
    hostname: str = "",
    open_ports: Iterable[int] | None = None,
) -> str:
    """
    Classify device type using inventory heuristics.

    Returns an i18n key such as ``device.router``.
    """
    ports = list(open_ports or [])

    for pattern, key in _HOSTNAME_HINTS:
        if hostname and pattern.search(hostname):
            return key

    for pattern, key in _VENDOR_HINTS:
        if vendor and pattern.search(vendor):
            return key

    scores: dict[str, int] = {}
    for port in ports:
        hint = _PORT_HINTS.get(port)
        if hint:
            scores[hint] = scores.get(hint, 0) + 1
    if scores:
        return max(scores.items(), key=lambda item: item[1])[0]
    return "device.unknown"


def parse_nmap_xml(xml_text: str) -> tuple[list[ServiceInfo], str]:
    """
    Parse nmap XML output into services and an OS guess.

    Used by discovery and unit tests (mocked subprocess output).
    """
    services: list[ServiceInfo] = []
    # Match each <port ...>...</port> block that is open.
    for port_block in re.finditer(
        r"<port\b[^>]*>.*?</port>",
        xml_text,
        flags=re.DOTALL,
    ):
        block = port_block.group(0)
        if 'state="open"' not in block and "state='open'" not in block:
            continue
        port_match = re.search(
            r'<port\b(?=[^>]*protocol="([^"]+)")(?=[^>]*portid="(\d+)")[^>]*>',
            block,
        )
        if not port_match:
            continue
        protocol, port_id = port_match.group(1), int(port_match.group(2))

        svc_match = re.search(r"<service\b([^>]*)/?>", block)
        name = product = version = extrainfo = ""
        if svc_match:
            attrs = svc_match.group(1)
            name = _xml_attr(attrs, "name")
            product = _xml_attr(attrs, "product")
            version = _xml_attr(attrs, "version")
            extrainfo = _xml_attr(attrs, "extrainfo")

        cpe_match = re.search(r"<cpe>([^<]+)</cpe>", block)
        cpe = cpe_match.group(1).strip() if cpe_match else ""

        services.append(
            ServiceInfo(
                port=port_id,
                protocol=protocol,
                name=name,
                product=product,
                version=version,
                extrainfo=extrainfo,
                cpe=cpe,
            )
        )

    os_guess = ""
    os_match = re.search(r'osmatch name="([^"]+)"', xml_text)
    if os_match:
        os_guess = os_match.group(1)

    services.sort(key=lambda s: s.port)
    return services, os_guess


def _xml_attr(attrs: str, name: str) -> str:
    match = re.search(rf'\b{name}="([^"]*)"', attrs)
    return match.group(1) if match else ""


def _nmap_probe(
    ip: str,
    *,
    timeout: int = 900,
    version_detect: bool = False,
    full_ports: bool = True,
    top_ports: int | None = None,
    os_detect: bool = True,
    default_scripts: bool = True,
    udp: bool = False,
    script_expr: str | None = None,
    max_mode: bool = False,
) -> tuple[list[ServiceInfo], str]:
    """
    Run an nmap probe against *ip*.

    Audit / max_mode: all TCP (+UDP), full -sV, -O, broad defensive NSE categories.
    """
    if not shutil.which("nmap"):
        return [], ""

    is_root = os.geteuid() == 0
    timing = "-T3" if max_mode else "-T4"  # steadier under huge script sets
    args: list[str] = ["nmap", "-Pn", timing]

    if is_root:
        args.append("-sS")
    else:
        args.append("-sT")

    if udp:
        args.append("-sU")

    if top_ports is not None and top_ports > 0:
        args.extend(["--top-ports", str(top_ports)])
    elif full_ports:
        rate = "200" if max_mode else "500"
        args.extend(["-p-", "--min-rate", rate])
    else:
        args.extend(["--top-ports", "1000"])

    if version_detect:
        args.extend(["-sV", "--version-all"])
        if max_mode:
            args.extend(["--version-intensity", "9"])
        timeout = max(timeout, 180)

    if os_detect and is_root:
        args.append("-O")
        if max_mode:
            args.extend(["--osscan-guess", "--max-os-tries", "2"])

    if script_expr:
        args.extend(["--script", script_expr])
        if max_mode:
            args.extend(["--script-timeout", "60s"])
    elif default_scripts:
        args.append("-sC")

    args.extend(["-oX", "-", ip])

    if full_ports and version_detect:
        timeout = max(timeout, 900)
    if udp:
        timeout = max(timeout, 1200)
    if max_mode:
        timeout = max(timeout, 1800)

    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return [], ""

    return parse_nmap_xml(proc.stdout)


def enrich_host(
    ip: str,
    mac: str,
    oui: OUIDatabase,
    *,
    probe_ports: bool = True,
    version_detect: bool = False,
    host_timeout: int = 900,
    full_ports: bool = True,
    top_ports: int | None = None,
    os_detect: bool = True,
    default_scripts: bool = True,
    udp: bool = False,
    script_expr: str | None = None,
    max_mode: bool = False,
) -> Device:
    """Build a full Device record for a single host."""
    vendor = oui.lookup(mac) if mac else ""
    hostname = resolve_hostname(ip)
    open_ports: list[int] = []
    services: list[ServiceInfo] = []
    os_guess = ""
    if probe_ports:
        services, os_guess = _nmap_probe(
            ip,
            timeout=host_timeout,
            version_detect=version_detect,
            full_ports=full_ports,
            top_ports=top_ports,
            os_detect=os_detect,
            default_scripts=default_scripts,
            udp=udp,
            script_expr=script_expr,
            max_mode=max_mode,
        )
        open_ports = [s.port for s in services]
    device_type = classify_device(vendor=vendor, hostname=hostname, open_ports=open_ports)
    return Device(
        ip=ip,
        mac=mac.upper() if mac else "",
        vendor=vendor or t("device.unknown"),
        hostname=hostname,
        device_type_key=device_type,
        os_guess=os_guess,
        open_ports=open_ports,
        services=services,
    )


def run_discovery(
    target: str,
    console: Console,
    *,
    threads: int = DEFAULT_THREADS,
    probe_ports: bool = True,
    version_detect: bool = False,
    host_timeout: int = 900,
    full_ports: bool = True,
    top_ports: int | None = None,
    os_detect: bool = True,
    default_scripts: bool = True,
    udp: bool = False,
    script_expr: str | None = None,
    max_mode: bool = False,
    on_device: Callable[[Device], None] | None = None,
) -> list[Device]:
    """
    Run full discovery against *target* and return enriched Device records.
    """
    validate_target(target)
    ensure_oui_database(console)
    oui = OUIDatabase()
    oui.load()

    console.print(f"[info]{t('scan.starting', target=target)}[/info]")
    console.print(f"[muted]{t('scan.discovery')}[/muted]")
    if max_mode:
        console.print(f"[warning]{t('scan.audit_max')}[/warning]")
    if probe_ports:
        if top_ports:
            console.print(f"[muted]{t('scan.nmap_top_ports', count=top_ports)}[/muted]")
        elif full_ports:
            console.print(f"[muted]{t('scan.nmap_full')}[/muted]")
        if version_detect:
            console.print(f"[muted]{t('scan.version_detect')}[/muted]")
        if os_detect:
            console.print(f"[muted]{t('scan.os_detect')}[/muted]")
        if script_expr:
            console.print(f"[muted]{t('scan.script_expr', expr=script_expr)}[/muted]")
        elif default_scripts:
            console.print(f"[muted]{t('scan.default_scripts')}[/muted]")
        if udp:
            console.print(f"[muted]{t('scan.udp')}[/muted]")
    if probe_ports and os.geteuid() != 0:
        console.print(f"[warning]{t('error.no_root')}[/warning]")
        if os_detect:
            console.print(f"[warning]{t('scan.os_detect_needs_root')}[/warning]")

    live = discover_live_hosts(target)
    if not live:
        console.print(f"[warning]{t('scan.devices_found', count=0)}[/warning]")
        return []

    devices: list[Device] = []
    skipped: list[str] = []

    with Progress(
        SpinnerColumn(style="green"),
        TextColumn("[info]{task.description}[/info]"),
        BarColumn(bar_width=None, style="green", complete_style="bright_green"),
        TextColumn("[muted]{task.completed}/{task.total}[/muted]"),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task(t("scan.progress"), total=len(live))

        with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
            futures = {
                pool.submit(
                    enrich_host,
                    ip,
                    mac,
                    oui,
                    probe_ports=probe_ports,
                    version_detect=version_detect,
                    host_timeout=host_timeout,
                    full_ports=full_ports,
                    top_ports=top_ports,
                    os_detect=os_detect,
                    default_scripts=default_scripts,
                    udp=udp,
                    script_expr=script_expr,
                    max_mode=max_mode,
                ): ip
                for ip, mac in live
            }
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    device = fut.result()
                    devices.append(device)
                    if on_device:
                        on_device(device)
                    else:
                        console.print(
                            f"[success]{t('scan.device_found', ip=device.ip, vendor=device.vendor)}[/success]"
                        )
                except Exception as exc:  # noqa: BLE001
                    skipped.append(ip)
                    console.print(
                        f"[warning]{t('scan.skipped_host', ip=ip, reason=str(exc))}[/warning]"
                    )
                finally:
                    progress.advance(task_id)

    devices.sort(key=lambda d: ipaddress.ip_address(d.ip))
    console.print(f"[success]{t('scan.complete')}[/success]")
    console.print(f"[info]{t('scan.devices_found', count=len(devices))}[/info]")
    return devices


def nmap_available() -> bool:
    """Return True if the nmap binary is on PATH."""
    return shutil.which("nmap") is not None
