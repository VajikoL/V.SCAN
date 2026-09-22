"""Local and reachable network discovery (L3 — not VLAN hopping).

Detects:
- Interface CIDRs (your LAN / directly attached VLANs if the NIC is tagged)
- Connected and static routes to other subnets the host can already reach
- Local 802.1Q VLAN interfaces (``ip -d link``, ``/proc/net/vlan/config``)
- Optional short passive observation of VLAN tags on the wire (root only)

Does NOT implement 802.1Q double-tagging or other active VLAN-hop attacks.
Scanning another VLAN requires a CIDR that is L3-reachable (or typed by you).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import subprocess
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class NetworkSegment:
    """A network / VLAN candidate for assessment."""

    cidr: str
    interface: str = ""
    source: str = "interface"  # interface | route | vlan | vlan-seen | custom
    label: str = ""
    vlan_id: int | None = None

    @property
    def network(self) -> ipaddress.IPv4Network | None:
        if not self.cidr:
            return None
        net = ipaddress.ip_network(self.cidr, strict=False)
        return net if isinstance(net, ipaddress.IPv4Network) else None

    @property
    def is_scannable(self) -> bool:
        """True when a concrete CIDR is available to feed into nmap/ARP."""
        return bool(self.cidr) and self.network is not None


def _run(cmd: list[str]) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
        return proc.stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _iface_cidrs() -> list[NetworkSegment]:
    """Parse ``ip -4 -o addr show`` for non-loopback interface prefixes."""
    out = _run(["ip", "-4", "-o", "addr", "show"])
    segments: list[NetworkSegment] = []
    for line in out.splitlines():
        match = re.search(
            r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)",
            line,
        )
        if not match:
            continue
        iface, ip, prefix = match.group(1), match.group(2), match.group(3)
        if iface == "lo" or iface.startswith("lo:"):
            continue
        try:
            net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        except ValueError:
            continue
        if not isinstance(net, ipaddress.IPv4Network):
            continue
        if net.is_loopback or net.is_link_local:
            continue
        iface_clean = iface.split("@")[0]
        vlan_id = _vlan_id_from_iface_name(iface_clean)
        label = f"VLAN {vlan_id} ({iface_clean})" if vlan_id is not None else f"{iface_clean} LAN"
        source = "vlan" if vlan_id is not None else "interface"
        segments.append(
            NetworkSegment(
                cidr=str(net),
                interface=iface_clean,
                source=source,
                label=label,
                vlan_id=vlan_id,
            )
        )
    return segments


def _route_cidrs() -> list[NetworkSegment]:
    """Parse ``ip -4 route`` for other reachable subnets (other VLANs via L3)."""
    out = _run(["ip", "-4", "route", "show"])
    segments: list[NetworkSegment] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("default") or "blackhole" in line:
            continue
        match = re.match(
            r"^(\d+\.\d+\.\d+\.\d+/\d+)\s+(?:via\s+\S+\s+)?dev\s+(\S+)",
            line,
        )
        if not match:
            continue
        cidr, iface = match.group(1), match.group(2)
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if not isinstance(net, ipaddress.IPv4Network):
            continue
        if net.is_loopback or net.is_link_local or net.prefixlen == 0:
            continue
        if net.prefixlen >= 31:
            continue
        via = "via" in line
        iface_clean = iface.split("@")[0]
        vlan_id = _vlan_id_from_iface_name(iface_clean)
        if via:
            label = f"routed subnet (via gateway)"
            if vlan_id is not None:
                label = f"routed VLAN {vlan_id}"
            source = "route"
        else:
            label = f"{iface_clean} attached"
            source = "vlan" if vlan_id is not None else "interface"
        segments.append(
            NetworkSegment(
                cidr=str(net),
                interface=iface_clean,
                source=source,
                label=label,
                vlan_id=vlan_id,
            )
        )
    return segments


def _vlan_id_from_iface_name(iface: str) -> int | None:
    match = re.search(r"(?:^vlan|[\./])(\d+)$", iface, flags=re.I)
    if match:
        return int(match.group(1))
    return None


def discover_local_vlan_ids() -> dict[int, str]:
    """
    Discover VLAN IDs configured on this host (interfaces / kernel VLAN table).

    Returns ``{vlan_id: interface_or_note}``.
    """
    found: dict[int, str] = {}

    # ip -d link show — "vlan protocol 802.1Q id 20"
    detailed = _run(["ip", "-d", "link", "show"])
    current_iface = ""
    for line in detailed.splitlines():
        head = re.match(r"^\d+:\s+(\S+):", line)
        if head:
            current_iface = head.group(1).split("@")[0]
        vlan_match = re.search(r"\bvlan\b.*?\bid\s+(\d+)\b", line, flags=re.I)
        if vlan_match:
            vid = int(vlan_match.group(1))
            found[vid] = current_iface or f"vlan{vid}"

        name_vid = _vlan_id_from_iface_name(current_iface) if current_iface else None
        if name_vid is not None:
            found.setdefault(name_vid, current_iface)

    # /proc/net/vlan/config — "vlan20  | 20  | eth0"
    try:
        with open("/proc/net/vlan/config", encoding="utf-8") as fh:
            for line in fh:
                match = re.match(r"^\s*(\S+)\s*\|\s*(\d+)\s*\|\s*(\S+)", line)
                if match:
                    name, vid_s, parent = match.group(1), match.group(2), match.group(3)
                    found[int(vid_s)] = name if name != "Name" else parent
    except OSError:
        pass

    return found


def observe_vlan_tags(seconds: float = 3.0) -> set[int]:
    """
    Passively observe 802.1Q VLAN IDs on the wire for a few seconds.

    Requires root and scapy. Does not inject frames or hop VLANs.
    """
    if os.geteuid() != 0:
        return set()
    try:
        from scapy.all import Dot1Q, sniff  # type: ignore
    except ImportError:
        return set()

    seen: set[int] = set()

    def _collect(pkt) -> None:  # noqa: ANN001
        if pkt.haslayer(Dot1Q):
            try:
                seen.add(int(pkt[Dot1Q].vlan))
            except Exception:  # noqa: BLE001
                return

    try:
        sniff(timeout=max(0.5, seconds), prn=_collect, store=False)
    except Exception as exc:  # noqa: BLE001
        logger.debug("VLAN tag observation failed: %s", exc)
    return seen


def _cidr_for_vlan_iface(iface: str) -> str:
    """Return IPv4 CIDR assigned to *iface*, if any."""
    out = _run(["ip", "-4", "-o", "addr", "show", "dev", iface])
    match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", out)
    if not match:
        return ""
    try:
        net = ipaddress.ip_network(f"{match.group(1)}/{match.group(2)}", strict=False)
        return str(net)
    except ValueError:
        return ""


def discover_vlan_segments(*, passive_seconds: float = 3.0) -> list[NetworkSegment]:
    """
    Auto-find VLANs: local VLAN ifaces + optional passive tag observation.

    Segments without an address keep ``cidr=""`` (user must type a CIDR to scan).
    """
    segments: list[NetworkSegment] = []
    local = discover_local_vlan_ids()
    for vid, iface in sorted(local.items()):
        cidr = _cidr_for_vlan_iface(iface) if iface else ""
        if not cidr:
            # Maybe iface name is vlan20 but address is on another name
            alt = f"vlan{vid}"
            cidr = _cidr_for_vlan_iface(alt) or _cidr_for_vlan_iface(f"eth0.{vid}")
        segments.append(
            NetworkSegment(
                cidr=cidr,
                interface=iface,
                source="vlan" if cidr else "vlan-seen",
                label=(
                    f"VLAN {vid} ready"
                    if cidr
                    else f"VLAN {vid} on {iface or 'host'} — type CIDR to scan"
                ),
                vlan_id=vid,
            )
        )

    observed = observe_vlan_tags(seconds=passive_seconds)
    known_ids = set(local)
    for vid in sorted(observed - known_ids):
        segments.append(
            NetworkSegment(
                cidr="",
                interface="",
                source="vlan-seen",
                label=f"VLAN {vid} seen on wire — type CIDR if authorized",
                vlan_id=vid,
            )
        )
    return segments


def _is_scannable_net(net: ipaddress.IPv4Network) -> bool:
    if net.is_loopback or net.is_link_local or net.prefixlen == 0:
        return False
    if net.prefixlen < 8 or net.prefixlen > 30:
        return False
    if net.is_private or net.is_reserved:
        return True
    shared = ipaddress.ip_network("100.64.0.0/10")
    if net.subnet_of(shared) or shared.overlaps(net):
        return True
    return False


def list_reachable_networks(*, discover_vlans: bool = False, passive_seconds: float = 3.0) -> list[NetworkSegment]:
    """
    Return unique network candidates for interactive / auto scan.

    When ``discover_vlans`` is True, also include local/observed VLAN entries.
    """
    merged: dict[str, NetworkSegment] = {}

    def _key(seg: NetworkSegment) -> str:
        if seg.cidr:
            return f"cidr:{seg.cidr}"
        return f"vlan:{seg.vlan_id}"

    def _add(seg: NetworkSegment) -> None:
        if seg.network is not None and not _is_scannable_net(seg.network):
            return
        key = _key(seg)
        existing = merged.get(key)
        if existing is None:
            merged[key] = seg
            return
        # Prefer entries that already have a CIDR / richer source
        rank = {"interface": 3, "vlan": 3, "route": 2, "vlan-seen": 1, "custom": 3}
        if rank.get(seg.source, 0) > rank.get(existing.source, 0):
            merged[key] = seg
        elif seg.cidr and not existing.cidr:
            merged[key] = seg

    for seg in _iface_cidrs() + _route_cidrs():
        _add(seg)

    if discover_vlans:
        for seg in discover_vlan_segments(passive_seconds=passive_seconds):
            _add(seg)

    result = list(merged.values())
    result.sort(
        key=lambda s: (
            0 if s.cidr else 1,
            -(s.network.prefixlen if s.network else 0),
            s.vlan_id or 0,
            s.cidr,
        )
    )
    return result


def primary_network() -> NetworkSegment | None:
    """Best guess for 'my LAN' — first interface CIDR with an address."""
    nets = list_reachable_networks(discover_vlans=False)
    for seg in nets:
        if seg.is_scannable and seg.source in {"interface", "vlan"}:
            return seg
    for seg in nets:
        if seg.is_scannable:
            return seg
    return None


def hostname_short() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "localhost"
