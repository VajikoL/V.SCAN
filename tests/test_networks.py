"""Tests for network listing and scan profiles."""

from __future__ import annotations

from vscan.core.networks import NetworkSegment, discover_local_vlan_ids, list_reachable_networks
from vscan.core.profiles import DEFAULT_PROFILE, get_profile


def test_default_profile_is_balanced_and_light() -> None:
    profile = get_profile(DEFAULT_PROFILE)
    assert profile.key == "balanced"
    assert profile.do_vuln is True
    assert profile.do_plugins is True
    assert profile.light_plugins is True
    assert profile.full_ports is False
    assert profile.top_ports == 1000


def test_audit_profile_is_max_mode() -> None:
    profile = get_profile("audit")
    assert profile.max_mode is True
    assert profile.full_ports is True
    assert profile.udp is True
    assert profile.do_plugins is True
    assert profile.do_vuln is True
    assert profile.light_plugins is False
    assert profile.script_expr is not None
    assert "vuln" in profile.script_expr
    assert "auth" in profile.script_expr
    assert profile.max_cves_per_service >= 40
    assert profile.host_timeout >= 1800


def test_audit_selects_all_plugins() -> None:
    from vscan.core.plugins import list_plugins, select_plugins

    all_ids = {p.id for p in list_plugins()}
    selected = {p.id for p in select_plugins(light=False, include_auth=True, force_all=True)}
    assert selected == all_ids


def test_list_reachable_networks_returns_segments(monkeypatch) -> None:
    from vscan.core import networks as nw

    monkeypatch.setattr(
        nw,
        "_iface_cidrs",
        lambda: [
            NetworkSegment("192.168.1.0/24", "eth0", "interface", "eth0 LAN"),
            NetworkSegment("10.10.20.0/24", "eth0.20", "vlan", "VLAN 20", vlan_id=20),
        ],
    )
    monkeypatch.setattr(
        nw,
        "_route_cidrs",
        lambda: [
            NetworkSegment("10.10.30.0/24", "eth0", "route", "routed VLAN/subnet"),
        ],
    )
    nets = list_reachable_networks(discover_vlans=False)
    cidrs = {n.cidr for n in nets}
    assert "192.168.1.0/24" in cidrs
    assert "10.10.20.0/24" in cidrs
    assert "10.10.30.0/24" in cidrs


def test_discover_local_vlan_ids_parses_ip_d_link(monkeypatch) -> None:
    from vscan.core import networks as nw

    sample = """
2: eth0: <BROADCAST,MULTICAST,UP>
5: eth0.40@eth0: <BROADCAST,MULTICAST,UP>
    vlan protocol 802.1Q id 40 <REORDER_HDR>
"""
    monkeypatch.setattr(nw, "_run", lambda cmd: sample if "link" in cmd else "")
    monkeypatch.setattr(nw, "open", lambda *a, **k: (_ for _ in ()).throw(OSError()), raising=False)

    # Avoid reading real /proc — patch open used inside discover
    import builtins
    real_open = builtins.open

    def fake_open(path, *args, **kwargs):
        if str(path) == "/proc/net/vlan/config":
            raise OSError("no vlan proc")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)
    found = discover_local_vlan_ids()
    assert 40 in found
