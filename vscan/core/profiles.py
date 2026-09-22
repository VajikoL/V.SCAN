"""Scan profiles — lightweight OpenVAS/Nessus-style policies by Vazha Lomtatidze."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanProfile:
    """Named assessment intensity preset."""

    key: str
    title_key: str
    description_key: str
    probe_ports: bool
    version_detect: bool
    full_ports: bool
    top_ports: int | None
    os_detect: bool
    default_scripts: bool
    udp: bool
    do_vuln: bool
    do_plugins: bool
    light_plugins: bool
    threads: int
    host_timeout: int
    # audit max: every plugin, full NSE categories, no soft caps
    max_mode: bool = False
    # Extra nmap --script expression (replaces plain -sC when set)
    script_expr: str | None = None
    # CVE matches kept per versioned service
    max_cves_per_service: int = 8
    plugin_timeout: float = 4.0


# Balanced default: powerful enough, not wasteful like always -p-.
PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(
        key="quick",
        title_key="profile.quick.title",
        description_key="profile.quick.desc",
        probe_ports=False,
        version_detect=False,
        full_ports=False,
        top_ports=None,
        os_detect=False,
        default_scripts=False,
        udp=False,
        do_vuln=False,
        do_plugins=False,
        light_plugins=True,
        threads=16,
        host_timeout=30,
        max_mode=False,
        max_cves_per_service=0,
        plugin_timeout=3.0,
    ),
    "balanced": ScanProfile(
        key="balanced",
        title_key="profile.balanced.title",
        description_key="profile.balanced.desc",
        probe_ports=True,
        version_detect=True,
        full_ports=False,
        top_ports=1000,
        os_detect=True,
        default_scripts=True,
        udp=False,
        do_vuln=True,
        do_plugins=True,
        light_plugins=True,
        threads=6,
        host_timeout=240,
        max_mode=False,
        max_cves_per_service=8,
        plugin_timeout=4.0,
    ),
    "deep": ScanProfile(
        key="deep",
        title_key="profile.deep.title",
        description_key="profile.deep.desc",
        probe_ports=True,
        version_detect=True,
        full_ports=True,
        top_ports=None,
        os_detect=True,
        default_scripts=True,
        udp=False,
        do_vuln=True,
        do_plugins=True,
        light_plugins=False,
        threads=4,
        host_timeout=900,
        max_mode=False,
        script_expr="default,safe,vuln",
        max_cves_per_service=15,
        plugin_timeout=8.0,
    ),
    "audit": ScanProfile(
        key="audit",
        title_key="profile.audit.title",
        description_key="profile.audit.desc",
        probe_ports=True,
        version_detect=True,
        full_ports=True,
        top_ports=None,
        os_detect=True,
        default_scripts=True,
        udp=True,
        do_vuln=True,
        do_plugins=True,
        light_plugins=False,
        threads=2,
        host_timeout=1800,
        max_mode=True,
        # Defensive NSE categories only (no exploit/brute/dos).
        script_expr="default,safe,vuln,auth,discovery,version",
        max_cves_per_service=40,
        plugin_timeout=15.0,
    ),
}

DEFAULT_PROFILE = "balanced"


def get_profile(key: str) -> ScanProfile:
    return PROFILES[key if key in PROFILES else DEFAULT_PROFILE]
