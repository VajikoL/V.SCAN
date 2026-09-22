"""Core package — shared business logic used by CLI and (future) GUI."""

from vscan.core.discovery import Device, ServiceInfo, run_discovery, validate_target
from vscan.core.vuln_scan import VulnerabilityFinding, run_vuln_scan

__all__ = [
    "Device",
    "ServiceInfo",
    "VulnerabilityFinding",
    "run_discovery",
    "run_vuln_scan",
    "validate_target",
]
