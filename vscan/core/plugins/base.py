"""Plugin base types for V.SCAN assessment checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from vscan.core.discovery import Device
from vscan.core.findings import Finding


@dataclass
class PluginContext:
    """Runtime options passed to every plugin."""

    timeout: float = 4.0
    light: bool = True
    allow_network: bool = True
    credentials: dict[str, str] = field(default_factory=dict)
    max_mode: bool = False  # audit: no soft caps, all scripts/plugins


class Plugin(Protocol):
    """Nessus/OpenVAS-style check module (detection + remediation only)."""

    id: str
    name: str
    category: str
    light: bool  # True = safe for balanced/default profiles

    def run(self, device: Device, ctx: PluginContext) -> list[Finding]:
        ...
