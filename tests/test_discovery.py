"""Tests for discovery helpers (no live network required)."""

from __future__ import annotations

import pytest

from vscan.core.discovery import (
    TargetValidationError,
    classify_device,
    validate_target,
)


def test_validate_ip() -> None:
    assert validate_target("192.168.1.10") == "192.168.1.10"


def test_validate_cidr() -> None:
    assert validate_target("10.0.0.0/24") == "10.0.0.0/24"


def test_validate_invalid() -> None:
    with pytest.raises(TargetValidationError):
        validate_target("not-an-ip")


def test_classify_router_by_hostname() -> None:
    assert classify_device(hostname="home-router") == "device.router"


def test_classify_printer_by_vendor() -> None:
    assert classify_device(vendor="Hewlett Packard") == "device.printer"


def test_classify_iot_by_ports() -> None:
    assert classify_device(open_ports=[1883, 5683]) == "device.iot"


def test_classify_server_by_ports() -> None:
    assert classify_device(open_ports=[22, 80, 443]) == "device.server"


def test_classify_unknown() -> None:
    assert classify_device() == "device.unknown"
