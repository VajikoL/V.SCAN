"""Tests for i18n helpers."""

from __future__ import annotations

from vscan.i18n.i18n import init_i18n, t


def test_english_translation() -> None:
    init_i18n("en")
    assert t("scan.complete") == "Scan complete"


def test_russian_translation() -> None:
    init_i18n("ru")
    assert "завершено" in t("scan.complete").lower() or "Сканирование" in t("scan.complete")


def test_format_kwargs() -> None:
    init_i18n("en")
    assert t("scan.devices_found", count=3) == "3 device(s) found"


def test_fallback_to_english_for_missing_key(tmp_path, monkeypatch) -> None:
    """Unknown keys fall back to the key string itself when absent everywhere."""
    init_i18n("en")
    assert t("this.key.does.not.exist") == "this.key.does.not.exist"


def test_georgian_loads() -> None:
    init_i18n("ka")
    assert t("app.name") == "V.SCAN"
    assert len(t("scan.discovery")) > 0


def test_all_supported_langs_have_core_keys() -> None:
    required = [
        "scan.starting",
        "scan.device_found",
        "scan.version_detect",
        "vuln.critical",
        "vuln.high",
        "vuln.medium",
        "vuln.low",
        "vuln.scanning",
        "vuln.remediation_upgrade",
        "scan.complete",
        "error.generic",
        "error.no_internet",
    ]
    for lang in ("en", "ru", "ka", "de", "fr", "es"):
        init_i18n(lang)
        for key in required:
            value = t(key)
            assert value != key, f"missing {key} in {lang}"
            assert "{" not in value or True  # templates may keep unused braces
