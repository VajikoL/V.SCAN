"""Configuration management for V.SCAN (~/.vscan/config.yaml)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

SUPPORTED_LANGS = ("en", "ka", "ru", "de", "fr", "es")
DEFAULT_LANG = "en"
DEFAULT_THREADS = 16
DEFAULT_HOST_TIMEOUT = 30
# Full TCP (-p-) + -sV + -O is slow; give each host ample time.
DEFAULT_FULL_SCAN_TIMEOUT = 900
DEFAULT_FULL_SCAN_THREADS = 4

VSCAN_HOME = Path.home() / ".vscan"
CONFIG_PATH = VSCAN_HOME / "config.yaml"
OUI_PATH = VSCAN_HOME / "oui.txt"
CACHE_DIR = VSCAN_HOME / "cache"
HISTORY_DB = VSCAN_HOME / "history.db"
REPORTS_DIR = VSCAN_HOME / "reports"


def ensure_dirs() -> None:
    """Create ~/.vscan, cache, and reports directories if they do not exist."""
    VSCAN_HOME.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def default_config() -> dict[str, Any]:
    """Return default configuration values."""
    return {
        "lang": DEFAULT_LANG,
        "threads": DEFAULT_THREADS,
        "host_timeout": DEFAULT_HOST_TIMEOUT,
        "first_run_completed": False,
    }


def load_config() -> dict[str, Any]:
    """Load config from disk, merging with defaults."""
    ensure_dirs()
    cfg = default_config()
    if CONFIG_PATH.is_file():
        with CONFIG_PATH.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if isinstance(data, dict):
            cfg.update(data)
    return cfg


def save_config(cfg: dict[str, Any]) -> None:
    """Persist configuration to ~/.vscan/config.yaml."""
    ensure_dirs()
    with CONFIG_PATH.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(cfg, fh, default_flow_style=False, allow_unicode=True)


def get_lang(override: str | None = None) -> str:
    """Resolve active language: CLI override > config > default."""
    if override and override in SUPPORTED_LANGS:
        return override
    cfg = load_config()
    lang = str(cfg.get("lang", DEFAULT_LANG))
    return lang if lang in SUPPORTED_LANGS else DEFAULT_LANG


def set_lang(lang: str) -> None:
    """Update language preference in config."""
    if lang not in SUPPORTED_LANGS:
        raise ValueError(f"Unsupported language: {lang}")
    cfg = load_config()
    cfg["lang"] = lang
    save_config(cfg)
