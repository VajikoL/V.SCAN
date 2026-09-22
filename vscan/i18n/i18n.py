"""Internationalization helpers for V.SCAN."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vscan.config import DEFAULT_LANG, get_lang

_LOCALES_DIR = Path(__file__).resolve().parent / "locales"
_catalog: dict[str, str] = {}
_fallback: dict[str, str] = {}
_current_lang: str = DEFAULT_LANG


def _load_locale(lang: str) -> dict[str, str]:
    path = _LOCALES_DIR / f"{lang}.json"
    if not path.is_file():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}


def init_i18n(lang: str | None = None) -> str:
    """Load locale catalogs and set active language. Returns resolved language code."""
    global _catalog, _fallback, _current_lang
    resolved = get_lang(lang)
    _current_lang = resolved
    _fallback = _load_locale(DEFAULT_LANG)
    _catalog = _load_locale(resolved) if resolved != DEFAULT_LANG else dict(_fallback)
    if resolved == DEFAULT_LANG:
        _catalog = dict(_fallback)
    return resolved


def current_lang() -> str:
    """Return the currently active language code."""
    return _current_lang


def t(key: str, **kwargs: Any) -> str:
    """
    Translate *key* using the active locale.

    Falls back to English, then to the key itself.
    Supports ``str.format`` placeholders via kwargs.
    """
    template = _catalog.get(key) or _fallback.get(key) or key
    if kwargs:
        try:
            return template.format(**kwargs)
        except (KeyError, ValueError, IndexError):
            return template
    return template
