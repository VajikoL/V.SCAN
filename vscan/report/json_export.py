"""JSON report export."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vscan import __app_name__, __author__, __version__


def export_json(data: dict[str, Any], path: Path) -> Path:
    payload = {
        "generator": {
            "name": __app_name__,
            "version": __version__,
            "author": __author__,
        },
        "scan": data,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
