"""JSON report rendering — the machine-readable form of the same data."""
from __future__ import annotations

import json
from pathlib import Path

from webscan import __version__
from webscan.core.models import ScanResult


def render(result: ScanResult, indent: int = 2) -> str:
    payload = {"scanner": "webscan-light", "version": __version__, **result.as_dict()}
    return json.dumps(payload, indent=indent, ensure_ascii=False)


def write(result: ScanResult, path: str | Path) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render(result), encoding="utf-8")
    return output
