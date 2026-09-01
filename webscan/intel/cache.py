"""A tiny JSON file cache, so repeat scans don't re-hit the public APIs."""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any


def cache_dir() -> Path:
    base = os.environ.get("WEBSCAN_CACHE_DIR")
    path = Path(base) if base else Path.home() / ".cache" / "webscan-light"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _path_for(namespace: str, key: str) -> Path:
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
    directory = cache_dir() / namespace
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"{digest}.json"


def get(namespace: str, key: str, max_age: int = 86_400) -> Any | None:
    path = _path_for(namespace, key)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    if time.time() - payload.get("_cached_at", 0) > max_age:
        return None
    return payload.get("value")


def put(namespace: str, key: str, value: Any) -> None:
    path = _path_for(namespace, key)
    try:
        path.write_text(json.dumps({"_cached_at": time.time(), "value": value}))
    except OSError:
        pass  # a broken cache must never break a scan
