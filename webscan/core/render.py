"""Headless-Chromium page rendering for JavaScript-heavy sites (SPAs).

The static crawler misses links, forms and endpoints that a single-page app
injects at runtime. When rendering is enabled, we drive the same headless
Chromium already bundled for PDF export to return the fully-rendered DOM, which
the spider then parses like any other page. Rendering is best-effort: any
failure falls back to the raw HTTP response.
"""
from __future__ import annotations

import base64
import subprocess  # nosec B404: fixed argv list, no shell
import tempfile
from pathlib import Path

from webscan.report.pdf import find_chrome


def available() -> bool:
    return find_chrome() is not None


def render_html(url: str, timeout: float = 20.0, wait_ms: int = 3500) -> str | None:
    """Return the fully-rendered DOM for ``url``, or None on failure."""
    chrome = find_chrome()
    if not chrome:
        return None
    with tempfile.TemporaryDirectory() as tmpdir:
        command = [
            chrome, "--headless", "--disable-gpu", "--no-sandbox",
            "--disable-dev-shm-usage", "--hide-scrollbars",
            f"--user-data-dir={tmpdir}/profile",
            f"--virtual-time-budget={wait_ms}",
            "--run-all-compositor-stages-before-draw",
            "--dump-dom", url,
        ]
        try:
            result = subprocess.run(  # nosec B603: fixed argv, no shell
                command, capture_output=True, text=True,
                timeout=timeout + wait_ms / 1000 + 10)
        except (subprocess.TimeoutExpired, OSError):
            return None
    dom = result.stdout or ""
    return dom if "<" in dom else None


def screenshot(url: str, out_path: str | Path, timeout: float = 20.0,
               width: int = 1200, height: int = 800, wait_ms: int = 3000) -> Path | None:
    """Capture a PNG screenshot of ``url``; return the path or None on failure."""
    chrome = find_chrome()
    if not chrome:
        return None
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmpdir:
        command = [
            chrome, "--headless", "--disable-gpu", "--no-sandbox",
            "--disable-dev-shm-usage", "--hide-scrollbars",
            f"--user-data-dir={tmpdir}/profile",
            f"--window-size={width},{height}",
            f"--virtual-time-budget={wait_ms}",
            f"--screenshot={out}", url,
        ]
        try:
            subprocess.run(command, capture_output=True, text=True,  # nosec B603: fixed argv, no shell
                           timeout=timeout + wait_ms / 1000 + 10)
        except (subprocess.TimeoutExpired, OSError):
            return None
    return out if out.exists() and out.stat().st_size > 0 else None


def screenshot_data_uri(url: str, timeout: float = 20.0, width: int = 900, height: int = 560,
                        wait_ms: int = 3000) -> str | None:
    """Capture a screenshot and return it as a data: URI (or None on failure)."""
    import tempfile as _t
    from pathlib import Path as _P
    with _t.TemporaryDirectory() as d:
        out = _P(d) / "shot.png"
        got = screenshot(url, out, timeout=timeout, width=width, height=height, wait_ms=wait_ms)
        if not got:
            return None
        raw = out.read_bytes()
    if len(raw) > 1_500_000:  # keep reports lean
        return None
    return "data:image/png;base64," + base64.b64encode(raw).decode()
