"""PDF rendering.

PDF output is optional: it drives a headless Chromium if one is available on
the system, and otherwise tells the user exactly how to get one. Nothing else
in the tool depends on it.
"""
from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404: used only with a fixed argv list (no shell)
import tempfile
from pathlib import Path

from webscan.core.models import ScanResult

from . import html as html_report

CHROME_CANDIDATES = (
    "chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome",
)

CHROME_PATHS = (
    "/opt/pw-browsers/chromium-1194/chrome-linux/chrome",
    "/opt/pw-browsers/chromium/chrome-linux/chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
)


class PdfUnavailable(RuntimeError):
    """Raised when no HTML-to-PDF backend could be found."""


def find_chrome() -> str | None:
    explicit = os.environ.get("WEBSCAN_CHROME")
    if explicit and Path(explicit).exists():
        return explicit
    for name in CHROME_CANDIDATES:
        found = shutil.which(name)
        if found:
            return found
    for path in CHROME_PATHS:
        if Path(path).exists():
            return path
    # Playwright's bundled builds, wherever they were installed.
    browsers_root = Path(os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw-browsers"))
    if browsers_root.is_dir():
        for candidate in sorted(browsers_root.glob("chromium*/chrome-linux/chrome")):
            return str(candidate)
    return None


def available() -> bool:
    return find_chrome() is not None


def html_to_pdf(markup: str, path: str | Path) -> Path:
    """Render an HTML string to PDF via headless Chromium."""
    chrome = find_chrome()
    if not chrome:
        raise PdfUnavailable(
            "No Chromium/Chrome binary was found for PDF rendering.\n"
            "Install one (e.g. 'apt install chromium' or 'brew install --cask chromium'), "
            "set WEBSCAN_CHROME=/path/to/chrome, or export the report with --format html "
            "and print it from your browser."
        )

    output = Path(path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        source = Path(tmpdir) / "report.html"
        source.write_text(markup, encoding="utf-8")
        command = [
            chrome,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--no-pdf-header-footer",
            "--run-all-compositor-stages-before-draw",
            "--virtual-time-budget=5000",
            f"--user-data-dir={tmpdir}/profile",
            f"--print-to-pdf={output}",
            source.as_uri(),
        ]
        process = subprocess.run(command, capture_output=True, text=True, timeout=120)  # nosec B603: fixed argv, no shell

    if not output.exists() or output.stat().st_size == 0:
        raise PdfUnavailable(
            f"Chromium failed to produce a PDF (exit {process.returncode}).\n"
            f"{(process.stderr or '').strip()[:600]}"
        )
    return output


def write(result: ScanResult, path: str | Path, include_exchanges: bool = False) -> Path:
    """Render a website ScanResult to PDF."""
    return html_to_pdf(html_report.render(result, include_exchanges=include_exchanges), path)
