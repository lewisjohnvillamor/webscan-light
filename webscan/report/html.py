"""HTML report rendering."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup, escape

from webscan import __version__
from webscan.core.models import ScanResult

TEMPLATE_DIR = Path(__file__).parent / "templates"

NUMERIC_COLUMNS = {"CVE", "CVSS", "EPSS Score", "EPSS Percentile", "Status", "Method"}

SCANNER_NOTE = (
    "This is a Light scan: it identifies misconfigurations, information exposure and "
    "version-based vulnerabilities. It does not actively test for injection classes such "
    "as SQLi, XSS, command injection or XXE, so the absence of such findings is not "
    "evidence that the application is free of them."
)

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")


def _linkify(value: object) -> Markup:
    """Escape a cell, then turn any bare URLs inside it into links."""
    text = escape(str(value))
    return Markup(
        URL_RE.sub(lambda m: f'<a href="{m.group(0)}">{m.group(0)}</a>', str(text))
    )


def _localtime(value: datetime | None) -> str:
    if not value:
        return "-"
    local = value.astimezone()
    offset = local.strftime("%z")
    pretty_offset = f"UTC{offset[:3]}" if offset else "UTC"
    return f"{local.strftime('%b %d, %Y / %H:%M:%S')} {pretty_offset}"


def _environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        # Unconditional: the report embeds content controlled by the scanned site,
        # and the template's ".j2" suffix would not match an extension-based rule.
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["linkify"] = _linkify
    env.filters["localtime"] = _localtime
    return env


def render(result: ScanResult, include_exchanges: bool = False) -> str:
    template = _environment().get_template("report.html.j2")
    return template.render(
        result=result,
        version=__version__,
        generated_at=datetime.now(timezone.utc),
        numeric_columns=NUMERIC_COLUMNS,
        scanner_note=SCANNER_NOTE,
        include_exchanges=include_exchanges,
    )


def write(result: ScanResult, path: str | Path, include_exchanges: bool = False) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render(result, include_exchanges=include_exchanges), encoding="utf-8")
    return output
