"""HTML report rendering."""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup, escape

from webscan import __version__
from webscan.core.models import ScanResult, Severity

from . import charts

TEMPLATE_DIR = Path(__file__).parent / "templates"

NUMERIC_COLUMNS = {"CVE", "CVSS", "EPSS Score", "EPSS Percentile", "Status", "Method", "Port"}

SEVERITY_VARS = {
    "Critical": "--critical",
    "High": "--high",
    "Medium": "--medium",
    "Low": "--low",
    "Info": "--info",
}

SCANNER_NOTE = (
    "This is a Light scan: it identifies misconfigurations, information exposure and "
    "version-based vulnerabilities. It does not actively test for injection classes such "
    "as SQLi, XSS, command injection or XXE, so the absence of such findings is not "
    "evidence that the application is free of them."
)

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")


def _linkify(value: object) -> Markup:
    text = str(escape(str(value)))
    return Markup(URL_RE.sub(lambda m: f'<a href="{m.group(0)}">{m.group(0)}</a>', text))


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
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["linkify"] = _linkify
    env.filters["localtime"] = _localtime
    return env


def _build_charts(result: ScanResult) -> dict:
    counts = result.rating_counts
    total = sum(counts.values())
    gauges = [
        charts.donut(counts[name], total or 1, color_var=var, label=name)
        for name, var in SEVERITY_VARS.items()
    ]
    stack = charts.stacked_bar(
        [(name, counts[name], var) for name, var in SEVERITY_VARS.items()]
    )

    owasp = Counter()
    for finding in result.findings:
        for category in finding.classification.owasp_2021:
            owasp[category] += 1
    owasp_chart = charts.hbars(list(owasp.items()), color_var="--accent")

    confirmed = sum(1 for f in result.findings if f.confidence.value == "CONFIRMED")
    return {
        "gauges": [Markup(g) for g in gauges],
        "stack": Markup(stack),
        "owasp_chart": Markup(owasp_chart),
        "confirmed": confirmed,
        "unconfirmed": len(result.findings) - confirmed,
        "total_findings": len(result.findings),
    }


def render(result: ScanResult, include_exchanges: bool = False) -> str:
    template = _environment().get_template("report.html.j2")
    return template.render(
        result=result,
        version=__version__,
        generated_at=datetime.now(timezone.utc),
        numeric_columns=NUMERIC_COLUMNS,
        severity_vars=SEVERITY_VARS,
        scanner_note=SCANNER_NOTE,
        include_exchanges=include_exchanges,
        charts=_build_charts(result),
    )


def write(result: ScanResult, path: str | Path, include_exchanges: bool = False) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render(result, include_exchanges=include_exchanges), encoding="utf-8")
    return output
