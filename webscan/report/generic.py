"""Render a generic ToolReport to HTML / JSON, reusing the shared design."""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from markupsafe import Markup

from webscan import __version__
from webscan.core.toolreport import ToolReport

from . import charts
from .html import NUMERIC_COLUMNS, SEVERITY_VARS, _environment

TOOL_GLYPHS = {
    "website": "🛡", "ssl": "🔒", "ports": "📡", "network": "🖧", "subdomains": "🌐",
    "vhosts": "🎭", "recon": "🔎", "api": "🧩", "urlfuzzer": "🗂", "dorks": "🔦",
    "takeover": "🪝", "xss": "⚡", "sqli": "💉", "sniper": "🎯", "logger": "📥",
}


def _build_charts(report: ToolReport) -> dict:
    counts = report.rating_counts
    total = sum(counts.values())
    gauges = [
        charts.donut(counts[name], total or 1, color_var=var, label=name)
        for name, var in SEVERITY_VARS.items()
    ]
    stack = charts.stacked_bar([(name, counts[name], var) for name, var in SEVERITY_VARS.items()])
    confirmed = sum(1 for f in report.findings if f.confidence.value == "CONFIRMED")
    return {
        "gauges": [Markup(g) for g in gauges],
        "stack": Markup(stack),
        "confirmed": confirmed,
        "unconfirmed": len(report.findings) - confirmed,
        "total_findings": len(report.findings),
    }


def render(report: ToolReport, include_exchanges: bool = False) -> str:
    template = _environment().get_template("tool_report.html.j2")
    return template.render(
        report=report,
        version=__version__,
        generated_at=datetime.now(timezone.utc),
        numeric_columns=NUMERIC_COLUMNS,
        severity_vars=SEVERITY_VARS,
        glyph=TOOL_GLYPHS.get(report.tool, "🛡"),
        include_exchanges=include_exchanges,
        charts=_build_charts(report),
    )


def render_json(report: ToolReport) -> str:
    return json.dumps(
        {"scanner": "webscan-light", "version": __version__, **report.as_dict()},
        indent=2, ensure_ascii=False,
    )


def write(report: ToolReport, path: str | Path, include_exchanges: bool = False) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render(report, include_exchanges=include_exchanges), encoding="utf-8")
    return output
