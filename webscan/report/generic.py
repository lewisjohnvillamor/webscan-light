"""Render a generic ToolReport to HTML / JSON, reusing the shared design."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from markupsafe import Markup

from webscan import __version__
from webscan.core.toolreport import ToolReport

from . import charts
from .html import NUMERIC_COLUMNS, SEVERITY_VARS, _environment

# Short monospace codes used as the report/masthead mark (no emoji).
TOOL_GLYPHS = {
    "website": "WEB", "ssl": "TLS", "ports": "PRT", "network": "NET", "subdomains": "SUB",
    "vhosts": "VHT", "dnsemail": "DNS", "deps": "DEP", "webmisc": "MSC", "cloud": "CLD", "secrets": "SEC", "typosquat": "TYP", "asm": "ASM", "recon": "RCN", "api": "API", "urlfuzzer": "FUZ", "dorks": "DRK",  # noqa: E501
    "takeover": "TKO", "xss": "XSS", "sqli": "SQL", "ssti": "SSTI", "cmdi": "CMD", "lfi": "LFI", "storedxss": "STOR", "sniper": "SNP", "logger": "LOG",  # noqa: E501
    "nuclei": "NUC", "nmapscan": "NMP",
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
        # chart values are server-generated inline SVG, not user input.
        "gauges": [Markup(g) for g in gauges],  # nosec B704
        "stack": Markup(stack),  # nosec B704
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
        glyph=TOOL_GLYPHS.get(report.tool, "WS"),
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
