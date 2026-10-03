"""CSV export of findings — for spreadsheets, ticket imports and triage.

Works for both the website ScanResult and any ToolReport, since both expose
``sorted_findings``. One row per finding with the fields a triager wants.
"""
from __future__ import annotations

import csv
import io

COLUMNS = ["severity", "confidence", "title", "port", "cve", "cwe", "cvss_v3",
           "epss_score", "cisa_kev", "recommendation", "references"]


def render_csv(report) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow(["target", getattr(report, "target", "")])
    writer.writerow(COLUMNS)
    for f in report.sorted_findings:
        c = f.classification
        writer.writerow([
            f.severity.label,
            f.confidence.value,
            f.title,
            f.port or "",
            ", ".join(c.cve),
            ", ".join(c.cwe),
            "" if c.cvss_v3 is None else f"{c.cvss_v3:g}",
            "" if c.epss_score is None else f"{c.epss_score:g}",
            "" if c.cisa_kev is None else str(c.cisa_kev),
            (f.recommendation or "").replace("\n", " ").strip(),
            " ".join(f.references),
        ])
    return buf.getvalue()
