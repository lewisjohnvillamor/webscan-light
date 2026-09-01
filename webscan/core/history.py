"""Record finished scans to the database and read them back.

Bridges the two report shapes (website ScanResult and generic ToolReport) into
one persisted row with pre-rendered HTML/JSON/SARIF, so a stored report can be
re-opened or exported later without reconstructing objects.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from webscan.core.models import ScanResult
from webscan.core.toolreport import ToolReport

from . import database


def record(result, scan_id: str | None = None) -> str:
    """Render and persist a ScanResult or ToolReport. Returns the row id."""
    from webscan.report import generic, jsonout, sarif
    from webscan.report import html as html_report

    scan_id = scan_id or uuid.uuid4().hex[:12]
    is_website = isinstance(result, ScanResult)

    if is_website:
        kind, tool_id, tool_name = "website", "website", "Website Scanner"
        html = html_report.render(result)
        json_blob = jsonout.render(result)
        sarif_blob = sarif.render(result)
    elif isinstance(result, ToolReport):
        kind, tool_id, tool_name = "tool", result.tool, result.tool_name
        html = generic.render(result)
        json_blob = generic.render_json(result)
        sarif_blob = None
    else:  # pragma: no cover - defensive
        raise TypeError(f"cannot record {type(result)!r}")

    database.save_scan({
        "id": scan_id, "kind": kind, "tool_id": tool_id, "tool_name": tool_name,
        "target": result.target, "status": result.status,
        "overall_risk": result.overall_risk.label, "findings_count": len(result.findings),
        "rating_counts": json.dumps(result.rating_counts),
        "created_at": result.start_time.isoformat(),
        "finished_at": (result.finish_time or datetime.now(timezone.utc)).isoformat(),
        "duration": result.duration_seconds,
        "html": html, "json": json_blob, "sarif": sarif_blob,
    })
    return scan_id


def list_scans(*args, **kwargs):
    return database.list_scans(*args, **kwargs)


def get_scan(scan_id: str):
    return database.get_scan(scan_id)
