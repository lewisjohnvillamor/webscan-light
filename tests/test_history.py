"""Persistence layer tests (isolated SQLite DB via env)."""
from __future__ import annotations

import os
import tempfile

import pytest


@pytest.fixture(autouse=True)
def _isolated_db(monkeypatch):
    monkeypatch.setenv("WEBSCAN_DB", tempfile.mktemp(suffix=".db"))
    # database caches an "initialised" flag; reset it for a fresh file.
    import webscan.core.database as db
    db._INITIALISED = False
    yield


def _sample_report():
    from webscan.core.models import Finding, Severity
    from webscan.core.toolreport import ToolReport
    r = ToolReport("ssl", "SSL/TLS Scanner", "https://example.com/")
    r.findings = [Finding("a", "Weak cipher", Severity.MEDIUM)]
    return r.finish()


def test_record_and_read_back():
    from webscan.core import history
    scan_id = history.record(_sample_report())
    row = history.get_scan(scan_id)
    assert row["overall_risk"] == "Medium"
    assert row["findings_count"] == 1
    assert "<" in row["html"] and row["json"].startswith("{")
    assert row["sarif"] is None  # tool reports have no SARIF


def test_record_website_has_sarif(server):
    from webscan.core import history
    from webscan.core.engine import ScanOptions, run_scan
    result = run_scan(ScanOptions(target=server, max_pages=3, offline=True))
    scan_id = history.record(result)
    row = history.get_scan(scan_id)
    assert row["kind"] == "website"
    assert row["sarif"] and "2.1.0" in row["sarif"]


def test_list_and_filter():
    from webscan.core import history
    history.record(_sample_report())
    rows = history.list_scans(limit=10)
    assert rows and rows[0]["tool_name"] == "SSL/TLS Scanner"
    assert history.list_scans(target="nonexistent-zzz") == []
