"""Scheduler + new-finding alert tests (isolated DB, no real network/notify)."""
from __future__ import annotations

import tempfile

import pytest

from webscan.core.models import Finding, Severity
from webscan.core.toolreport import ToolReport


@pytest.fixture(autouse=True)
def _isolated_db(monkeypatch):
    monkeypatch.setenv("WEBSCAN_DB", tempfile.mktemp(suffix=".db"))
    import webscan.core.database as db
    db._INITIALISED = False
    yield


def _report(titles):
    r = ToolReport("ssl", "SSL/TLS Scanner", "https://example.com/")
    r.findings = [Finding(f"t{i}", t, Severity.MEDIUM) for i, t in enumerate(titles)]
    return r.finish()


def test_first_run_sets_baseline_no_alert(monkeypatch):
    from webscan.core import scheduler
    alerts = []
    monkeypatch.setattr(scheduler.notify, "notify", lambda *a, **k: alerts.append(a))
    monkeypatch.setattr(scheduler, "_run_one", lambda *a, **k: _report(["A"]))

    scheduler.add_schedule("ssl", "example.com", 60, {})
    assert scheduler.run_due() == 1
    assert alerts == []  # baseline run never alerts


def test_new_finding_triggers_alert(monkeypatch):
    from webscan.core import database, scheduler
    alerts = []
    monkeypatch.setattr(scheduler.notify, "notify", lambda subject, text, payload=None: alerts.append(payload))

    reports = [_report(["A"]), _report(["A", "B"])]  # second run adds "B"
    monkeypatch.setattr(scheduler, "_run_one", lambda *a, **k: reports.pop(0))

    sched = scheduler.add_schedule("ssl", "example.com", 60, {})
    scheduler.run_due()                                   # baseline (A)
    # Force it due again.
    database.update_schedule_run(sched["id"], "", scheduler._now().isoformat(),
                                 database.get_schedule(sched["id"])["last_scan_id"])
    scheduler.run_due()                                   # sees A + B -> B is new

    assert len(alerts) == 1
    titles = [f["title"] for f in alerts[0]["new_findings"]]
    assert titles == ["B"]


def test_no_alert_when_findings_unchanged(monkeypatch):
    from webscan.core import database, scheduler
    alerts = []
    monkeypatch.setattr(scheduler.notify, "notify", lambda *a, **k: alerts.append(a))
    monkeypatch.setattr(scheduler, "_run_one", lambda *a, **k: _report(["A"]))

    sched = scheduler.add_schedule("ssl", "example.com", 60, {})
    scheduler.run_due()
    database.update_schedule_run(sched["id"], "", scheduler._now().isoformat(),
                                 database.get_schedule(sched["id"])["last_scan_id"])
    scheduler.run_due()
    assert alerts == []


def test_duration_parsing():
    from webscan.cli import _parse_duration
    assert _parse_duration("30m") == 1800
    assert _parse_duration("12h") == 43200
    assert _parse_duration("1d") == 86400
    assert _parse_duration("90") == 90
    assert _parse_duration("") == 86400
