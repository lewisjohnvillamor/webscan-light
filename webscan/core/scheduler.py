"""Scheduled scans with new-finding alerts.

A single background thread polls the schedules table; when one is due it runs
the scan, records it, diffs the findings against that schedule's previous run,
and fires a notification for any *new* finding.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

from . import database, history, notify


def _now() -> datetime:
    return datetime.now(timezone.utc)


def add_schedule(tool_id: str, target: str, interval_seconds: int, options: dict | None = None) -> dict:
    from webscan.tools.base import get_tool, load_tools
    load_tools()
    if tool_id == "website":
        tool_name = "Website Scanner"
    else:
        spec = get_tool(tool_id)
        if not spec:
            raise ValueError(f"unknown tool '{tool_id}'")
        tool_name = spec.name
    entry = {
        "id": uuid.uuid4().hex[:12], "tool_id": tool_id, "tool_name": tool_name,
        "target": target, "interval_seconds": max(60, int(interval_seconds)),
        "options": json.dumps(options or {}), "enabled": 1,
        "last_run": None, "next_run": _now().isoformat(), "last_scan_id": None,
        "created_at": _now().isoformat(),
    }
    database.save_schedule(entry)
    return entry


def _finding_keys(report_json: str) -> set[tuple]:
    try:
        data = json.loads(report_json)
    except (json.JSONDecodeError, TypeError):
        return set()
    return {(f.get("test_id"), f.get("title"), f.get("port")) for f in data.get("findings", [])}


def _run_one(tool_id: str, target: str, options: dict):
    from webscan.core.engine import ScanOptions, run_scan
    from webscan.tools.base import ToolOptions, get_tool, load_tools
    load_tools()
    if tool_id == "website":
        return run_scan(ScanOptions(
            target=target, offline=options.get("offline", False),
            verify_tls=not options.get("insecure", False),
            timeout=options.get("timeout", 15), max_pages=options.get("max_items", 15) or 15))
    spec = get_tool(tool_id)
    opts = ToolOptions(
        timeout=options.get("timeout", 10), offline=options.get("offline", False),
        verify_tls=not options.get("insecure", False), ports=options.get("ports", ""),
        wordlist=options.get("wordlist", ""), max_items=options.get("max_items", 0),
        active=True, authorized=options.get("authorized", False),
        extra={"time_based": "1"} if options.get("time_based") else {})
    return spec.func(target, opts)


def run_due(now: datetime | None = None) -> int:
    """Run every schedule whose next_run has passed. Returns how many ran."""
    now = now or _now()
    ran = 0
    for sched in database.list_schedules(enabled_only=True):
        try:
            next_run = datetime.fromisoformat(sched["next_run"]) if sched["next_run"] else now
        except (ValueError, TypeError):
            next_run = now
        if next_run > now:
            continue

        options = json.loads(sched["options"] or "{}")
        try:
            result = _run_one(sched["tool_id"], sched["target"], options)
        except Exception:  # noqa: BLE001
            _reschedule(sched, now)
            continue

        scan_id = history.record(result)
        _diff_and_alert(sched, scan_id, result)
        database.update_schedule_run(
            sched["id"], last_run=now.isoformat(),
            next_run=(now + timedelta(seconds=sched["interval_seconds"])).isoformat(),
            last_scan_id=scan_id)
        ran += 1
    return ran


def _reschedule(sched: dict, now: datetime) -> None:
    database.update_schedule_run(
        sched["id"], last_run=now.isoformat(),
        next_run=(now + timedelta(seconds=sched["interval_seconds"])).isoformat(),
        last_scan_id=sched.get("last_scan_id"))


def _diff_and_alert(sched: dict, scan_id: str, result) -> None:
    previous_id = sched.get("last_scan_id")
    if not previous_id:
        return  # first run establishes the baseline; no alert
    previous = database.get_scan(previous_id)
    if not previous:
        return
    old_keys = _finding_keys(previous["json"])
    new_findings = [f for f in result.sorted_findings
                    if (f.test_id, f.title, f.port) not in old_keys]
    if not new_findings:
        return
    lines = [f"- [{f.severity.label}] {f.title}" for f in new_findings[:20]]
    subject = f"webscan: {len(new_findings)} new finding(s) on {sched['target']} ({sched['tool_name']})"
    text = (f"{sched['tool_name']} found {len(new_findings)} new finding(s) on "
            f"{sched['target']}:\n\n" + "\n".join(lines))
    notify.notify(subject, text, {
        "target": sched["target"], "tool": sched["tool_id"], "scan_id": scan_id,
        "new_findings": [{"severity": f.severity.label, "title": f.title} for f in new_findings],
    })


class Scheduler:
    def __init__(self, poll_seconds: int = 30) -> None:
        self.poll_seconds = poll_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        database.init_db()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="webscan-scheduler")
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                run_due()
            except Exception:  # noqa: BLE001
                pass
            self._stop.wait(self.poll_seconds)

    def stop(self) -> None:
        self._stop.set()
