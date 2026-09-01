"""SQLite persistence — standard library only.

Stores finished scans (with their rendered report blobs) and scheduled scans.
A single file, WAL mode, safe for the app's handful of worker threads.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from pathlib import Path

_LOCK = threading.Lock()
_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    kind TEXT, tool_id TEXT, tool_name TEXT, target TEXT,
    status TEXT, overall_risk TEXT, findings_count INTEGER,
    rating_counts TEXT, created_at TEXT, finished_at TEXT, duration INTEGER,
    html TEXT, json TEXT, sarif TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);

CREATE TABLE IF NOT EXISTS schedules (
    id TEXT PRIMARY KEY,
    tool_id TEXT, tool_name TEXT, target TEXT,
    interval_seconds INTEGER, options TEXT,
    enabled INTEGER DEFAULT 1,
    last_run TEXT, next_run TEXT, last_scan_id TEXT,
    created_at TEXT
);
"""


def data_dir() -> Path:
    override = os.environ.get("WEBSCAN_DATA_DIR")
    path = Path(override) if override else Path.home() / ".local" / "share" / "webscan-light"
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_path() -> Path:
    override = os.environ.get("WEBSCAN_DB")
    return Path(override) if override else data_dir() / "webscan.db"


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path()), check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


_INITIALISED = False


def init_db() -> None:
    global _INITIALISED
    if _INITIALISED:
        return
    with _LOCK, connect() as conn:
        conn.executescript(_SCHEMA)
    _INITIALISED = True


# ---- scans ---------------------------------------------------------------
def save_scan(entry: dict) -> None:
    init_db()
    columns = ("id", "kind", "tool_id", "tool_name", "target", "status", "overall_risk",
               "findings_count", "rating_counts", "created_at", "finished_at", "duration",
               "html", "json", "sarif")
    placeholders = ",".join("?" for _ in columns)
    values = [entry.get(c) for c in columns]
    with _LOCK, connect() as conn:
        conn.execute(
            f"INSERT OR REPLACE INTO scans ({','.join(columns)}) VALUES ({placeholders})", values)


def list_scans(limit: int = 100, target: str | None = None, tool_id: str | None = None) -> list[dict]:
    init_db()
    query = ("SELECT id, kind, tool_id, tool_name, target, status, overall_risk, "
             "findings_count, rating_counts, created_at, duration FROM scans")
    clauses, params = [], []
    if target:
        clauses.append("target LIKE ?"); params.append(f"%{target}%")
    if tool_id:
        clauses.append("tool_id = ?"); params.append(tool_id)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    with connect() as conn:
        return [dict(row) for row in conn.execute(query, params)]


def get_scan(scan_id: str) -> dict | None:
    init_db()
    with connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return dict(row) if row else None


def delete_scan(scan_id: str) -> None:
    with _LOCK, connect() as conn:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))


# ---- schedules -----------------------------------------------------------
def save_schedule(entry: dict) -> None:
    init_db()
    columns = ("id", "tool_id", "tool_name", "target", "interval_seconds", "options",
               "enabled", "last_run", "next_run", "last_scan_id", "created_at")
    placeholders = ",".join("?" for _ in columns)
    with _LOCK, connect() as conn:
        conn.execute(f"INSERT OR REPLACE INTO schedules ({','.join(columns)}) VALUES ({placeholders})",
                     [entry.get(c) for c in columns])


def list_schedules(enabled_only: bool = False) -> list[dict]:
    init_db()
    query = "SELECT * FROM schedules"
    if enabled_only:
        query += " WHERE enabled = 1"
    query += " ORDER BY created_at DESC"
    with connect() as conn:
        return [dict(row) for row in conn.execute(query)]


def get_schedule(schedule_id: str) -> dict | None:
    init_db()
    with connect() as conn:
        row = conn.execute("SELECT * FROM schedules WHERE id = ?", (schedule_id,)).fetchone()
    return dict(row) if row else None


def delete_schedule(schedule_id: str) -> None:
    with _LOCK, connect() as conn:
        conn.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))


def update_schedule_run(schedule_id: str, last_run: str, next_run: str, last_scan_id: str) -> None:
    with _LOCK, connect() as conn:
        conn.execute("UPDATE schedules SET last_run=?, next_run=?, last_scan_id=? WHERE id=?",
                     (last_run, next_run, last_scan_id, schedule_id))
