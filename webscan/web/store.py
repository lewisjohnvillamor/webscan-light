"""In-memory registry of jobs started from the web UI (website scan or any tool)."""
from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from webscan.core import history
from webscan.core.engine import ScanOptions, run_scan
from webscan.core.toolreport import ToolReport
from webscan.tools.base import ToolOptions, get_tool


@dataclass
class Job:
    id: str
    kind: str                      # "website" | "tool"
    tool_id: str
    tool_name: str
    target: str
    state: str = "queued"          # queued | running | finished | failed | blocked
    stage: str = "Starting"
    done: int = 0
    total: int = 0
    result: Any = None             # ScanResult or ToolReport
    error: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def percent(self) -> int:
        if self.state in ("finished", "failed", "blocked"):
            return 100
        if not self.total:
            return 5
        return min(99, int(100 * self.done / self.total))

    @property
    def summary(self) -> dict | None:
        if not self.result:
            return None
        return {
            "overall_risk": self.result.overall_risk.label,
            "rating_counts": self.result.rating_counts,
            "findings": len(self.result.findings),
            "duration_seconds": self.result.duration_seconds,
        }

    def as_dict(self) -> dict:
        return {
            "id": self.id, "kind": self.kind, "tool_id": self.tool_id,
            "tool_name": self.tool_name, "target": self.target, "state": self.state,
            "stage": self.stage, "done": self.done, "total": self.total,
            "percent": self.percent, "error": self.error,
            "created_at": self.created_at.isoformat(), "summary": self.summary,
        }


class JobStore:
    def __init__(self, max_jobs: int = 100, max_workers: int = 4) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=max_workers)
        self.max_jobs = max_jobs

    def _add(self, job: Job) -> None:
        with self._lock:
            self._jobs[job.id] = job
            while len(self._jobs) > self.max_jobs:
                oldest = min(self._jobs.values(), key=lambda j: j.created_at)
                if oldest.state in ("queued", "running"):
                    break
                del self._jobs[oldest.id]

    def start_website(self, options: ScanOptions) -> Job:
        job = Job(id=uuid.uuid4().hex[:12], kind="website", tool_id="website",
                  tool_name="Website Scanner", target=options.target)
        self._add(job)
        self._pool.submit(self._run_website, job, options)
        return job

    def start_tool(self, tool_id: str, target: str, options: ToolOptions) -> Job:
        spec = get_tool(tool_id)
        job = Job(id=uuid.uuid4().hex[:12], kind="tool", tool_id=tool_id,
                  tool_name=spec.name if spec else tool_id, target=target)
        self._add(job)
        self._pool.submit(self._run_tool, job, spec, target, options)
        return job

    def _run_website(self, job: Job, options: ScanOptions) -> None:
        job.state = "running"

        def progress(stage: str, done: int, total: int) -> None:
            job.stage, job.done, job.total = stage, done, total

        try:
            job.result = run_scan(options, progress=progress)
            if job.result.status == "Failed":
                job.state = "failed"
                job.error = job.result.errors[0] if job.result.errors else "scan failed"
            else:
                job.state, job.stage = "finished", "Finished"
                _persist(job)
        except Exception as exc:  # noqa: BLE001
            job.state, job.error = "failed", f"{type(exc).__name__}: {exc}"

    def _run_tool(self, job: Job, spec, target: str, options: ToolOptions) -> None:
        job.state = "running"
        if not spec:
            job.state, job.error = "failed", f"unknown tool '{job.tool_id}'"
            return
        try:
            report: ToolReport = spec.func(target, options)
            job.result = report
            if report.status == "Blocked":
                job.state, job.error = "blocked", (report.errors[0] if report.errors else "blocked")
            elif report.status == "Failed":
                job.state, job.error = "failed", (report.errors[0] if report.errors else "failed")
            else:
                job.state, job.stage = "finished", "Finished"
                _persist(job)
        except Exception as exc:  # noqa: BLE001
            job.state, job.error = "failed", f"{type(exc).__name__}: {exc}"

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def recent(self, limit: int = 12) -> list[Job]:
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)
        return jobs[:limit]


def _persist(job: Job) -> None:
    """Save a finished job to the database; never let persistence break a scan."""
    try:
        history.record(job.result, job.id)
    except Exception:  # noqa: BLE001
        pass  # nosec B110: persistence is best-effort, must not fail a scan
