"""In-memory registry of scans started from the web UI."""
from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone

from webscan.core.engine import ScanOptions, run_scan
from webscan.core.models import ScanResult


@dataclass
class ScanJob:
    id: str
    target: str
    state: str = "queued"          # queued | running | finished | failed
    stage: str = "Starting"
    done: int = 0
    total: int = 0
    result: ScanResult | None = None
    error: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def percent(self) -> int:
        if self.state == "finished":
            return 100
        if not self.total:
            return 5
        return min(99, int(100 * self.done / self.total))

    @property
    def summary(self) -> dict | None:
        """The headline numbers, shared by the JSON API and the UI templates."""
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
            "id": self.id,
            "target": self.target,
            "state": self.state,
            "stage": self.stage,
            "done": self.done,
            "total": self.total,
            "percent": self.percent,
            "error": self.error,
            "created_at": self.created_at.isoformat(),
            "summary": self.summary,
        }


class ScanStore:
    """Bounded store; oldest scans are evicted so a long-lived server can't grow forever."""

    def __init__(self, max_scans: int = 50, max_workers: int = 4) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=max_workers)
        self.max_scans = max_scans

    def start(self, options: ScanOptions) -> ScanJob:
        job = ScanJob(id=uuid.uuid4().hex[:12], target=options.target)
        with self._lock:
            self._jobs[job.id] = job
            self._evict_locked()
        self._pool.submit(self._run, job, options)
        return job

    def _evict_locked(self) -> None:
        while len(self._jobs) > self.max_scans:
            oldest = min(self._jobs.values(), key=lambda j: j.created_at)
            if oldest.state in ("queued", "running"):
                break
            del self._jobs[oldest.id]

    def _run(self, job: ScanJob, options: ScanOptions) -> None:
        job.state = "running"

        def progress(stage: str, done: int, total: int) -> None:
            job.stage, job.done, job.total = stage, done, total

        try:
            job.result = run_scan(options, progress=progress)
            if job.result.status == "Failed":
                job.state = "failed"
                job.error = job.result.errors[0] if job.result.errors else "scan failed"
            else:
                job.state = "finished"
                job.stage = "Finished"
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            job.state = "failed"
            job.error = f"{type(exc).__name__}: {exc}"

    def get(self, scan_id: str) -> ScanJob | None:
        return self._jobs.get(scan_id)

    def recent(self, limit: int = 20) -> list[ScanJob]:
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)
        return jobs[:limit]
