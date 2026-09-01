"""A generic report produced by any tool in the suite.

The website scanner keeps its own rich ScanResult; every other tool
(SSL/TLS, ports, subdomains, recon, ...) produces a ToolReport, which the
generic renderer turns into the same gauge-and-card layout.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .models import Finding, Severity, Table


@dataclass
class Section:
    """A titled block of evidence: a table, key/value pairs, or free text."""

    title: str
    intro: str = ""
    table: Table | None = None
    kv: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""
    severity: Severity | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "intro": self.intro,
            "table": self.table.as_dict() if self.table else None,
            "kv": [list(pair) for pair in self.kv],
            "body": self.body,
            "severity": self.severity.label if self.severity else None,
        }


@dataclass
class ToolReport:
    tool: str                     # machine id, e.g. "ssl"
    tool_name: str                # display name, e.g. "SSL/TLS Scanner"
    target: str
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finish_time: datetime | None = None
    status: str = "Running"
    findings: list[Finding] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)
    params: list[tuple[str, str]] = field(default_factory=list)
    stats: list[tuple[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> int:
        if not self.finish_time:
            return 0
        return int((self.finish_time - self.start_time).total_seconds())

    @property
    def overall_risk(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)

    @property
    def rating_counts(self) -> dict[str, int]:
        counts = {s.label: 0 for s in reversed(Severity)}
        for finding in self.findings:
            counts[finding.severity.label] += 1
        return counts

    @property
    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-int(f.severity), self.findings.index(f)))

    def finish(self, status: str = "Finished") -> "ToolReport":
        self.finish_time = datetime.now(timezone.utc)
        self.status = status
        return self

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "tool_name": self.tool_name,
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "finish_time": self.finish_time.isoformat() if self.finish_time else None,
            "duration_seconds": self.duration_seconds,
            "status": self.status,
            "overall_risk": self.overall_risk.label,
            "rating_counts": self.rating_counts,
            "findings": [f.as_dict() for f in self.sorted_findings],
            "sections": [s.as_dict() for s in self.sections],
            "params": [list(p) for p in self.params],
            "stats": [list(s) for s in self.stats],
            "errors": self.errors,
        }
