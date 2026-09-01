"""Core data model shared by the checks, the engine and the report renderers."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class Severity(enum.IntEnum):
    """Risk ratings, ordered so that ``max()`` yields the overall risk level."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


class Confidence(enum.Enum):
    CONFIRMED = "CONFIRMED"
    UNCONFIRMED = "UNCONFIRMED"


@dataclass
class Table:
    """A small evidence table rendered underneath a finding's title."""

    columns: list[str]
    rows: list[list[str]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"columns": self.columns, "rows": self.rows}


@dataclass
class Classification:
    """The 'Classification' block at the bottom of a finding."""

    cwe: list[str] = field(default_factory=list)
    owasp_2017: list[str] = field(default_factory=list)
    owasp_2021: list[str] = field(default_factory=list)
    owasp_2025: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    cvss_v3: float | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    cisa_kev: bool | None = None

    def as_rows(self) -> list[tuple[str, str]]:
        """Ordered label/value pairs, matching the reference report's ordering."""
        rows: list[tuple[str, str]] = []
        if self.epss_score is not None:
            rows.append(("EPSS score", f"{self.epss_score:g}"))
        if self.epss_percentile is not None:
            rows.append(("EPSS percentile", f"{self.epss_percentile:g}"))
        if self.cisa_kev is not None:
            rows.append(("CISA KEV", str(self.cisa_kev)))
        if self.cve:
            rows.append(("CVE", ", ".join(self.cve)))
        if self.cvss_v3 is not None:
            rows.append(("CVSS V3", f"{self.cvss_v3:g}"))
        if self.cwe:
            rows.append(("CWE", ", ".join(self.cwe)))
        if self.owasp_2017:
            rows.append(("OWASP Top 10 - 2017", ", ".join(self.owasp_2017)))
        if self.owasp_2021:
            rows.append(("OWASP Top 10 - 2021", ", ".join(self.owasp_2021)))
        if self.owasp_2025:
            rows.append(("OWASP Top 10 - 2025", ", ".join(self.owasp_2025)))
        return rows

    def as_dict(self) -> dict[str, Any]:
        return {
            "cwe": self.cwe,
            "owasp_2017": self.owasp_2017,
            "owasp_2021": self.owasp_2021,
            "owasp_2025": self.owasp_2025,
            "cve": self.cve,
            "cvss_v3": self.cvss_v3,
            "epss_score": self.epss_score,
            "epss_percentile": self.epss_percentile,
            "cisa_kev": self.cisa_kev,
        }


@dataclass
class Finding:
    """One entry in the report's 'Findings' section."""

    test_id: str
    title: str
    severity: Severity
    confidence: Confidence = Confidence.CONFIRMED
    port: str = ""
    table: Table | None = None
    risk_description: str = ""
    recommendation: str = ""
    references: list[str] = field(default_factory=list)
    classification: Classification = field(default_factory=Classification)
    request_response: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "test_id": self.test_id,
            "title": self.title,
            "severity": self.severity.label,
            "confidence": self.confidence.value,
            "port": self.port,
            "table": self.table.as_dict() if self.table else None,
            "risk_description": self.risk_description,
            "recommendation": self.recommendation,
            "references": self.references,
            "classification": self.classification.as_dict(),
            "request_response": self.request_response,
        }


@dataclass
class ScanStats:
    unique_injection_points: int = 0
    urls_spidered: int = 0
    http_requests: int = 0
    average_response_ms: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "unique_injection_points": self.unique_injection_points,
            "urls_spidered": self.urls_spidered,
            "http_requests": self.http_requests,
            "average_response_ms": self.average_response_ms,
        }


@dataclass
class ScanResult:
    target: str
    scan_type: str = "Light"
    authentication: bool = False
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finish_time: datetime | None = None
    status: str = "Running"
    findings: list[Finding] = field(default_factory=list)
    tests_performed: list[str] = field(default_factory=list)
    ports: list[str] = field(default_factory=lambda: ["443"])
    stats: ScanStats = field(default_factory=ScanStats)
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
        """Highest risk first; ties keep the order the checks ran in."""
        return sorted(
            self.findings,
            key=lambda f: (-int(f.severity), self.findings.index(f)),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "authentication": self.authentication,
            "start_time": self.start_time.isoformat(),
            "finish_time": self.finish_time.isoformat() if self.finish_time else None,
            "duration_seconds": self.duration_seconds,
            "status": self.status,
            "overall_risk": self.overall_risk.label,
            "rating_counts": self.rating_counts,
            "findings": [f.as_dict() for f in self.sorted_findings],
            "tests_performed": self.tests_performed,
            "ports": self.ports,
            "stats": self.stats.as_dict(),
            "errors": self.errors,
        }
