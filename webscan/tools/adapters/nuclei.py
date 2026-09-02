"""nuclei adapter - optional template-based vulnerability scanning.

nuclei (https://github.com/projectdiscovery/nuclei, MIT) ships thousands of
community-maintained detection templates with fresh CVE proof-of-concepts. We
never try to reproduce that corpus; instead, when the `nuclei` binary is present
we invoke it, parse its JSONL output, and fold each result into the same Finding
model the native engine uses - so nuclei results share the report, the severity
scoring and the OWASP mapping.

It is active/intrusive, so it is gated behind --authorized (CLI) or the
authorization checkbox (UI), rate-limited by default, and bounded by an overall
time budget. If nuclei is not installed the tool returns install guidance rather
than failing.
"""
from __future__ import annotations

import json
import shutil
import subprocess  # nosec B404: fixed argv list, no shell
from urllib.parse import urlparse

from webscan.core.http import normalize_target
from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.toolreport import Section, ToolReport

from ..base import ToolOptions, tool

BINARY = "nuclei"
INSTALL_HINT = (
    "nuclei is not installed on this host. Install it (Go: "
    "`go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`, or a "
    "release binary / `webscan-light:full` Docker image) to enable this tool.")

_SEVERITY = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL, "unknown": Severity.INFO,
}


def path() -> str | None:
    return shutil.which(BINARY)


def version() -> str:
    binary = path()
    if not binary:
        return ""
    try:
        out = subprocess.run(  # nosec B603: fixed argv, no shell
            [binary, "-version"], capture_output=True, text=True, timeout=10)
    except (subprocess.TimeoutExpired, OSError):
        return ""
    text = (out.stderr or "") + (out.stdout or "")
    for line in text.splitlines():
        if "version" in line.lower():
            return line.strip()
    return text.strip().splitlines()[0] if text.strip() else "(unknown)"


def _as_list(value) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v]
    return [str(value)]


def _finding(entry: dict) -> Finding | None:
    info = entry.get("info") or {}
    name = info.get("name") or entry.get("template-id") or "nuclei detection"
    template_id = entry.get("template-id") or entry.get("templateID") or "nuclei"
    severity = _SEVERITY.get(str(info.get("severity", "info")).lower(), Severity.INFO)

    matched = entry.get("matched-at") or entry.get("matched") or entry.get("host") or ""
    rows = [["Template", template_id]]
    if entry.get("type"):
        rows.append(["Protocol", str(entry["type"])])
    if matched:
        rows.append(["Matched at", str(matched)])
    if entry.get("matcher-name"):
        rows.append(["Matcher", str(entry["matcher-name"])])
    extracted = _as_list(entry.get("extracted-results"))
    if extracted:
        rows.append(["Extracted", ", ".join(extracted)[:300]])

    cls = info.get("classification") or {}
    classification = Classification(
        cve=_as_list(cls.get("cve-id")),
        cwe=_as_list(cls.get("cwe-id")),
        cvss_v3=_coerce_float(cls.get("cvss-score")),
        epss_score=_coerce_float(cls.get("epss-score")),
        epss_percentile=_coerce_float(cls.get("epss-percentile")),
    )

    port = ""
    try:
        parsed = urlparse(str(matched) if "://" in str(matched) else "//" + str(matched))
        if parsed.port:
            port = str(parsed.port)
    except (ValueError, TypeError):
        port = ""

    exchange = None
    request, response = entry.get("request"), entry.get("response")
    if request or response:
        exchange = "\n\n".join(p for p in (request, response) if p)[:8000]

    return Finding(
        test_id=f"nuclei_{template_id}",
        title=name,
        severity=severity,
        confidence=Confidence.CONFIRMED,
        port=port,
        table=Table(columns=["Field", "Value"], rows=rows),
        risk_description=info.get("description", "") or "",
        recommendation=info.get("remediation", "") or "",
        references=_as_list(info.get("reference")),
        classification=classification,
        request_response=exchange,
    )


def _coerce_float(value) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


@tool(id="nuclei", name="Nuclei (templates)", category="Vulnerability", glyph="NUC",
      order=45, target_hint="URL", active=True,
      description="Template-based vulnerability scanning via the external nuclei engine "
                  "(optional; results folded into the report).")
def run(target: str, options: ToolOptions) -> ToolReport:
    base = normalize_target(target)
    report = ToolReport(tool="nuclei", tool_name="Nuclei (templates)", target=base)

    binary = path()
    if not binary:
        report.params = [("Target", base), ("Engine", "nuclei (not installed)")]
        report.sections.append(Section(title="nuclei not available", intro=INSTALL_HINT))
        report.errors.append(INSTALL_HINT)
        return report.finish("Skipped")

    if not options.authorized:
        report.params = [("Target", base), ("Engine", version() or "nuclei")]
        report.errors.append(
            "nuclei is active/intrusive. Re-run with --authorized (CLI) or tick the "
            "authorization box (UI) to confirm you are permitted to test this target.")
        return report.finish("Blocked")

    # Guard against a target that could be read as a flag by the Go arg parser.
    if base.strip().startswith("-"):
        report.errors.append("Refusing an unsafe target that begins with '-'.")
        return report.finish("Blocked")

    extra = options.extra or {}
    severity = extra.get("severity", "low,medium,high,critical")
    rate_limit = extra.get("rate_limit") or ("30" if options.delay else "150")
    budget = _coerce_float(extra.get("budget")) or 300.0
    concurrency = str(max(1, min(options.workers, 50)))

    command = [
        binary, "-target", base, "-jsonl", "-silent", "-no-color",
        "-disable-update-check", "-severity", severity,
        "-rate-limit", str(rate_limit), "-concurrency", concurrency,
        "-timeout", str(int(max(options.timeout, 5))),
    ]
    for flag, key in (("-tags", "tags"), ("-templates", "templates"),
                      ("-exclude-tags", "exclude_tags")):
        if extra.get(key):
            command += [flag, str(extra[key])]

    report.params = [
        ("Target", base), ("Engine", version() or "nuclei"),
        ("Severity filter", severity), ("Rate limit", str(rate_limit)),
        ("Time budget", f"{int(budget)}s"),
        ("Templates", str(extra.get("templates", "default set"))),
    ]

    timed_out = False
    stdout = ""
    try:
        result = subprocess.run(  # nosec B603: fixed argv, no shell
            command, capture_output=True, text=True, timeout=budget)
        stdout = result.stdout or ""
        if result.stderr and "matched" not in result.stderr.lower():
            for line in result.stderr.splitlines():
                if line.strip() and not line.startswith("["):
                    report.errors.append(line.strip()[:200])
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = (exc.stdout.decode() if isinstance(exc.stdout, bytes) else exc.stdout) or ""
        report.errors.append(f"nuclei hit the {int(budget)}s time budget; partial results shown.")
    except OSError as exc:
        report.errors.append(f"Could not run nuclei: {exc}")
        return report.finish("Error")

    parsed = 0
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        finding = _finding(entry)
        if finding:
            report.findings.append(finding)
            parsed += 1

    report.stats = [("Findings", str(parsed)), ("Templates run", "nuclei default/selected")]
    if not parsed and not timed_out:
        report.sections.append(Section(
            title="No template matches",
            intro="nuclei ran but no templates matched at the selected severity levels."))
    return report.finish("Finished")
