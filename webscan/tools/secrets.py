"""Secrets scanner: find hard-coded credentials and keys in a local codebase."""
from __future__ import annotations

import re
from pathlib import Path

from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.toolreport import Section, ToolReport

from .base import ToolOptions, tool
from .manifests import SKIP_DIRS

PATTERNS = [
    ("AWS access key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.HIGH),
    ("AWS secret access key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}"), Severity.CRITICAL),  # noqa: E501
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.HIGH),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), Severity.HIGH),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), Severity.HIGH),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), Severity.HIGH),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{24,}\b"), Severity.CRITICAL),
    ("Twilio key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), Severity.HIGH),
    ("SendGrid key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), Severity.HIGH),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), Severity.CRITICAL),  # noqa: E501
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), Severity.MEDIUM),
    ("DB connection string w/ creds", re.compile(r"(?i)\b(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis)://[^\s:@/]+:[^\s:@/]+@"), Severity.HIGH),  # noqa: E501
    ("Generic hard-coded secret", re.compile(r"(?i)(?:api[_-]?key|secret|passwd|password|token|access[_-]?key)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"), Severity.MEDIUM),  # noqa: E501
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{40,}"), Severity.MEDIUM),
]
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf", ".zip", ".gz", ".tar",
            ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".webp", ".lock", ".min.js",
            ".map", ".so", ".dylib", ".dll", ".class", ".pyc", ".o", ".a", ".wasm"}
PLACEHOLDER = re.compile(r"(?i)(example|dummy|test|placeholder|xxx+|your[_-]?|changeme|<[^>]+>|\bfake\b|\bsample\b)")


def _redact(value: str, keep: int = 4) -> str:
    value = value.strip()
    return value if len(value) <= keep * 2 else f"{value[:keep]}…{value[-keep:]} ({len(value)} chars)"


@tool(id="secrets", name="Secrets Scanner", category="Vulnerability", glyph="🔑", order=58, local_fs=True,
      target_hint="path to a directory or file",
      description="Scan a local codebase for hard-coded credentials, keys and tokens.")
def run(target: str, options: ToolOptions) -> ToolReport:
    report = ToolReport(tool="secrets", tool_name="Secrets Scanner", target=target)
    report.params = [("Path", target)]
    base = Path(target)
    if not base.exists():
        report.errors.append(f"Path not found: {target}")
        return report.finish("Failed")

    files = [base] if base.is_file() else [
        p for p in base.rglob("*")
        if p.is_file() and not any(part in SKIP_DIRS for part in p.parts)
        and p.suffix.lower() not in SKIP_EXT]
    max_files = options.max_items or 5000
    files = files[:max_files]

    rows: list[list[str]] = []
    scanned = 0
    by_type: dict[str, int] = {}
    for path in files:
        try:
            if path.stat().st_size > 2_000_000:
                continue
            raw = path.read_bytes()
            if b"\x00" in raw[:1024]:  # binary
                continue
            text = raw.decode("utf-8", "replace")
        except OSError:
            continue
        scanned += 1
        for lineno, line in enumerate(text.splitlines(), 1):
            if len(line) > 500:
                continue
            for label, pattern, severity in PATTERNS:
                m = pattern.search(line)
                if not m:
                    continue
                if PLACEHOLDER.search(m.group(0)):
                    continue
                rel = str(path.relative_to(base)) if base.is_dir() else path.name
                rows.append([rel, str(lineno), label, _redact(m.group(0)), severity.label])
                by_type[label] = by_type.get(label, 0) + 1

    # One finding per secret type, listing locations.
    for label in sorted(by_type):
        hits = [r for r in rows if r[2] == label]
        severity = next(s for (lbl, _p, s) in PATTERNS if lbl == label)
        report.findings.append(Finding(
            test_id=f"secret_{label.lower().replace(' ', '_')[:24]}",
            title=f"{label} found in source ({by_type[label]})",
            severity=severity, confidence=Confidence.CONFIRMED,
            table=Table(["File", "Line", "Evidence"], [[h[0], h[1], h[3]] for h in hits[:50]]),
            risk_description="Secrets committed to source are exposed to everyone with repo "
                             "access and often leak publicly. Treat any committed secret as "
                             "compromised.",
            recommendation="Remove the secret, rotate it immediately, and load secrets from "
                           "environment/secret-manager at runtime. Purge it from git history.",
            classification=Classification(cwe=["CWE-798"],
                                          owasp_2021=["A5 - Security Misconfiguration"],
                                          owasp_2017=["A6 - Security Misconfiguration"],
                                          owasp_2025=["A02 - Security Misconfiguration"])))

    report.sections.append(Section(
        title=f"Findings by file ({len(rows)})",
        intro="No hard-coded secrets detected." if not rows else "",
        table=Table(["File", "Line", "Type", "Evidence", "Severity"], rows[:200])))
    report.stats = [("Files scanned", str(scanned)), ("Secrets found", str(len(rows)))]
    return report.finish()
