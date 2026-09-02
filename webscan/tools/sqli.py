"""SQL injection detector (active, non-destructive).

Uses three classic, low-impact signals: database error messages, boolean
differential (AND 1=1 vs AND 1=2), and an optional time-based probe. It reads
only; it never modifies data and sends no destructive statements.
"""
from __future__ import annotations

import re
import time

from webscan.core.http import HttpClient, normalize_target
from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.toolreport import Section, ToolReport

from .base import ToolOptions, tool
from .injection import discover

SQL_ERRORS = [
    (re.compile(r"(?i)SQL syntax.*MySQL"), "MySQL"),
    (re.compile(r"(?i)valid MySQL result"), "MySQL"),
    (re.compile(r"(?i)\bORA-\d{5}"), "Oracle"),
    (re.compile(r"(?i)PostgreSQL.*ERROR"), "PostgreSQL"),
    (re.compile(r"(?i)Unclosed quotation mark after the character string"), "MSSQL"),
    (re.compile(r"(?i)Microsoft OLE DB Provider for SQL Server"), "MSSQL"),
    (re.compile(r"(?i)SQLite/JDBCDriver"), "SQLite"),
    (re.compile(r"(?i)sqlite3.OperationalError"), "SQLite"),
    (re.compile(r"(?i)SQLSTATE\["), "generic SQL"),
    (re.compile(r"(?i)\bpsql:.*ERROR"), "PostgreSQL"),
]
ERROR_PROBES = ["'", '"', "')", "';"]


def _error_dbms(text: str) -> str | None:
    for pattern, dbms in SQL_ERRORS:
        if pattern.search(text):
            return dbms
    return None


@tool(id="sqli", name="SQLi Detector", category="Exploit", glyph="💉", order=71,
      target_hint="URL with parameters", active=True,
      description="Actively test parameters for SQL injection (error, boolean and time based).")
def run(target: str, options: ToolOptions) -> ToolReport:
    base = normalize_target(target)
    report = ToolReport(tool="sqli", tool_name="SQLi Detector", target=base)
    report.params = [("Target", base), ("Mode", "active (read-only probes)")]

    if not options.authorized:
        report.errors.append(
            "Active testing is disabled. Re-run with --authorized (CLI) or tick the "
            "authorization box (UI) to confirm you are permitted to test this target.")
        return report.finish("Blocked")

    client = HttpClient(timeout=max(options.timeout, 12), verify_tls=options.verify_tls, delay=options.delay)
    points = discover(client, base, max_pages=options.max_items or 10, max_depth=2, render=options.render)
    report.stats = [("Injection points", str(len(points)))]
    if not points:
        report.sections.append(Section(title="Injection points",
                                       intro="No GET/POST parameters were found to test."))
        return report.finish()

    tested_rows: list[list[str]] = []
    for point in points:
        original = point.base_params.get(point.param, "1")
        result = "no signal"
        detected = None

        # 1) Error-based.
        for probe in ERROR_PROBES:
            method, url, data = point.build(f"{original}{probe}")
            resp = client.request(method, url, data=data, cache=False)
            if resp.ok:
                dbms = _error_dbms(resp.text)
                if dbms:
                    detected = ("error-based", dbms, f"{original}{probe}")
                    result = f"error-based ({dbms})"
                    break

        # 2) Boolean-based differential.
        if not detected:
            m1, u1, d1 = point.build(f"{original}' AND '1'='1")
            m2, u2, d2 = point.build(f"{original}' AND '1'='2")
            r_true = client.request(m1, u1, data=d1, cache=False)
            r_false = client.request(m2, u2, data=d2, cache=False)
            if r_true.ok and r_false.ok and r_true.status_code == r_false.status_code:
                delta = abs(len(r_true.text) - len(r_false.text))
                if delta > 40 and len(r_true.text) != len(r_false.text):
                    baseline = client.request(*point.build(original)[:2],
                                              data=point.build(original)[2], cache=False)
                    if baseline.ok and abs(len(baseline.text) - len(r_true.text)) < delta:
                        detected = ("boolean-based", "differential response", "' AND '1'='1 vs '1'='2")
                        result = "boolean-based (response differs)"

        # 3) Time-based (opt-in via active; kept to one careful probe).
        if not detected and options.extra.get("time_based") == "1":
            payload = f"{original}'; SELECT pg_sleep(4)-- -"
            method, url, data = point.build(payload)
            start = time.monotonic()
            resp = client.request(method, url, data=data, cache=False)
            elapsed = time.monotonic() - start
            if resp.ok and elapsed > 3.5:
                detected = ("time-based", "delayed response", payload)
                result = f"time-based ({elapsed:.1f}s delay)"

        tested_rows.append([point.method, point.param, result])

        if detected:
            technique, evidence, payload = detected
            report.findings.append(Finding(
                test_id="sqli", title=f"SQL injection in parameter '{point.param}' ({technique})",
                severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                table=Table(columns=["Method", "Parameter", "Technique", "Evidence"],
                            rows=[[point.method, point.param, technique, evidence]]),
                risk_description="The parameter alters the SQL query. An attacker can read or "
                                 "modify the entire database, bypass authentication, and in many "
                                 "configurations execute commands on the database host.",
                recommendation="Use parameterized queries / prepared statements everywhere and "
                               "apply least-privilege database accounts. Never concatenate input "
                               "into SQL.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
                classification=Classification(cwe=["CWE-89"], owasp_2021=["A3 - Injection"],
                                              owasp_2017=["A1 - Injection"]),
                request_response=f"{point.method} {point.url}\nparameter {point.param} = {payload}",
            ))

    report.sections.append(Section(
        title=f"Parameters tested ({len(tested_rows)})",
        table=Table(columns=["Method", "Parameter", "Result"], rows=tested_rows),
    ))
    report.stats.append(("HTTP requests", str(client.request_count)))
    return report.finish()
