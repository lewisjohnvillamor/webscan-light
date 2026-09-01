"""Reflected XSS detector (active, non-destructive).

Injects a unique, harmless marker into each parameter and reports the ones that
are reflected into the response without HTML-encoding, in a context where script
execution would be possible. It never delivers a working exploit payload.
"""
from __future__ import annotations

from webscan.core.http import HttpClient, normalize_target
from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.toolreport import Section, ToolReport

from .base import ToolOptions, tool
from .injection import discover

MARKER = "wsXSS{n}probe"
# Characters whose survival (unencoded) makes injection into that context possible.
BREAKOUT = "<>\"'"


@tool(id="xss", name="XSS Detector", category="Exploit", glyph="⚡", order=70,
      target_hint="URL with parameters", active=True,
      description="Actively test parameters for reflected XSS and report a safe proof of concept.")
def run(target: str, options: ToolOptions) -> ToolReport:
    base = normalize_target(target)
    report = ToolReport(tool="xss", tool_name="XSS Detector", target=base)
    report.params = [("Target", base), ("Mode", "active (reflection probe)")]

    if not options.authorized:
        report.errors.append(
            "Active testing is disabled. Re-run with --authorized (CLI) or tick the "
            "authorization box (UI) to confirm you are permitted to test this target.")
        return report.finish("Blocked")

    client = HttpClient(timeout=options.timeout, verify_tls=options.verify_tls, delay=options.delay)
    points = discover(client, base, max_pages=options.max_items or 10, max_depth=2)
    report.stats = [("Injection points", str(len(points)))]
    if not points:
        report.sections.append(Section(title="Injection points",
                                       intro="No GET/POST parameters were found to test."))
        return report.finish()

    tested_rows: list[list[str]] = []
    for index, point in enumerate(points):
        marker = MARKER.format(n=index)
        probe = f"{marker}{BREAKOUT}"
        method, url, data = point.build(probe)
        resp = client.request(method, url, data=data, cache=False)
        if not resp.ok:
            continue
        body = resp.text
        reflected = marker in body
        raw_breakout = ""
        status = "reflected (encoded)" if reflected else "not reflected"
        if reflected:
            # Are the raw breakout characters reflected right after our marker?
            tail = body[body.find(marker) + len(marker): body.find(marker) + len(marker) + 6]
            raw_breakout = "".join(c for c in BREAKOUT if c in tail)
            if raw_breakout:
                status = f"reflected UNENCODED ({raw_breakout})"
        tested_rows.append([point.method, point.param, url if point.method == "GET" else point.url, status])

        if reflected and raw_breakout and ("<" in raw_breakout or '"' in raw_breakout or "'" in raw_breakout):
            report.findings.append(Finding(
                test_id="xss_reflected", title=f"Reflected XSS in parameter '{point.param}'",
                severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                table=Table(columns=["Method", "Parameter", "Injected", "Reflected as"],
                            rows=[[point.method, point.param, probe, f"unencoded: {raw_breakout}"]]),
                risk_description="The parameter reflects attacker input into the page without "
                                 "HTML-encoding, including characters needed to break out of the "
                                 "surrounding context. An attacker can inject script that runs in "
                                 "the victim's browser, stealing sessions or acting as the user.",
                recommendation="Context-encode all output (HTML/attribute/JS) and add a strict "
                               "Content-Security-Policy. Prefer framework auto-escaping.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
                classification=Classification(cwe=["CWE-79"], owasp_2021=["A3 - Injection"],
                                              owasp_2017=["A7 - Cross-Site Scripting (XSS)"]),
                request_response=f"{method} {url}\n\n(marker '{marker}' reflected with raw {raw_breakout})",
            ))

    report.sections.append(Section(
        title=f"Parameters tested ({len(tested_rows)})",
        table=Table(columns=["Method", "Parameter", "URL", "Result"], rows=tested_rows),
    ))
    report.stats.append(("HTTP requests", str(client.request_count)))
    return report.finish()
