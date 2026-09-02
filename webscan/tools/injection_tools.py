"""Deep active injection detectors: SSTI, command injection, LFI/path traversal.

These are the injection classes the Light website scan intentionally skips.
Each is active (sends payloads) and gated behind --authorized. They reuse the
shared injection-point discovery and prefer high-signal, low-impact probes
(unique markers, error/content matches, and short time-based confirmation).
"""
from __future__ import annotations

import re
import time

from webscan.core.http import HttpClient, normalize_target
from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.toolreport import Section, ToolReport

from .base import ToolOptions, tool
from .injection import discover

INJECTION_CLASS = Classification(cwe=["CWE-94"], owasp_2021=["A3 - Injection"],
                                 owasp_2017=["A1 - Injection"], owasp_2025=["A03 - Injection"])


def _blocked(report: ToolReport, options: ToolOptions) -> bool:
    if not options.authorized:
        report.errors.append(
            "Active testing is disabled. Re-run with --authorized (CLI) or tick the "
            "authorization box (UI) to confirm you are permitted to test this target.")
        report.finish("Blocked")
        return True
    return False


def _client(options: ToolOptions, min_timeout: float = 0.0) -> HttpClient:
    return HttpClient(timeout=max(options.timeout, min_timeout), verify_tls=options.verify_tls,
                      delay=options.delay,
                      extra_headers={"Cookie": options.cookie} if options.cookie else None)


# --------------------------------------------------------------------------- SSTI
SSTI_PAYLOADS = [
    ("{{{{7*7}}}}", "49"),          # Jinja2/Twig  -> zz49zz via prefix below
    ("${{7*7}}", "49"),             # some template engines
    ("${7*7}", "49"),               # JSP EL / Freemarker
    ("<%= 7*7 %>", "49"),           # ERB
    ("#{7*7}", "49"),               # Ruby / Thymeleaf
]


@tool(id="ssti", name="SSTI Detector", category="Exploit", glyph="🧨", order=72,
      target_hint="URL with parameters", active=True,
      description="Actively test parameters for server-side template injection (SSTI).")
def ssti(target: str, options: ToolOptions) -> ToolReport:
    base = normalize_target(target)
    report = ToolReport(tool="ssti", tool_name="SSTI Detector", target=base)
    report.params = [("Target", base), ("Mode", "active (template evaluation probe)")]
    if _blocked(report, options):
        return report
    client = _client(options)
    points = discover(client, base, max_pages=options.max_items or 10, max_depth=2,
                      render=options.render)
    rows: list[list[str]] = []
    for point in points:
        hit = None
        for expr, expected in SSTI_PAYLOADS:
            marker = f"ws{abs(hash(point.param)) % 9973}"
            payload = f"{marker}{expr}{marker}"
            method, url, data = point.build(payload)
            resp = client.request(method, url, data=data, cache=False)
            if resp.ok and f"{marker}{expected}{marker}" in resp.text:
                hit = (expr, payload)
                break
        rows.append([point.method, point.param, "vulnerable" if hit else "no signal"])
        if hit:
            report.findings.append(Finding(
                test_id="ssti", title=f"Server-side template injection in '{point.param}'",
                severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED,
                table=Table(["Method", "Parameter", "Payload"], [[point.method, point.param, hit[1]]]),
                risk_description="The parameter is evaluated as a server-side template: the "
                                 "expression was computed (7*7 returned 49). SSTI commonly leads "
                                 "to remote code execution.",
                recommendation="Never pass user input into template source. Use a sandboxed "
                               "engine and pass data as context variables, not template strings.",
                references=["https://portswigger.net/research/server-side-template-injection"],
                classification=INJECTION_CLASS,
                request_response=f"{point.method} {point.url}\nparameter {point.param} = {hit[1]}"))
    report.sections.append(Section(title=f"Parameters tested ({len(rows)})",
                                   table=Table(["Method", "Parameter", "Result"], rows)))
    report.stats = [("Injection points", str(len(points))), ("HTTP requests", str(client.request_count))]
    return report.finish()


# ------------------------------------------------------------------- command injection
CMDI_OUTPUT = [(";id", re.compile(r"uid=\d+\(")), ("|id", re.compile(r"uid=\d+\(")),
               ("&&id", re.compile(r"uid=\d+\("))]
CMDI_SLEEP = ["; sleep {n}", "| sleep {n}", "`sleep {n}`", "$(sleep {n})", "& sleep {n}"]


@tool(id="cmdi", name="Command Injection", category="Exploit", glyph="⌨", order=73,
      target_hint="URL with parameters", active=True,
      description="Actively test parameters for OS command injection (output and time based).")
def cmdi(target: str, options: ToolOptions) -> ToolReport:
    base = normalize_target(target)
    report = ToolReport(tool="cmdi", tool_name="Command Injection", target=base)
    report.params = [("Target", base), ("Mode", "active (output + time based)")]
    if _blocked(report, options):
        return report
    client = _client(options, min_timeout=15)
    points = discover(client, base, max_pages=options.max_items or 8, max_depth=2,
                      render=options.render)
    rows: list[list[str]] = []
    for point in points:
        original = point.base_params.get(point.param, "1")
        detected = None
        # 1) Output-based.
        for suffix, pattern in CMDI_OUTPUT:
            method, url, data = point.build(f"{original}{suffix}")
            resp = client.request(method, url, data=data, cache=False)
            if resp.ok and pattern.search(resp.text):
                detected = ("output-based", f"{original}{suffix}")
                break
        # 2) Time-based (one confirming pair).
        if not detected:
            payload = CMDI_SLEEP[0].format(n=5)
            method, url, data = point.build(f"{original}{payload}")
            start = time.monotonic()
            resp = client.request(method, url, data=data, cache=False)
            elapsed = time.monotonic() - start
            if resp.ok and elapsed > 4.5:
                # confirm with a different duration to rule out a slow endpoint
                start = time.monotonic()
                client.request(*point.build(f"{original}{CMDI_SLEEP[0].format(n=2)}")[:2],
                               data=point.build(f"{original}{CMDI_SLEEP[0].format(n=2)}")[2], cache=False)
                elapsed2 = time.monotonic() - start
                if elapsed2 < elapsed - 1.5:
                    detected = ("time-based", f"{original}{payload}")
        rows.append([point.method, point.param, detected[0] if detected else "no signal"])
        if detected:
            report.findings.append(Finding(
                test_id="cmdi", title=f"OS command injection in '{point.param}' ({detected[0]})",
                severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED,
                table=Table(["Method", "Parameter", "Technique", "Payload"],
                            [[point.method, point.param, detected[0], detected[1]]]),
                risk_description="The parameter is passed to an operating-system shell. An "
                                 "attacker can run arbitrary commands on the server, typically a "
                                 "full compromise.",
                recommendation="Never build shell commands from user input. Use language APIs "
                               "with argument arrays, avoid the shell, and validate strictly.",
                references=["https://owasp.org/www-community/attacks/Command_Injection"],
                classification=Classification(cwe=["CWE-78"], owasp_2021=["A3 - Injection"],
                                              owasp_2017=["A1 - Injection"], owasp_2025=["A03 - Injection"]),
                request_response=f"{point.method} {point.url}\nparameter {point.param} = {detected[1]}"))
    report.sections.append(Section(title=f"Parameters tested ({len(rows)})",
                                   table=Table(["Method", "Parameter", "Result"], rows)))
    report.stats = [("Injection points", str(len(points))), ("HTTP requests", str(client.request_count))]
    return report.finish()


# --------------------------------------------------------------------------- LFI
LFI_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
]
LFI_SIGNS = [re.compile(r"root:.*:0:0:"), re.compile(r"\[extensions\]", re.I),
             re.compile(r"; for 16-bit app support", re.I)]


@tool(id="lfi", name="LFI / Path Traversal", category="Exploit", glyph="📂", order=74,
      target_hint="URL with parameters", active=True,
      description="Actively test parameters for local file inclusion / path traversal.")
def lfi(target: str, options: ToolOptions) -> ToolReport:
    base = normalize_target(target)
    report = ToolReport(tool="lfi", tool_name="LFI / Path Traversal", target=base)
    report.params = [("Target", base), ("Mode", "active (file-read probe)")]
    if _blocked(report, options):
        return report
    client = _client(options)
    points = discover(client, base, max_pages=options.max_items or 8, max_depth=2,
                      render=options.render)
    rows: list[list[str]] = []
    for point in points:
        hit = None
        for payload in LFI_PAYLOADS:
            method, url, data = point.build(payload)
            resp = client.request(method, url, data=data, cache=False)
            if resp.ok and any(sign.search(resp.text) for sign in LFI_SIGNS):
                hit = payload
                break
        rows.append([point.method, point.param, "vulnerable" if hit else "no signal"])
        if hit:
            report.findings.append(Finding(
                test_id="lfi", title=f"Local file inclusion / path traversal in '{point.param}'",
                severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                table=Table(["Method", "Parameter", "Payload"], [[point.method, point.param, hit]]),
                risk_description="The parameter reads arbitrary files from the server (a known "
                                 "system file was returned). This exposes source code, configs "
                                 "and secrets, and can escalate to code execution.",
                recommendation="Never build file paths from user input. Use an allow-list of "
                               "identifiers mapped to fixed paths, and canonicalise/validate.",
                references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                classification=Classification(cwe=["CWE-22"], owasp_2021=["A1 - Broken Access Control"],
                                              owasp_2017=["A5 - Broken Access Control"],
                                              owasp_2025=["A01 - Broken Access Control"]),
                request_response=f"{point.method} {point.url}\nparameter {point.param} = {hit}"))
    report.sections.append(Section(title=f"Parameters tested ({len(rows)})",
                                   table=Table(["Method", "Parameter", "Result"], rows)))
    report.stats = [("Injection points", str(len(points))), ("HTTP requests", str(client.request_count))]
    return report.finish()
