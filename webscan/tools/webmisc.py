"""Web misconfiguration scanner: CORS, clickjacking, open redirect, host-header, CRLF."""
from __future__ import annotations

from urllib.parse import urlparse

from webscan.core.http import HttpClient, normalize_target
from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.toolreport import Section, ToolReport

from .base import ToolOptions, tool
from .injection import discover

EVIL = "evil-webscan-test.example"
REDIRECT_PARAMS = {"url", "next", "redirect", "redirect_uri", "redirect_url", "return",
                   "returnurl", "return_url", "dest", "destination", "continue", "goto",
                   "r", "u", "link", "target", "redir", "out"}


def _misconfig(cwe):
    return Classification(cwe=[cwe], owasp_2021=["A5 - Security Misconfiguration"],
                          owasp_2017=["A6 - Security Misconfiguration"],
                          owasp_2025=["A02 - Security Misconfiguration"])


@tool(id="webmisc", name="Web Misconfig Scanner", category="Vulnerability", glyph="🧱", order=57,
      target_hint="URL", active=True,
      description="Test CORS, clickjacking, open redirect, host-header and CRLF-injection issues.")
def run(target: str, options: ToolOptions) -> ToolReport:
    base = normalize_target(target)
    report = ToolReport(tool="webmisc", tool_name="Web Misconfig Scanner", target=base)
    report.params = [("Target", base)]
    client = HttpClient(timeout=options.timeout, verify_tls=options.verify_tls)
    port = "443/tcp" if urlparse(base).scheme == "https" else "80/tcp"
    checks: list[list[str]] = []

    root = client.get(base)
    if not root.ok:
        report.errors.append(f"Could not fetch {base}: {root.error}")
        return report.finish("Failed")

    # ---- CORS ----
    cors = client.get(base, headers={"Origin": f"https://{EVIL}"})
    acao = cors.header("Access-Control-Allow-Origin") or ""
    acac = (cors.header("Access-Control-Allow-Credentials") or "").lower() == "true"
    if acao == "*" or EVIL in acao:
        sev = Severity.HIGH if (acac and EVIL in acao) else Severity.MEDIUM if EVIL in acao else Severity.LOW
        checks.append(["CORS", "Permissive", f"ACAO: {acao}" + (" + credentials" if acac else "")])
        report.findings.append(Finding(
            test_id="cors", title="Permissive CORS policy", severity=sev,
            confidence=Confidence.CONFIRMED, port=port,
            table=Table(["Origin sent", "ACAO", "Credentials"],
                        [[f"https://{EVIL}", acao, "yes" if acac else "no"]]),
            risk_description="The server reflects an arbitrary Origin (or allows any origin). "
                             "With credentials enabled this lets a malicious site read "
                             "authenticated responses on the victim's behalf.",
            recommendation="Reflect only an allow-list of trusted origins and never combine a "
                           "wildcard origin with Access-Control-Allow-Credentials.",
            classification=_misconfig("CWE-942")))
    else:
        checks.append(["CORS", "OK", acao or "no ACAO header"])

    # ---- Clickjacking ----
    xfo = root.header("X-Frame-Options")
    csp = root.header("Content-Security-Policy") or ""
    framable = not xfo and "frame-ancestors" not in csp.lower()
    if framable:
        checks.append(["Clickjacking", "Framable", "No X-Frame-Options or frame-ancestors"])
        report.findings.append(Finding(
            test_id="clickjacking", title="Page can be framed (clickjacking)",
            severity=Severity.LOW, confidence=Confidence.CONFIRMED, port=port,
            table=Table(["URL", "Evidence"], [[base, "No X-Frame-Options and no CSP frame-ancestors"]]),
            risk_description="The page can be embedded in an attacker's iframe and overlaid to "
                             "trick users into clicking hidden controls (clickjacking).",
            recommendation="Send 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
            classification=_misconfig("CWE-1021")))
    else:
        checks.append(["Clickjacking", "Protected", xfo or "CSP frame-ancestors"])

    # ---- Host header injection ----
    hh = client.get(base, headers={"Host": EVIL}, allow_redirects=False)
    location = hh.header("Location") or ""
    if EVIL in location or EVIL in hh.text[:4000]:
        checks.append(["Host header", "Reflected", f"'{EVIL}' echoed in response"])
        report.findings.append(Finding(
            test_id="host_header", title="Host header injection", severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED, port=port,
            table=Table(["Injected Host", "Reflected in"],
                        [[EVIL, "Location header" if EVIL in location else "response body"]]),
            risk_description="The application trusts the Host header and reflects it, enabling "
                             "poisoned password-reset links, cache poisoning and redirect abuse.",
            recommendation="Validate the Host header against an allow-list and use an absolute, "
                           "configured base URL rather than the request Host.",
            classification=_misconfig("CWE-644")))
    else:
        checks.append(["Host header", "OK", "not reflected"])

    # ---- Open redirect + CRLF (need parameters) ----
    points = discover(client, base, max_pages=options.max_items or 8, max_depth=2)
    redirect_hit = crlf_hit = False
    for pt in points:
        if pt.param.lower() in REDIRECT_PARAMS and not redirect_hit:
            method, url, data = pt.build(f"https://{EVIL}/")
            resp = client.request(method, url, data=data, allow_redirects=False)
            loc = resp.header("Location") or ""
            if 300 <= resp.status_code < 400 and (loc.startswith(f"https://{EVIL}")
                                                  or loc.startswith(f"//{EVIL}")):
                redirect_hit = True
                report.findings.append(Finding(
                    test_id="open_redirect", title=f"Open redirect via '{pt.param}'",
                    severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED, port=port,
                    table=Table(["Parameter", "Location"], [[pt.param, loc]]),
                    risk_description="The parameter redirects to an attacker-controlled URL, "
                                     "which aids phishing and can bypass OAuth redirect checks.",
                    recommendation="Allow redirects only to a fixed allow-list of paths/hosts.",
                    classification=Classification(cwe=["CWE-601"],
                                                  owasp_2021=["A1 - Broken Access Control"],
                                                  owasp_2017=["A5 - Broken Access Control"],
                                                  owasp_2025=["A01 - Broken Access Control"])))
        if not crlf_hit:
            method, url, data = pt.build("test%0d%0aX-Webscan-Injected:1")
            resp = client.request(method, url, data=data, allow_redirects=False)
            if resp.header("X-Webscan-Injected") == "1":
                crlf_hit = True
                report.findings.append(Finding(
                    test_id="crlf", title=f"CRLF / header injection via '{pt.param}'",
                    severity=Severity.HIGH, confidence=Confidence.CONFIRMED, port=port,
                    table=Table(["Parameter", "Evidence"], [[pt.param, "Injected response header appeared"]]),
                    risk_description="Carriage-return/line-feed injection lets an attacker add "
                                     "response headers — enabling response splitting, cache "
                                     "poisoning and cookie injection.",
                    recommendation="Strip CR/LF from any user input placed into response headers.",
                    classification=_misconfig("CWE-113")))
    checks.append(["Open redirect", "Found" if redirect_hit else "Not found",
                   f"{len(points)} parameters tested"])
    checks.append(["CRLF injection", "Found" if crlf_hit else "Not found",
                   f"{len(points)} parameters tested"])

    report.sections.append(Section(title="Checks", table=Table(["Check", "Result", "Detail"], checks)))
    report.stats = [("Parameters tested", str(len(points))), ("HTTP requests", str(client.request_count))]
    return report.finish()
