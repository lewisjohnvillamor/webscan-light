"""Stored (persistent) XSS detector.

Submits a unique, harmless marker through each form, then re-crawls the site to
see whether the marker is later served back unencoded (in a context where script
would execute). It never delivers a working exploit payload.
"""
from __future__ import annotations

from webscan.core.http import HttpClient, normalize_target
from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.spider import crawl
from webscan.core.toolreport import Section, ToolReport

from .base import ToolOptions, tool

BREAKOUT = '"><b>'
TEXT_TYPES = {"text", "textarea", "search", "url", "email", "", "hidden"}


@tool(id="storedxss", name="Stored XSS Detector", category="Exploit", glyph="💾", order=71,
      target_hint="URL", active=True,
      description="Submit markers through forms and detect stored/persistent XSS on re-crawl.")
def run(target: str, options: ToolOptions) -> ToolReport:
    base = normalize_target(target)
    report = ToolReport(tool="storedxss", tool_name="Stored XSS Detector", target=base)
    report.params = [("Target", base), ("Mode", "active (submit + re-crawl)")]
    if not options.authorized:
        report.errors.append(
            "Active testing is disabled. Re-run with --authorized (CLI) or tick the "
            "authorization box (UI) to confirm you are permitted to test this target.")
        return report.finish("Blocked")

    client = HttpClient(timeout=options.timeout, verify_tls=options.verify_tls, delay=options.delay,
                        extra_headers={"Cookie": options.cookie} if options.cookie else None)
    crawl_result = crawl(client, base, max_pages=options.max_items or 10, max_depth=2,
                         render=options.render)
    forms = [f for f in crawl_result.forms if any(
        i.get("type", "") in TEXT_TYPES for i in f.inputs if i.get("name"))]

    submitted: list[tuple[str, str, str]] = []  # (marker, form action, field)
    for index, form in enumerate(forms):
        marker = f"wsstored{index}z"
        data = {}
        for field in form.inputs:
            name = field.get("name")
            if not name:
                continue
            ftype = field.get("type", "")
            if ftype in TEXT_TYPES:
                data[name] = f"{marker}{BREAKOUT}"
            else:
                data[name] = field.get("value", "") or "1"
        resp = client.request(form.method or "POST", form.action, data=data, cache=False)
        if resp.ok:
            submitted.append((marker, form.action, ", ".join(data)))

    # Re-crawl and look for any marker reflected with the raw breakout sequence.
    recrawl = crawl(client, base, max_pages=(options.max_items or 10) + 4, max_depth=2)
    pages_text = {page.url: page.response.text for page in recrawl.pages}
    rows: list[list[str]] = []
    for marker, action, fields in submitted:
        found_on = [url for url, text in pages_text.items()
                    if f"{marker}{BREAKOUT}" in text]
        stored = bool(found_on)
        rows.append([action, fields, "STORED + unencoded" if stored else "not reflected"])
        if stored:
            report.findings.append(Finding(
                test_id="stored_xss", title=f"Stored XSS via form {action}",
                severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                table=Table(["Form action", "Reflected on"], [[action, found_on[0]]]),
                risk_description="A value submitted through this form is stored and later served "
                                 "back to users without encoding, including the characters needed "
                                 "to break out of HTML context. Stored XSS runs for every visitor "
                                 "of the affected page.",
                recommendation="Context-encode all stored content on output and apply a strict "
                               "Content-Security-Policy. Validate and sanitise on input as defence "
                               "in depth.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],  # noqa: E501
                classification=Classification(cwe=["CWE-79"], owasp_2021=["A3 - Injection"],
                                              owasp_2017=["A7 - Cross-Site Scripting (XSS)"],
                                              owasp_2025=["A03 - Injection"])))

    report.sections.append(Section(
        title=f"Forms submitted ({len(submitted)})",
        intro="No suitable forms were found to test." if not submitted else "",
        table=Table(["Form action", "Fields", "Result"], rows)))
    report.stats = [("Forms tested", str(len(forms))), ("HTTP requests", str(client.request_count))]
    return report.finish()
