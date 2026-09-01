"""Checks over the HTML forms discovered during the crawl."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from webscan.core.context import ScanContext
from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.registry import check

from .common import INSECURE_DESIGN_2025, misconfig

AUTH_CLASSIFICATION = Classification(
    cwe=["CWE-319"],
    owasp_2017=["A3 - Sensitive Data Exposure"],
    owasp_2021=["A2 - Cryptographic Failures"],
    owasp_2025=["A03 - Cryptographic Failures"],
)


@check("login_interfaces", "Scanned for login interfaces", order=90)
def login_interfaces(context: ScanContext) -> list[Finding]:
    rows = [
        [form.page_url, form.action, form.method,
         ", ".join(form.field_names) or "-"]
        for form in context.crawl.forms
        if form.has_password
    ]
    if not rows:
        return []
    return [
        Finding(
            test_id="login_interfaces",
            title="Login interface found",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(
                columns=["Page URL", "Form action", "Method", "Fields"], rows=rows[:20]
            ),
            risk_description=(
                "There is no direct risk in exposing a login form. It is reported because an "
                "authentication entry point is the target of credential stuffing and "
                "brute-force attacks, and deserves rate limiting and monitoring."
            ),
            recommendation=(
                "Protect the login endpoint with rate limiting, account lockout or progressive "
                "delays, multi-factor authentication, and monitoring for credential stuffing."
            ),
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            ],
            classification=Classification(
                cwe=["CWE-1018"],
                owasp_2017=["A2 - Broken Authentication"],
                owasp_2021=["A7 - Identification and Authentication Failures"],
                owasp_2025=["A07 - Authentication Failures"],
            ),
        )
    ]


@check("password_unencrypted", "Scanned for passwords submitted unencrypted", order=91)
def password_unencrypted(context: ScanContext) -> list[Finding]:
    rows = [
        [form.page_url, form.action, "Password form submits over plain HTTP"]
        for form in context.crawl.forms
        if form.has_password and urlparse(form.action).scheme == "http"
    ]
    if not rows:
        return []
    return [
        Finding(
            test_id="password_unencrypted",
            title="Password submitted over an unencrypted channel",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(columns=["Page URL", "Form action", "Evidence"], rows=rows),
            risk_description=(
                "The risk is that credentials travel in clear text and can be read by anyone "
                "positioned on the network between the user and the server."
            ),
            recommendation=(
                "Point the form action at an https:// URL and serve the page containing the "
                "form over HTTPS as well."
            ),
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
            ],
            classification=AUTH_CLASSIFICATION,
        )
    ]


@check("secure_password_submission", "Scanned for secure password submission", order=92)
def secure_password_submission(context: ScanContext) -> list[Finding]:
    rows: list[list[str]] = []
    for form in context.crawl.forms:
        if not form.has_password:
            continue
        issues = []
        if form.method == "GET":
            issues.append("form uses the GET method")
        if urlparse(form.page_url).scheme == "http":
            issues.append("the page hosting the form is served over HTTP")
        if issues:
            rows.append([form.page_url, form.action, "; ".join(issues)])
    if not rows:
        return []
    return [
        Finding(
            test_id="secure_password_submission",
            title="Insecure password submission",
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(columns=["Page URL", "Form action", "Evidence"], rows=rows),
            risk_description=(
                "The risk is that credentials are exposed before they even reach the server: "
                "a GET form puts the password in the URL, and a form delivered over HTTP can "
                "be rewritten in transit to send the password anywhere."
            ),
            recommendation=(
                "Serve the login page over HTTPS and submit credentials with POST to an HTTPS "
                "endpoint."
            ),
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            ],
            classification=AUTH_CLASSIFICATION,
        )
    ]


@check("file_upload", "Scanned for file upload", order=93)
def file_upload(context: ScanContext) -> list[Finding]:
    rows = [
        [form.page_url, form.action, form.method,
         ", ".join(i["name"] for i in form.inputs if i["type"] == "file") or "-"]
        for form in context.crawl.forms
        if form.has_file_upload
    ]
    if not rows:
        return []
    return [
        Finding(
            test_id="file_upload",
            title="File upload functionality found",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(
                columns=["Page URL", "Form action", "Method", "File fields"], rows=rows[:20]
            ),
            risk_description=(
                "There is no direct risk in offering file uploads. It is reported because "
                "upload endpoints are a common route to remote code execution when the file "
                "type, name and storage location are not tightly controlled."
            ),
            recommendation=(
                "Validate the file type by content rather than extension, store uploads "
                "outside the web root, generate new file names, and never serve uploaded "
                "files from a path where they can be executed."
            ),
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
            ],
            classification=Classification(
                cwe=["CWE-434"],
                owasp_2017=["A6 - Security Misconfiguration"],
                owasp_2021=["A4 - Insecure Design"],
                owasp_2025=[INSECURE_DESIGN_2025],
            ),
        )
    ]


API_HINT = re.compile(r"(?i)(^|/)(api|graphql|rest|v[0-9]+|_next/data|wp-json)(/|$)")


@check("api_endpoints", "Scanned for API endpoints", order=94)
def api_endpoints(context: ScanContext) -> list[Finding]:
    candidates: set[str] = set()
    for page in context.crawl.pages:
        for url in [page.url, *page.links, *page.scripts]:
            path = urlparse(url).path
            if API_HINT.search(path):
                candidates.add(url)
        # Endpoints referenced from inline script bodies.
        for match in re.findall(r"[\"'](/(?:api|graphql|wp-json)/[A-Za-z0-9_\-/.]{1,80})[\"']",
                                page.response.text):
            candidates.add(context.url_for(match))
    if not candidates:
        return []
    rows = [[url, "Referenced by the application"] for url in sorted(candidates)[:25]]
    return [
        Finding(
            test_id="api_endpoints",
            title="API endpoints discovered",
            severity=Severity.INFO,
            confidence=Confidence.UNCONFIRMED,
            port=context.port,
            table=Table(columns=["URL", "Evidence"], rows=rows),
            risk_description=(
                "There is no direct risk in having API endpoints. They are listed because APIs "
                "frequently enforce weaker authorization than the web interface and are worth "
                "reviewing separately."
            ),
            recommendation=(
                "Ensure every endpoint enforces authentication and object-level authorization, "
                "and that undocumented or deprecated versions are removed from production."
            ),
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
            ],
            classification=misconfig("CWE-200"),
        )
    ]
