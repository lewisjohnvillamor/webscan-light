"""HTTP method checks."""
from __future__ import annotations

from webscan.core.context import ScanContext
from webscan.core.models import Confidence, Finding, Severity, Table
from webscan.core.registry import check

from .common import misconfig


@check("http_options", "Scanned for enabled HTTP OPTIONS method", order=40)
def http_options(context: ScanContext) -> list[Finding]:
    response = context.client.request("OPTIONS", context.target, cache=True)
    if not response.ok:
        return []
    allow = response.header("Allow") or response.header("Access-Control-Allow-Methods")
    if not allow:
        return []
    summary = (
        "We did a HTTP OPTIONS request.\n"
        f"The server responded with a {response.status_code} status code and the header: "
        f"Allow: {allow}"
    )
    return [
        Finding(
            test_id="http_options",
            title="HTTP OPTIONS enabled",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(
                columns=["URL", "Method", "Summary"],
                rows=[[context.target, "OPTIONS", summary]],
            ),
            risk_description=(
                "The only risk this might present nowadays is revealing debug HTTP methods "
                "that can be used on the server. This can present a danger if any of those "
                "methods can lead to sensitive information, like authentication information, "
                "secret keys."
            ),
            recommendation=(
                "We recommend that you check for unused HTTP methods or even better, disable "
                "the OPTIONS method. This can be done using your webserver configuration."
            ),
            references=[
                "https://techcommunity.microsoft.com/t5/iis-support-blog/http-options-and-default-page-vulnerabilities/ba-p/1504845",
                "https://docs.nginx.com/nginx-management-suite/acm/how-to/policies/allowed-http-methods/",
            ],
            classification=misconfig("CWE-16"),
            request_response=response.raw_exchange(),
        )
    ]


DEBUG_METHODS = ("TRACE", "TRACK", "DEBUG", "PUT", "DELETE", "CONNECT")


@check("debug_methods", "Scanned for enabled HTTP debug methods", order=41)
def debug_methods(context: ScanContext) -> list[Finding]:
    rows: list[list[str]] = []
    for method in DEBUG_METHODS:
        response = context.client.request(
            method, context.target, allow_redirects=False, cache=True
        )
        if not response.ok:
            continue
        # 2xx to TRACE/TRACK that echoes the request, or any 2xx to a write method,
        # means the server actually honours the method rather than rejecting it.
        if method in ("TRACE", "TRACK"):
            if response.status_code == 200 and "TRACE" in response.text.upper()[:200]:
                rows.append([context.target, method,
                             f"Server echoed the request back with status {response.status_code}"])
        elif 200 <= response.status_code < 300:
            rows.append([context.target, method,
                         f"Server accepted the request with status {response.status_code}"])
    if not rows:
        return []
    return [
        Finding(
            test_id="debug_methods",
            title="HTTP debug methods enabled",
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(columns=["URL", "Method", "Evidence"], rows=rows),
            risk_description=(
                "The risk is that debug and write HTTP methods can be abused to read back "
                "request headers (including cookies and authentication data) or to modify "
                "content on the server."
            ),
            recommendation=(
                "Disable TRACE, TRACK, DEBUG and any write method the application does not "
                "need, in the web server configuration."
            ),
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
            ],
            classification=misconfig("CWE-16"),
        )
    ]
