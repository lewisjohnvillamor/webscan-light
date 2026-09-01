"""Security header checks."""
from __future__ import annotations

import re

from webscan.core.context import ScanContext
from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.registry import check

from .common import misconfig

CSP_REFERENCES = [
    "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
]


def _meta_csp(context: ScanContext) -> str | None:
    page = context.root
    if not page or not page.soup:
        return None
    meta = page.soup.find(
        "meta", attrs={"http-equiv": re.compile("^content-security-policy$", re.I)}
    )
    return meta.get("content") if meta else None


@check("csp", "Scanned for missing HTTP header - Content Security Policy", order=20)
def missing_csp(context: ScanContext) -> list[Finding]:
    response = context.root_response
    if not response or not response.ok:
        return []
    if response.header("Content-Security-Policy") or _meta_csp(context):
        return []
    return [
        Finding(
            test_id="csp",
            title="Missing security header: Content-Security-Policy",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(
                columns=["URL", "Evidence"],
                rows=[[
                    context.target,
                    "Response does not include the HTTP Content-Security-Policy "
                    "security header or meta tag",
                ]],
            ),
            risk_description=(
                "The risk is that if the target application is vulnerable to XSS, lack of "
                "this header makes it easily exploitable by attackers."
            ),
            recommendation=(
                "Configure the Content-Security-Header to be sent with each HTTP response "
                "in order to apply the specific policies needed by the application."
            ),
            references=CSP_REFERENCES,
            classification=misconfig("CWE-1021"),
            request_response=response.raw_exchange(),
        )
    ]


UNSAFE_CSP_DIRECTIVES = {
    "unsafe-inline": "allows inline scripts/styles, which defeats most XSS protection",
    "unsafe-eval": "allows eval(), which lets injected strings become code",
    "*": "uses a wildcard source, allowing content from any origin",
    "data:": "allows data: URIs as a script/object source",
}


@check("csp_unsafe", "Scanned for unsafe HTTP header Content Security Policy", order=21)
def unsafe_csp(context: ScanContext) -> list[Finding]:
    response = context.root_response
    if not response or not response.ok:
        return []
    policy = response.header("Content-Security-Policy") or _meta_csp(context)
    if not policy:
        return []

    rows: list[list[str]] = []
    lowered = policy.lower()
    for directive_part in policy.split(";"):
        directive_part = directive_part.strip()
        if not directive_part:
            continue
        name = directive_part.split()[0].lower()
        if name not in ("script-src", "default-src", "object-src", "style-src", "script-src-elem"):
            continue
        for token, reason in UNSAFE_CSP_DIRECTIVES.items():
            if re.search(rf"(^|\s)'?{re.escape(token)}'?(\s|$)", directive_part, re.I):
                rows.append([context.target, name, f"'{token}' — {reason}"])
    if not lowered.strip():
        return []
    if not rows:
        return []
    return [
        Finding(
            test_id="csp_unsafe",
            title="Unsafe Content-Security-Policy directives",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(columns=["URL", "Directive", "Issue"], rows=rows),
            risk_description=(
                "The risk is that a permissive Content-Security-Policy does not actually "
                "stop script injection: sources such as 'unsafe-inline' or a wildcard origin "
                "let an attacker's payload execute even though a policy is present."
            ),
            recommendation=(
                "Remove 'unsafe-inline', 'unsafe-eval' and wildcard sources from the policy. "
                "Use nonces or hashes for the inline scripts the application genuinely needs."
            ),
            references=CSP_REFERENCES,
            classification=misconfig("CWE-1021"),
            request_response=response.raw_exchange(),
        )
    ]


@check("hsts", "Scanned for missing HTTP header - Strict-Transport-Security", order=22)
def missing_hsts(context: ScanContext) -> list[Finding]:
    response = context.root_response
    if not response or not response.ok or not context.is_https:
        return []
    if response.header("Strict-Transport-Security"):
        return []
    return [
        Finding(
            test_id="hsts",
            title="Missing security header: Strict-Transport-Security",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(
                columns=["URL", "Evidence"],
                rows=[[context.target,
                       "Response does not include the HTTP Strict-Transport-Security header"]],
            ),
            risk_description=(
                "The risk is that an attacker positioned on the network can downgrade the "
                "connection to plain HTTP before the browser ever reaches the HTTPS site, "
                "and intercept or modify the traffic."
            ),
            recommendation=(
                "Configure the Strict-Transport-Security header with a max-age of at least "
                "one year, for example: Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains."
            ),
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            ],
            classification=misconfig("CWE-319"),
            request_response=response.raw_exchange(),
        )
    ]


@check("xcto", "Scanned for missing HTTP header - X-Content-Type-Options", order=23)
def missing_xcto(context: ScanContext) -> list[Finding]:
    response = context.root_response
    if not response or not response.ok:
        return []
    if (response.header("X-Content-Type-Options") or "").lower().strip() == "nosniff":
        return []
    return [
        Finding(
            test_id="xcto",
            title="Missing security header: X-Content-Type-Options",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(
                columns=["URL", "Evidence"],
                rows=[[context.target,
                       "Response does not include the HTTP X-Content-Type-Options header"]],
            ),
            risk_description=(
                "The risk is that a browser may MIME-sniff a response and treat it as a "
                "different content type than the server declared, which can turn an uploaded "
                "or reflected file into executable script."
            ),
            recommendation=(
                "Configure the server to send X-Content-Type-Options: nosniff with each "
                "HTTP response."
            ),
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
            ],
            classification=misconfig("CWE-16"),
            request_response=response.raw_exchange(),
        )
    ]


@check("referrer_policy", "Scanned for missing HTTP header - Referrer", order=24)
def missing_referrer_policy(context: ScanContext) -> list[Finding]:
    response = context.root_response
    if not response or not response.ok:
        return []
    if response.header("Referrer-Policy"):
        return []
    return [
        Finding(
            test_id="referrer_policy",
            title="Missing security header: Referrer-Policy",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(
                columns=["URL", "Evidence"],
                rows=[[context.target,
                       "Response does not include the HTTP Referrer-Policy header"]],
            ),
            risk_description=(
                "The risk is that the full URL of a page — which may contain identifiers, "
                "tokens or other sensitive path and query data — is sent to third-party sites "
                "in the Referer header when a user follows an outbound link."
            ),
            recommendation=(
                "Configure the Referrer-Policy header, for example: "
                "Referrer-Policy: strict-origin-when-cross-origin."
            ),
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
            ],
            classification=misconfig("CWE-200"),
            request_response=response.raw_exchange(),
        )
    ]


RATE_LIMIT_HEADERS = (
    "RateLimit-Limit", "RateLimit-Policy", "X-RateLimit-Limit",
    "X-Rate-Limit-Limit", "Retry-After",
)


@check("rate_limit", "Scanned for missing HTTP header - Rate Limit", order=25)
def missing_rate_limit(context: ScanContext) -> list[Finding]:
    response = context.root_response
    if not response or not response.ok:
        return []
    if any(response.header(name) for name in RATE_LIMIT_HEADERS):
        return []
    return [
        Finding(
            test_id="rate_limit",
            title="Missing rate limiting headers",
            severity=Severity.INFO,
            confidence=Confidence.UNCONFIRMED,
            port=context.port,
            table=Table(
                columns=["URL", "Evidence"],
                rows=[[context.target,
                       "Response does not advertise any RateLimit-* or X-RateLimit-* header"]],
            ),
            risk_description=(
                "The absence of rate limiting headers is not proof that rate limiting is "
                "missing, but when no limits are enforced an attacker can brute-force "
                "credentials or scrape the application without being throttled."
            ),
            recommendation=(
                "Apply rate limiting to authentication and other expensive endpoints, and "
                "advertise the limits with the RateLimit-Limit / RateLimit-Remaining headers."
            ),
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
            ],
            classification=Classification(
                cwe=["CWE-770"],
                owasp_2017=["A6 - Security Misconfiguration"],
                owasp_2021=["A4 - Insecure Design"],
                owasp_2025=["A06 - Insecure Design"],
            ),
            request_response=response.raw_exchange(),
        )
    ]
