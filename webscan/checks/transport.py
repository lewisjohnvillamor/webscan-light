"""Transport security checks: certificate trust and HTTP/HTTPS handling."""
from __future__ import annotations

from urllib.parse import urlparse, urlunparse

from webscan.core.context import ScanContext
from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.registry import check

from .common import misconfig


@check("untrusted_cert", "Scanned for use of untrusted certificates", order=50)
def untrusted_certificate(context: ScanContext) -> list[Finding]:
    tls = context.tls
    if not tls.get("enabled"):
        return []
    if tls.get("trusted") and not tls.get("expired"):
        return []

    reason = tls.get("error") or ""
    if tls.get("expired"):
        reason = f"Certificate expired on {tls.get('not_after')}"
    return [
        Finding(
            test_id="untrusted_cert",
            title="Untrusted TLS certificate",
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(
                columns=["Host", "Issuer", "Evidence"],
                rows=[[
                    tls.get("host", context.hostname),
                    tls.get("issuer", "-") or "-",
                    reason or "Certificate could not be validated against the system trust store",
                ]],
            ),
            risk_description=(
                "The risk is that visitors cannot distinguish a genuine connection from an "
                "intercepted one. Browsers show a warning that users learn to click through, "
                "which makes a real man-in-the-middle attack far easier to carry out."
            ),
            recommendation=(
                "Install a certificate issued by a publicly trusted Certificate Authority "
                "that matches the hostname and renew it before it expires."
            ),
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
            ],
            classification=misconfig("CWE-295"),
        )
    ]


@check("secure_communication", "Scanned for secure communication", order=51)
def secure_communication(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(context.target)

    if parsed.scheme == "http":
        findings.append(
            Finding(
                test_id="secure_communication",
                title="Website does not use HTTPS",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                port=context.port,
                table=Table(
                    columns=["URL", "Evidence"],
                    rows=[[context.target, "The site was served over plain HTTP"]],
                ),
                risk_description=(
                    "The risk is that all traffic — including credentials, session cookies "
                    "and personal data — travels in clear text and can be read or modified by "
                    "anyone on the network path."
                ),
                recommendation=(
                    "Obtain a TLS certificate, serve the whole site over HTTPS and redirect "
                    "all HTTP traffic to HTTPS."
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                ],
                classification=Classification(
                    cwe=["CWE-319"],
                    owasp_2017=["A3 - Sensitive Data Exposure"],
                    owasp_2021=["A2 - Cryptographic Failures"],
                    owasp_2025=["A03 - Cryptographic Failures"],
                ),
            )
        )
        return findings

    # HTTPS target: verify the plain-HTTP version redirects to HTTPS.
    http_url = urlunparse(("http",) + tuple(parsed)[1:])
    response = context.client.get(http_url, allow_redirects=False, cache=True)
    if not response.ok:
        return findings
    location = response.header("Location") or ""
    redirects_to_https = (
        300 <= response.status_code < 400 and location.lower().startswith("https://")
    )
    if not redirects_to_https:
        findings.append(
            Finding(
                test_id="secure_communication",
                title="HTTP traffic is not redirected to HTTPS",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                port=context.port,
                table=Table(
                    columns=["URL", "Evidence"],
                    rows=[[
                        http_url,
                        f"Plain HTTP request returned status {response.status_code}"
                        + (f" with Location: {location}" if location else " without redirecting to HTTPS"),
                    ]],
                ),
                risk_description=(
                    "The risk is that a user who types the address without a scheme, or "
                    "follows an old http:// link, is served over an unencrypted channel where "
                    "the traffic can be intercepted or modified."
                ),
                recommendation=(
                    "Configure the web server to answer every plain HTTP request with a "
                    "301 redirect to the equivalent HTTPS URL, and enable HSTS."
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                ],
                classification=misconfig("CWE-319"),
                request_response=response.raw_exchange(),
            )
        )
    return findings


@check("mixed_content", "Scanned for mixed content between HTTP and HTTPS", order=52)
def mixed_content(context: ScanContext) -> list[Finding]:
    if not context.is_https:
        return []
    rows: list[list[str]] = []
    for page in context.html_pages:
        if not page.soup:
            continue
        for element in page.soup.find_all(["script", "img", "iframe", "link", "audio", "video", "source"]):
            url = element.get("src") or element.get("href") or ""
            if url.lower().startswith("http://"):
                rows.append([page.url, element.name, url])
    if not rows:
        return []
    active = {"script", "iframe", "link"}
    severity = Severity.MEDIUM if any(row[1] in active for row in rows) else Severity.LOW
    return [
        Finding(
            test_id="mixed_content",
            title="Mixed content between HTTP and HTTPS",
            severity=severity,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(columns=["Page URL", "Element", "Insecure resource"], rows=rows[:25]),
            risk_description=(
                "The risk is that resources loaded over plain HTTP inside an HTTPS page can be "
                "intercepted and replaced. For scripts and stylesheets this gives an attacker "
                "code execution in the context of the secure page."
            ),
            recommendation=(
                "Serve every sub-resource over HTTPS, or use protocol-relative/absolute HTTPS "
                "URLs. The upgrade-insecure-requests CSP directive can be used as a stop-gap."
            ),
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
            ],
            classification=misconfig("CWE-319"),
        )
    ]


TRUSTED_CDN_HINTS = ("cdnjs.cloudflare.com", "cdn.jsdelivr.net", "code.jquery.com", "unpkg.com")


@check("cross_domain_inclusion", "Scanned for cross domain file inclusion", order=53)
def cross_domain_inclusion(context: ScanContext) -> list[Finding]:
    rows: list[list[str]] = []
    seen: set[str] = set()
    for page in context.html_pages:
        if not page.soup:
            continue
        for script in page.soup.find_all("script", src=True):
            src = script["src"].strip()
            host = urlparse(src if "//" in src else "").hostname
            if not host or host == context.hostname or src in seen:
                continue
            seen.add(src)
            has_integrity = bool(script.get("integrity"))
            rows.append([
                page.url,
                src,
                "Subresource Integrity present" if has_integrity else "No integrity attribute",
            ])
    unprotected = [row for row in rows if row[2] == "No integrity attribute"]
    if not unprotected:
        return []
    return [
        Finding(
            test_id="cross_domain_inclusion",
            title="Cross-domain JavaScript included without Subresource Integrity",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(columns=["Page URL", "Script source", "Evidence"], rows=unprotected[:25]),
            risk_description=(
                "The risk is that the application executes code it does not control. If the "
                "third-party host is compromised or hijacked, arbitrary JavaScript runs with "
                "full access to this site's pages, cookies and DOM."
            ),
            recommendation=(
                "Host critical scripts yourself, or pin third-party scripts with a Subresource "
                "Integrity hash and the crossorigin attribute."
            ),
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
            ],
            classification=Classification(
                cwe=["CWE-829"],
                owasp_2017=["A9 - Using Components with Known Vulnerabilities"],
                owasp_2021=["A8 - Software and Data Integrity Failures"],
                owasp_2025=["A04 - Software Supply Chain Failures"],
            ),
        )
    ]
