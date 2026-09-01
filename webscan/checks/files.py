"""Checks for well-known files and exposed directories."""
from __future__ import annotations

import re

from webscan.core.context import ScanContext
from webscan.core.models import Confidence, Finding, Severity, Table
from webscan.core.registry import check

from .common import INSECURE_DESIGN_2025, misconfig


@check("robots", "Scanned for robots.txt file", order=30)
def robots_txt(context: ScanContext) -> list[Finding]:
    response = context.fetch("/robots.txt")
    if not response.ok or response.status_code != 200:
        return []
    ctype = (response.header("Content-Type") or "").lower()
    if "html" in ctype:  # soft-404 that returns the site's index page
        return []
    if not re.search(r"(?im)^\s*(user-agent|disallow|allow|sitemap)\s*:", response.text):
        return []
    return [
        Finding(
            test_id="robots",
            title="Robots.txt file found",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(columns=["URL"], rows=[[response.url]]),
            risk_description=(
                "There is no particular security risk in having a robots.txt file. However, "
                "it's important to note that adding endpoints in it should not be considered "
                "a security measure, as this file can be directly accessed and read by anyone."
            ),
            recommendation=(
                "We recommend you to manually review the entries from robots.txt and remove "
                "the ones which lead to sensitive locations in the website (ex. administration "
                "panels, configuration files, etc)."
            ),
            references=["https://www.theregister.co.uk/2015/05/19/robotstxt/"],
            classification=misconfig(owasp_2025=INSECURE_DESIGN_2025),
            request_response=response.raw_exchange(),
        )
    ]


@check("security_txt", "Scanned for absence of the security.txt file", order=31)
def security_txt(context: ScanContext) -> list[Finding]:
    candidates = ["/.well-known/security.txt", "/security.txt"]
    for path in candidates:
        response = context.fetch(path)
        if response.ok and response.status_code == 200 and "contact:" in response.text.lower():
            return []
    missing_url = context.url_for(candidates[0])
    return [
        Finding(
            test_id="security_txt",
            title="Security.txt file is missing",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(columns=["URL"], rows=[[f"Missing: {missing_url}"]]),
            risk_description=(
                "There is no particular risk in not having a security.txt file for your "
                "server. However, this file is important because it offers a designated "
                "channel for reporting vulnerabilities and security issues."
            ),
            recommendation=(
                "We recommend you to implement the security.txt file according to the "
                "standard, in order to allow researchers or users report any security issues "
                "they find, improving the defensive mechanisms of your server."
            ),
            references=["https://securitytxt.org/"],
            classification=misconfig("CWE-1188"),
        )
    ]


CLIENT_ACCESS_FILES = ("/crossdomain.xml", "/clientaccesspolicy.xml")


@check("client_access_policy", "Scanned for client access policies", order=32)
def client_access_policy(context: ScanContext) -> list[Finding]:
    rows: list[list[str]] = []
    for path in CLIENT_ACCESS_FILES:
        response = context.fetch(path)
        if not response.ok or response.status_code != 200:
            continue
        if "xml" not in (response.header("Content-Type") or "").lower() and "<" not in response.text[:200]:
            continue
        wildcard = bool(re.search(r'domain\s*=\s*"\*"', response.text, re.I))
        rows.append([
            response.url,
            "Wildcard policy (domain=\"*\") — any domain may read cross-origin data"
            if wildcard else "Policy file present",
        ])
    if not rows:
        return []
    permissive = any("Wildcard" in row[1] for row in rows)
    return [
        Finding(
            test_id="client_access_policy",
            title="Client access policy file found",
            severity=Severity.LOW if permissive else Severity.INFO,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(columns=["URL", "Evidence"], rows=rows),
            risk_description=(
                "The risk is that a permissive cross-domain policy allows content hosted on "
                "any other domain to read data from this server on behalf of an authenticated "
                "user, bypassing the same-origin policy."
            ),
            recommendation=(
                "Remove the policy file if the legacy Flash/Silverlight clients that needed it "
                "are gone, or restrict it to the specific domains that require access."
            ),
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-side_Testing/",
            ],
            classification=misconfig("CWE-942"),
        )
    ]


OPENAPI_PATHS = (
    "/openapi.json", "/swagger.json", "/openapi.yaml", "/swagger.yaml",
    "/api-docs", "/v2/api-docs", "/swagger-ui.html", "/api/openapi.json",
)


@check("openapi", "Scanned for OpenAPI files", order=33)
def openapi_files(context: ScanContext) -> list[Finding]:
    rows: list[list[str]] = []
    for path in OPENAPI_PATHS:
        response = context.fetch(path)
        if not response.ok or response.status_code != 200:
            continue
        body = response.text[:4000]
        if re.search(r'"(openapi|swagger)"\s*:', body) or re.search(r"(?m)^\s*(openapi|swagger)\s*:", body):
            rows.append([response.url, "OpenAPI/Swagger definition is publicly readable"])
        elif "swagger-ui" in body.lower():
            rows.append([response.url, "Swagger UI is publicly reachable"])
    if not rows:
        return []
    return [
        Finding(
            test_id="openapi",
            title="OpenAPI/Swagger definition exposed",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(columns=["URL", "Evidence"], rows=rows),
            risk_description=(
                "The risk is that a publicly readable API definition hands an attacker the "
                "complete list of endpoints, parameters and authentication requirements, "
                "removing the guesswork from attacking the API."
            ),
            recommendation=(
                "Restrict the API definition and any interactive documentation UI to "
                "authenticated internal users, or do not deploy them to production."
            ),
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
            ],
            classification=misconfig("CWE-200"),
        )
    ]


DIR_LISTING_PATTERNS = (
    re.compile(r"<title>\s*Index of /", re.I),
    re.compile(r"<h1>\s*Index of /", re.I),
    re.compile(r"Directory Listing For", re.I),
    re.compile(r"\[To Parent Directory\]", re.I),
)

COMMON_DIRS = ("/images/", "/img/", "/static/", "/assets/", "/uploads/", "/files/", "/css/", "/js/")


@check("directory_listing", "Scanned for directory listing", order=34)
def directory_listing(context: ScanContext) -> list[Finding]:
    rows: list[list[str]] = []
    for path in COMMON_DIRS:
        response = context.fetch(path)
        if not response.ok or response.status_code != 200:
            continue
        if any(pattern.search(response.text) for pattern in DIR_LISTING_PATTERNS):
            rows.append([response.url, "Server returned an automatically generated directory index"])
    if not rows:
        return []
    return [
        Finding(
            test_id="directory_listing",
            title="Directory listing enabled",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(columns=["URL", "Evidence"], rows=rows),
            risk_description=(
                "The risk is that directory listings reveal files that were never meant to be "
                "linked — backups, configuration files, source archives — which an attacker "
                "can download directly."
            ),
            recommendation=(
                "Disable automatic directory indexing in the web server configuration "
                "(for example 'autoindex off' in nginx or 'Options -Indexes' in Apache)."
            ),
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
            ],
            classification=misconfig("CWE-548"),
        )
    ]
