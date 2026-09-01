"""Technology fingerprinting.

Produces the "Server software and technology found" finding, and publishes the
detected software/version pairs on the context so the version-based CVE lookup
can consume them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from webscan.core.context import ScanContext
from webscan.core.models import Confidence, Finding, Severity, Table
from webscan.core.registry import check
from webscan.data.signatures import SIGNATURES

from .common import misconfig


@dataclass
class Technology:
    name: str
    categories: list[str]
    version: str | None = None
    cpe: str | None = None
    evidence: list[str] = field(default_factory=list)

    @property
    def display(self) -> str:
        return f"{self.name} {self.version}" if self.version else self.name


def _version_from(match: re.Match) -> str | None:
    """Prefer a named ``version`` group, falling back to the first group."""
    if "version" in match.re.groupindex:
        value = match.group("version")
    else:
        value = match.group(1) if match.re.groups else None
    return value.strip() if value else None


def _match_signature(signature: dict, context: ScanContext) -> Technology | None:
    tech = Technology(
        name=signature["name"],
        categories=list(signature.get("categories", [])),
        cpe=signature.get("cpe"),
    )
    matched = False

    response = context.root_response
    if response:
        for header_name, pattern in (signature.get("header") or {}).items():
            value = response.header(header_name)
            if value is None:
                continue
            match = re.search(pattern, value)
            if match:
                matched = True
                tech.evidence.append(f"{header_name}: {value}")
                tech.version = tech.version or _version_from(match)

    for page in context.html_pages:
        body = page.response.text
        for pattern in signature.get("html") or []:
            match = re.search(pattern, body)
            if match:
                matched = True
                tech.version = tech.version or _version_from(match)
                tech.evidence.append(f"body matches {pattern}")
                break
        for pattern in signature.get("script") or []:
            for src in page.scripts:
                match = re.search(pattern, src)
                if match:
                    matched = True
                    tech.version = tech.version or _version_from(match)
                    tech.evidence.append(f"script: {src}")
                    break
        if page.soup:
            for meta_name, pattern in (signature.get("meta") or {}).items():
                meta = page.soup.find("meta", attrs={"name": re.compile(f"^{meta_name}$", re.I)})
                content = meta.get("content") if meta else None
                if content:
                    match = re.search(pattern, content)
                    if match:
                        matched = True
                        tech.version = tech.version or _version_from(match)
                        tech.evidence.append(f"meta {meta_name}: {content}")

    for cookie_name, pattern in (signature.get("cookie") or {}).items():
        for page in context.crawl.pages:
            for raw in page.response.cookies:
                name = raw.split("=", 1)[0].strip()
                value = raw.split("=", 1)[1].split(";")[0] if "=" in raw else ""
                if re.match(f"^{re.escape(cookie_name)}$", name, re.I) and (
                    not pattern or re.search(pattern, value)
                ):
                    matched = True
                    tech.evidence.append(f"cookie: {name}")

    return tech if matched else None


def detect(context: ScanContext) -> list[Technology]:
    """Run every signature; cached on the context so checks can share the result."""
    if "technologies" in context.shared:
        return context.shared["technologies"]

    found: dict[str, Technology] = {}
    for signature in SIGNATURES:
        tech = _match_signature(signature, context)
        if tech:
            found[tech.name] = tech
    # Apply 'implies' only for technologies that were actually detected.
    for signature in SIGNATURES:
        if signature["name"] in found:
            for implied_name in signature.get("implies") or []:
                if implied_name in found:
                    continue
                implied_sig = next((s for s in SIGNATURES if s["name"] == implied_name), None)
                if implied_sig:
                    found[implied_name] = Technology(
                        name=implied_name,
                        categories=list(implied_sig.get("categories", [])),
                        cpe=implied_sig.get("cpe"),
                        evidence=[f"implied by {signature['name']}"],
                    )

    technologies = sorted(found.values(), key=lambda t: t.name.lower())
    context.shared["technologies"] = technologies
    return technologies


@check("technologies", "Scanned for website technologies", order=10)
def technologies(context: ScanContext) -> list[Finding]:
    detected = detect(context)
    if not detected:
        return []
    rows = [[tech.display, ", ".join(tech.categories)] for tech in detected]
    return [
        Finding(
            test_id="technologies",
            title="Server software and technology found",
            severity=Severity.INFO,
            confidence=Confidence.UNCONFIRMED,
            port=context.port,
            table=Table(columns=["Software / Version", "Category"], rows=rows),
            risk_description=(
                "The risk is that an attacker could use this information to mount specific "
                "attacks against the identified software type and version."
            ),
            recommendation=(
                "We recommend you to eliminate the information which permits the "
                "identification of software platform, technology, server and operating "
                "system: HTTP server headers, HTML meta information, etc."
            ),
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/stable/"
                "4-Web_Application_Security_Testing/01-Information_Gathering/"
                "02-Fingerprint_Web_Server.html",
            ],
            classification=misconfig("CWE-200"),
        )
    ]
