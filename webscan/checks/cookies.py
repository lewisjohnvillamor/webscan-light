"""Cookie attribute checks."""
from __future__ import annotations

from dataclasses import dataclass

from webscan.core.context import ScanContext
from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.registry import check

from .common import misconfig


@dataclass
class Cookie:
    name: str
    attributes: dict[str, str]
    source_url: str
    raw: str

    def has(self, flag: str) -> bool:
        return flag.lower() in self.attributes

    def get(self, attribute: str) -> str:
        return self.attributes.get(attribute.lower(), "")


def _parse_cookie(raw: str, source_url: str) -> Cookie | None:
    parts = [part.strip() for part in raw.split(";") if part.strip()]
    if not parts or "=" not in parts[0]:
        return None
    name = parts[0].split("=", 1)[0].strip()
    attributes: dict[str, str] = {}
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            attributes[key.strip().lower()] = value.strip()
        else:
            attributes[part.lower()] = ""
    return Cookie(name=name, attributes=attributes, source_url=source_url, raw=raw)


def collect_cookies(context: ScanContext) -> list[Cookie]:
    """Parse every Set-Cookie seen during the crawl (cached on the context)."""
    cached = context.shared.get("cookies")
    if cached is not None:
        return cached
    return context.cached("cookies", lambda: _collect(context))


def _collect(context: ScanContext) -> list[Cookie]:
    cookies: list[Cookie] = []
    seen: set[str] = set()
    for page in context.crawl.pages:
        for raw in page.response.cookies:
            cookie = _parse_cookie(raw, page.url)
            if cookie and cookie.name not in seen:
                seen.add(cookie.name)
                cookies.append(cookie)
    return cookies


SESSION_HINTS = ("sess", "sid", "auth", "token", "login", "jwt", "csrf", "remember")


def _looks_like_session(cookie: Cookie) -> bool:
    lowered = cookie.name.lower()
    return any(hint in lowered for hint in SESSION_HINTS)


@check("cookie_httponly", "Scanned for HttpOnly flag of cookie", order=60)
def cookie_httponly(context: ScanContext) -> list[Finding]:
    rows = [
        [cookie.source_url, cookie.name, "HttpOnly flag is not set"]
        for cookie in collect_cookies(context)
        if not cookie.has("httponly")
    ]
    if not rows:
        return []
    return [
        Finding(
            test_id="cookie_httponly",
            title="Cookie without HttpOnly flag",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(columns=["URL", "Cookie", "Evidence"], rows=rows),
            risk_description=(
                "The risk is that a cookie without the HttpOnly flag is readable from "
                "JavaScript. If the application has a cross-site scripting flaw, the attacker "
                "can steal the cookie and hijack the user's session."
            ),
            recommendation=(
                "Set the HttpOnly flag on every cookie that does not need to be read by "
                "client-side scripts, in particular session cookies."
            ),
            references=[
                "https://owasp.org/www-community/HttpOnly",
            ],
            classification=Classification(
                cwe=["CWE-1004"],
                owasp_2017=["A6 - Security Misconfiguration"],
                owasp_2021=["A5 - Security Misconfiguration"],
                owasp_2025=["A02 - Security Misconfiguration"],
            ),
        )
    ]


@check("cookie_secure", "Scanned for Secure flag of cookie", order=61)
def cookie_secure(context: ScanContext) -> list[Finding]:
    if not context.is_https:
        return []
    rows = [
        [cookie.source_url, cookie.name, "Secure flag is not set"]
        for cookie in collect_cookies(context)
        if not cookie.has("secure")
    ]
    if not rows:
        return []
    return [
        Finding(
            test_id="cookie_secure",
            title="Cookie without Secure flag",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(columns=["URL", "Cookie", "Evidence"], rows=rows),
            risk_description=(
                "The risk is that a cookie without the Secure flag is also sent over plain "
                "HTTP requests, where an attacker on the network can read it."
            ),
            recommendation=(
                "Set the Secure flag on every cookie so browsers only transmit it over HTTPS."
            ),
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
            ],
            classification=misconfig("CWE-614"),
        )
    ]


@check("cookie_domain", "Scanned for domain too loose set for cookies", order=62)
def cookie_domain(context: ScanContext) -> list[Finding]:
    rows: list[list[str]] = []
    host = context.hostname
    for cookie in collect_cookies(context):
        domain = cookie.get("domain").lstrip(".")
        if not domain or domain == host:
            continue
        # A cookie scoped to a parent domain is shared with every sibling subdomain.
        if host.endswith("." + domain) and domain.count(".") >= 1:
            rows.append([
                cookie.source_url,
                cookie.name,
                f"Domain={cookie.get('domain')} — shared with all subdomains of {domain}",
            ])
    if not rows:
        return []
    return [
        Finding(
            test_id="cookie_domain",
            title="Cookie scoped too loosely",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(columns=["URL", "Cookie", "Evidence"], rows=rows),
            risk_description=(
                "The risk is that the cookie is sent to every subdomain of the parent domain. "
                "A vulnerability on any unrelated subdomain — including one operated by a "
                "third party — then exposes this application's cookies."
            ),
            recommendation=(
                "Remove the Domain attribute so the cookie is host-only, or scope it to the "
                "narrowest domain that actually needs it."
            ),
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
            ],
            classification=misconfig("CWE-565"),
        )
    ]
