"""Google Hacking (Dorks): generate ready-to-run advanced-search queries."""
from __future__ import annotations

from urllib.parse import quote_plus

from webscan.core.models import Confidence, Finding, Severity, Table
from webscan.core.toolreport import Section, ToolReport

from .base import ToolOptions, tool
from .subdomains import _root_domain

CATEGORIES = {
    "Exposed files & directories": [
        ('site:{d} intitle:"index of"', "Open directory listings"),
        ('site:{d} ext:sql | ext:dbf | ext:mdb', "Database dumps"),
        ('site:{d} ext:log', "Log files"),
        ('site:{d} ext:bak | ext:old | ext:backup | ext:swp', "Backup files"),
        ('site:{d} ext:env | ext:ini | ext:conf | ext:cfg', "Config files"),
        ('site:{d} intitle:"index of" (wp-config | .env | config.php)', "Sensitive config in listings"),
    ],
    "Login & admin interfaces": [
        ('site:{d} inurl:login | inurl:signin | inurl:admin', "Login/admin pages"),
        ('site:{d} intitle:"admin" | intitle:"dashboard"', "Admin dashboards"),
        ('site:{d} inurl:wp-admin | inurl:wp-login', "WordPress admin"),
    ],
    "Sensitive information": [
        ('site:{d} ext:txt intext:password | intext:passwd', "Password references"),
        ('site:{d} "api_key" | "apikey" | "client_secret"', "API keys / secrets"),
        ('site:{d} filetype:xls | filetype:xlsx | filetype:csv intext:email', "Spreadsheets with emails"),
        ('site:{d} intext:"BEGIN RSA PRIVATE KEY"', "Private keys"),
    ],
    "Application internals": [
        ('site:{d} inurl:phpinfo | intitle:"phpinfo()"', "phpinfo pages"),
        ('site:{d} intext:"sql syntax near" | intext:"Warning: mysql_"', "SQL error messages"),
        ('site:{d} inurl:"error" | intitle:"exception"', "Error/exception pages"),
        ('site:{d} inurl:api | inurl:swagger | inurl:graphql', "API surface"),
    ],
    "Third-party & cloud exposure": [
        ('site:pastebin.com "{d}"', "Leaks on Pastebin"),
        ('site:github.com "{d}"', "Code mentions on GitHub"),
        ('site:s3.amazonaws.com "{d}"', "S3 buckets"),
        ('"{d}" (password | secret | token) site:trello.com', "Trello board leaks"),
    ],
}


@tool(id="dorks", name="Google Hacking", category="Recon", glyph="🔦", order=50,
      target_hint="domain (e.g. example.com)",
      description="Generate advanced-search operators (Google Dorks) to surface exposed data.")
def run(target: str, options: ToolOptions) -> ToolReport:
    domain = _root_domain(target)
    report = ToolReport(tool="dorks", tool_name="Google Hacking", target=domain)
    report.params = [("Domain", domain)]
    total = 0
    for category, queries in CATEGORIES.items():
        rows = []
        for template, purpose in queries:
            query = template.format(d=domain)
            url = f"https://www.google.com/search?q={quote_plus(query)}"
            rows.append([query, purpose, url])
            total += 1
        report.sections.append(Section(
            title=category,
            table=Table(columns=["Dork query", "Finds", "Run on Google"], rows=rows),
        ))
    report.stats = [("Dork queries", str(total)), ("Categories", str(len(CATEGORIES)))]
    report.findings.append(Finding(
        test_id="dorks", title=f"{total} Google dork queries generated for {domain}",
        severity=Severity.INFO, confidence=Confidence.UNCONFIRMED,
        risk_description="Search engines index content that was never meant to be public. "
                         "Running these operators reveals what an attacker can find about you "
                         "with no direct interaction with your servers.",
        recommendation="Run each query, remove or protect anything sensitive that appears, and "
                       "use robots.txt plus authentication rather than obscurity for private data.",
    ))
    return report.finish()
