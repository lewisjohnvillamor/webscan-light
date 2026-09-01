"""Subdomain finder: certificate transparency (crt.sh) + DNS brute force."""
from __future__ import annotations

import concurrent.futures
import json
import re

import requests

from webscan.core.models import Confidence, Finding, Severity, Table
from webscan.core.toolreport import Section, ToolReport

from .base import ToolOptions, tool
from .dnsutil import resolve
from .wordlists import SUBDOMAINS, load_words

DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)


def _root_domain(target: str) -> str:
    host = target.strip().lower()
    host = re.sub(r"^https?://", "", host).split("/")[0].split(":")[0]
    return host


def _crtsh(domain: str, timeout: float) -> set[str]:
    found: set[str] = set()
    try:
        response = requests.get(  # nosec B113: timeout set on the next line
            "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
            timeout=max(timeout, 20), headers={"User-Agent": "webscan-light"},
        )
        if response.status_code == 200:
            for entry in response.json():
                for name in str(entry.get("name_value", "")).splitlines():
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(domain) and DOMAIN_RE.match(name):
                        found.add(name)
    except (requests.RequestException, json.JSONDecodeError):
        pass
    return found


@tool(id="subdomains", name="Subdomain Finder", category="Recon", glyph="🌐", order=40,
      target_hint="root domain (e.g. example.com)",
      description="Discover subdomains via certificate transparency logs and DNS brute force.")
def run(target: str, options: ToolOptions) -> ToolReport:
    domain = _root_domain(target)
    report = ToolReport(tool="subdomains", tool_name="Subdomain Finder", target=domain)
    report.params = [("Root domain", domain)]

    candidates: set[str] = set()
    sources: dict[str, str] = {}

    if not options.offline:
        for name in _crtsh(domain, options.timeout):
            candidates.add(name)
            sources[name] = "crt.sh"

    words = load_words(SUBDOMAINS, options.wordlist)
    for word in words:
        candidates.add(f"{word}.{domain}")

    resolved_rows: list[list[str]] = []
    live = 0

    def check(name: str) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
        return name, resolve(name, "A", options.timeout), resolve(name, "CNAME", options.timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(20, options.workers)) as pool:
        for name, a, cname in pool.map(check, sorted(candidates)):
            if a or cname:
                live += 1
                resolved_rows.append([
                    name,
                    ", ".join(a[:3]) or "-",
                    (cname[0] if cname else "-"),
                    sources.get(name, "brute force" if name.split(".", 1)[0] in words else "crt.sh"),
                ])

    resolved_rows.sort(key=lambda r: r[0])
    report.sections.append(Section(
        title=f"Live subdomains ({live})",
        intro="Only names that resolve are listed." if live else "No subdomains resolved.",
        table=Table(columns=["Subdomain", "A record(s)", "CNAME", "Source"], rows=resolved_rows),
    ))
    report.stats = [("Candidates tested", str(len(candidates))), ("Live", str(live))]

    if live:
        report.findings.append(Finding(
            test_id="subdomains_found", title=f"{live} subdomains discovered",
            severity=Severity.INFO, confidence=Confidence.CONFIRMED,
            table=Table(columns=["Subdomain", "A record(s)"], rows=[[r[0], r[1]] for r in resolved_rows[:30]]),
            risk_description="Each subdomain widens the attack surface. Forgotten or staging "
                             "hosts often run outdated software or expose internal tooling.",
            recommendation="Review the list for hosts that should not be public, decommission "
                           "unused DNS records, and bring every live host into your scanning scope.",
        ))
    return report.finish()
