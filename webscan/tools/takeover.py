"""Subdomain takeover detector: dangling CNAMEs to unclaimed cloud resources."""
from __future__ import annotations

import concurrent.futures

import requests

from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.toolreport import Section, ToolReport

from .base import ToolOptions, tool
from .dnsutil import resolve
from .subdomains import _crtsh, _root_domain
from .wordlists import SUBDOMAINS, TAKEOVER_SIGNATURES, load_words


def _check(name: str, timeout: float) -> dict | None:
    cnames = resolve(name, "CNAME", timeout)
    if not cnames:
        return None
    cname = cnames[0].rstrip(".")
    for service, markers, fingerprints in TAKEOVER_SIGNATURES:
        if not any(marker in cname for marker in markers):
            continue
        a = resolve(name, "A", timeout)
        body = ""
        for scheme in ("https", "http"):
            try:
                resp = requests.get(f"{scheme}://{name}/", timeout=timeout,
                                    headers={"User-Agent": "webscan-light"}, allow_redirects=True)
                body = resp.text[:6000]
                break
            except requests.RequestException:
                continue
        vulnerable = any(fp.lower() in body.lower() for fp in fingerprints)
        # A CNAME to the service with no A record is itself a strong dangling signal.
        dangling = not a
        if vulnerable or dangling:
            return {
                "name": name, "cname": cname, "service": service,
                "evidence": "Unclaimed-resource fingerprint in response" if vulnerable
                            else "CNAME points to service but name does not resolve (dangling)",
                "confirmed": vulnerable,
            }
    return None


@tool(id="takeover", name="Subdomain Takeover", category="Vulnerability", glyph="🪝", order=45,
      target_hint="root domain (e.g. example.com)",
      description="Detect dangling CNAMEs pointing to unclaimed cloud resources (takeover risk).")
def run(target: str, options: ToolOptions) -> ToolReport:
    domain = _root_domain(target)
    report = ToolReport(tool="takeover", tool_name="Subdomain Takeover", target=domain)
    report.params = [("Root domain", domain)]

    candidates: set[str] = set()
    if not options.offline:
        candidates |= _crtsh(domain, options.timeout)
    for word in load_words(SUBDOMAINS, options.wordlist):
        candidates.add(f"{word}.{domain}")

    rows: list[list[str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(20, options.workers)) as pool:
        results = pool.map(lambda n: _check(n, options.timeout), sorted(candidates))
        for result in results:
            if not result:
                continue
            rows.append([result["name"], result["service"], result["cname"], result["evidence"]])
            report.findings.append(Finding(
                test_id="takeover", title=f"Potential subdomain takeover: {result['name']}",
                severity=Severity.HIGH if result["confirmed"] else Severity.MEDIUM,
                confidence=Confidence.CONFIRMED if result["confirmed"] else Confidence.UNCONFIRMED,
                table=Table(columns=["Subdomain", "Service", "CNAME", "Evidence"],
                            rows=[[result["name"], result["service"], result["cname"], result["evidence"]]]),
                risk_description=f"The subdomain points at {result['service']} but the resource "
                                 "appears unclaimed. An attacker who registers it there serves "
                                 "content from your domain — enabling phishing, cookie theft and "
                                 "OAuth-redirect abuse.",
                recommendation="Remove the dangling DNS record, or re-claim the resource on "
                               f"{result['service']} so it is under your control.",
                classification=Classification(cwe=["CWE-350"]),
            ))

    report.sections.append(Section(
        title="Takeover candidates",
        intro="No dangling records with a known takeover fingerprint were found." if not rows else "",
        table=Table(columns=["Subdomain", "Service", "CNAME", "Evidence"], rows=rows),
    ))
    report.stats = [("Names checked", str(len(candidates))), ("Candidates", str(len(rows)))]
    return report.finish()
