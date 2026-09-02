"""Website recon: DNS, WHOIS/RDAP, HTTP headers and technology at a glance."""
from __future__ import annotations

import json

import requests

from webscan.core.http import HttpClient, normalize_target
from webscan.core.models import Table
from webscan.core.toolreport import Section, ToolReport

from .base import ToolOptions, tool
from .dnsutil import resolve
from .subdomains import _root_domain


def _rdap(domain: str, timeout: float) -> list[tuple[str, str]]:
    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=timeout,
                            headers={"User-Agent": "webscan-light"})
        if resp.status_code != 200:
            return []
        data = resp.json()
        events = {e.get("eventAction"): e.get("eventDate", "")[:10] for e in data.get("events", [])}
        registrar = ""
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                for item in entity.get("vcardArray", [[], []])[1]:
                    if item[0] == "fn":
                        registrar = item[3]
        rows = [("Registrar", registrar or "-"),
                ("Registered", events.get("registration", "-")),
                ("Last changed", events.get("last changed", "-")),
                ("Expires", events.get("expiration", "-")),
                ("Status", ", ".join(data.get("status", [])) or "-"),
                ("Nameservers", ", ".join(ns.get("ldhName", "") for ns in data.get("nameservers", [])) or "-")]
        return rows
    except (requests.RequestException, json.JSONDecodeError, KeyError, IndexError):
        return []


@tool(id="recon", name="Website Recon", category="Recon", glyph="🔎", order=10,
      target_hint="URL or domain",
      description="A one-page profile: DNS records, WHOIS/RDAP, HTTP headers and server tech.")
def run(target: str, options: ToolOptions) -> ToolReport:
    url = normalize_target(target)
    domain = _root_domain(target)
    report = ToolReport(tool="recon", tool_name="Website Recon", target=url)
    report.params = [("Target", url), ("Domain", domain)]

    dns_rows = []
    for rtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"):
        values = resolve(domain, rtype, options.timeout)
        if values:
            dns_rows.append([rtype, "\n".join(values[:8])])
    report.sections.append(Section(title="DNS records",
                                   table=Table(columns=["Type", "Value"], rows=dns_rows)))

    if not options.offline:
        rdap_rows = _rdap(domain, options.timeout)
        if rdap_rows:
            report.sections.append(Section(title="Domain registration (RDAP)", kv=rdap_rows))

    client = HttpClient(timeout=options.timeout, verify_tls=options.verify_tls, delay=options.delay,
                        extra_headers={"Cookie": options.cookie} if options.cookie else None)
    resp = client.get(url)
    if resp.ok:
        interesting = ["Server", "X-Powered-By", "Via", "X-AspNet-Version", "Content-Type",
                       "Strict-Transport-Security", "Content-Security-Policy", "Set-Cookie",
                       "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy",
                       "Cache-Control", "CF-Ray", "X-Vercel-Id", "X-Amz-Cf-Id"]
        header_rows = [[h, resp.header(h)] for h in interesting if resp.header(h)]
        report.sections.append(Section(title="HTTP response headers",
                                       intro=f"HTTP {resp.status_code} from {resp.url}",
                                       table=Table(columns=["Header", "Value"], rows=header_rows)))
        report.params.append(("Status code", str(resp.status_code)))
    else:
        report.errors.append(f"Could not fetch {url}: {resp.error}")

    report.stats = [("DNS record types", str(len(dns_rows))), ("HTTP requests", str(client.request_count))]
    return report.finish()
