"""Virtual host finder: which hostnames a single IP serves via the Host header."""
from __future__ import annotations

import concurrent.futures

import requests
import urllib3

from webscan.core.models import Confidence, Finding, Severity, Table
from webscan.core.toolreport import Section, ToolReport

from .base import ToolOptions, tool
from .dnsutil import resolve
from .subdomains import _crtsh, _root_domain
from .wordlists import SUBDOMAINS, load_words

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _fetch(ip: str, host: str, scheme: str, timeout: float) -> tuple[int, int] | None:
    try:
        resp = requests.get(f"{scheme}://{ip}/", headers={"Host": host, "User-Agent": "webscan-light"},
                            timeout=timeout, verify=False, allow_redirects=False)  # nosec B501: vhost probe by IP; cert cannot match the tested Host
        return resp.status_code, len(resp.content)
    except requests.RequestException:
        return None


@tool(id="vhosts", name="Virtual Host Finder", category="Recon", glyph="🎭", order=42,
      target_hint="domain or IP", active=True,
      description="Find name-based virtual hosts served by the target IP via Host-header probing.")
def run(target: str, options: ToolOptions) -> ToolReport:
    domain = _root_domain(target)
    report = ToolReport(tool="vhosts", tool_name="Virtual Host Finder", target=domain)

    ips = resolve(domain, "A", options.timeout)
    if not ips:
        report.errors.append(f"Could not resolve {domain} to an IP.")
        return report.finish("Failed")
    ip = ips[0]
    scheme = "https"
    report.params = [("Domain", domain), ("IP", ip)]

    candidates: set[str] = {domain}
    if not options.offline:
        candidates |= _crtsh(domain, options.timeout)
    for word in load_words(SUBDOMAINS, options.wordlist):
        candidates.add(f"{word}.{domain}")

    baseline = _fetch(ip, f"webscan-nonexistent-{abs(hash(domain)) % 9999}.{domain}", scheme, options.timeout)
    base_sig = baseline if baseline else (0, 0)

    rows: list[list[str]] = []

    def probe(host: str):
        result = _fetch(ip, host, scheme, options.timeout)
        if not result:
            return None
        code, size = result
        # A response that differs from the catch-all baseline indicates a distinct vhost.
        if (code, size) != base_sig and code not in (400, 421):
            distinct = abs(size - base_sig[1]) > 48 or code != base_sig[0]
            if distinct:
                return [host, str(code), str(size)]
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(15, options.workers)) as pool:
        for result in pool.map(probe, sorted(candidates)):
            if result:
                rows.append(result)

    rows.sort(key=lambda r: r[0])
    report.sections.append(Section(
        title=f"Virtual hosts on {ip} ({len(rows)})",
        intro="Only the default host appears to be served." if not rows else
              "These hostnames return a distinct response from this IP.",
        table=Table(columns=["Host header", "Status", "Response size"], rows=rows),
    ))
    report.stats = [("IP", ip), ("Names tested", str(len(candidates))), ("Distinct vhosts", str(len(rows)))]
    if len(rows) > 1:
        report.findings.append(Finding(
            test_id="vhosts", title=f"{len(rows)} virtual hosts share IP {ip}",
            severity=Severity.INFO, confidence=Confidence.CONFIRMED,
            table=Table(columns=["Host header", "Status"], rows=[[r[0], r[1]] for r in rows[:30]]),
            risk_description="Co-hosted sites share an IP and often a web server. A weakness in "
                             "one virtual host can expose the others.",
            recommendation="Ensure each virtual host is patched and isolated; do not assume an "
                           "internal-only vhost is unreachable just because it is not in DNS.",
        ))
    return report.finish()
