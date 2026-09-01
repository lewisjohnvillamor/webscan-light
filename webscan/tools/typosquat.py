"""Typosquat / look-alike domain monitor (brand protection)."""
from __future__ import annotations

import concurrent.futures

import requests

from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.toolreport import Section, ToolReport

from .base import ToolOptions, tool
from .dnsutil import resolve
from .subdomains import _root_domain

KEYBOARD = {"a": "qsz", "b": "vgn", "c": "xdv", "d": "sfe", "e": "wrd", "g": "fht",
            "i": "uok", "l": "kop", "m": "n", "n": "bm", "o": "ipl", "r": "et",
            "s": "adz", "t": "ry", "u": "yi", "0": "o", "1": "l", "o0": "0"}
COMMON_TLDS = ["com", "net", "org", "co", "io", "info", "app", "online", "site", "xyz"]
HOMOGLYPHS = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5"}


def _variants(name: str, tld: str) -> set[str]:
    out: set[str] = set()
    # omission
    for i in range(len(name)):
        out.add(name[:i] + name[i + 1:])
    # transposition
    for i in range(len(name) - 1):
        out.add(name[:i] + name[i + 1] + name[i] + name[i + 2:])
    # adjacent-key substitution
    for i, ch in enumerate(name):
        for repl in KEYBOARD.get(ch, ""):
            out.add(name[:i] + repl + name[i + 1:])
    # duplication
    for i, ch in enumerate(name):
        out.add(name[:i] + ch + name[i:])
    # homoglyph
    for i, ch in enumerate(name):
        if ch in HOMOGLYPHS:
            out.add(name[:i] + HOMOGLYPHS[ch] + name[i + 1:])
    # hyphen insertion
    for i in range(1, len(name)):
        out.add(name[:i] + "-" + name[i:])
    out.discard(name)
    out.discard("")
    domains = {f"{v}.{tld}" for v in out if len(v) > 1}
    # TLD swap of the original name
    domains |= {f"{name}.{t}" for t in COMMON_TLDS if t != tld}
    return domains


@tool(id="typosquat", name="Typosquat Monitor", category="Recon", glyph="🪪", order=46,
      target_hint="domain (e.g. example.com)",
      description="Generate look-alike domains and flag ones that are registered and live.")
def run(target: str, options: ToolOptions) -> ToolReport:
    domain = _root_domain(target)
    if "." not in domain:
        report = ToolReport(tool="typosquat", tool_name="Typosquat Monitor", target=domain)
        report.errors.append("Provide a full domain, e.g. example.com")
        return report.finish("Failed")
    name, _, tld = domain.partition(".")
    report = ToolReport(tool="typosquat", tool_name="Typosquat Monitor", target=domain)
    report.params = [("Domain", domain)]

    candidates = sorted(_variants(name, tld))
    if options.max_items:
        candidates = candidates[: options.max_items]

    rows: list[list[str]] = []

    def check(cand: str):
        a = resolve(cand, "A", options.timeout)
        if not a:
            return None
        title = ""
        if not options.offline:
            for scheme in ("https", "http"):
                try:
                    resp = requests.get(f"{scheme}://{cand}/", timeout=min(options.timeout, 6),
                                        headers={"User-Agent": "webscan-light"}, allow_redirects=True)
                    import re as _re
                    m = _re.search(r"<title[^>]*>(.*?)</title>", resp.text, _re.I | _re.S)
                    title = (m.group(1).strip()[:60] if m else f"HTTP {resp.status_code}")
                    break
                except requests.RequestException:
                    continue
        return [cand, ", ".join(a[:2]), title or "resolves"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(20, options.workers)) as pool:
        for result in pool.map(check, candidates):
            if result:
                rows.append(result)

    rows.sort(key=lambda r: r[0])
    if rows:
        report.findings.append(Finding(
            test_id="typosquat", title=f"{len(rows)} look-alike domains are registered and live",
            severity=Severity.LOW, confidence=Confidence.UNCONFIRMED,
            table=Table(["Look-alike domain", "Resolves to", "Site title"], rows[:60]),
            risk_description="Registered look-alike domains are commonly used for phishing, "
                             "brand impersonation and email spoofing against your users.",
            recommendation="Review each domain; report or take down malicious ones, and consider "
                           "defensively registering the closest variants.",
            classification=Classification(cwe=["CWE-1021"],
                                          owasp_2021=["A4 - Insecure Design"],
                                          owasp_2017=["A6 - Security Misconfiguration"],
                                          owasp_2025=["A06 - Insecure Design"])))
    report.sections.append(Section(
        title=f"Live look-alike domains ({len(rows)})",
        intro="No generated look-alike domains resolve." if not rows else
              "These generated variants resolve to an IP (they may or may not be malicious).",
        table=Table(["Domain", "Resolves to", "Title"], rows)))
    report.stats = [("Variants generated", str(len(candidates))), ("Live", str(len(rows)))]
    return report.finish()
