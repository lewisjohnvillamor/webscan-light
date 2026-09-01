"""Sniper: run the whole suite against one target and aggregate the results.

This is a discovery-and-detection aggregator. Unlike the commercial
"auto-exploiter" it is modelled on, it never delivers exploit payloads, obtains
shells, or reads the target filesystem. It runs the recon and detection tools
and merges their findings and evidence into one report.
"""
from __future__ import annotations

from webscan.core.engine import ScanOptions, run_scan
from webscan.core.models import Finding, Severity, Table
from webscan.core.toolreport import Section, ToolReport

from . import ports as ports_tool
from . import recon as recon_tool
from . import ssl_scan
from . import subdomains as subdomains_tool
from . import takeover as takeover_tool
from .base import ToolOptions, tool
from .subdomains import _root_domain


@tool(id="sniper", name="Sniper: Recon Aggregator", category="Exploit", glyph="🎯", order=90,
      target_hint="URL or domain", active=True,
      description="Run recon, ports, SSL, the website scanner, subdomains and takeover, aggregated.")
def run(target: str, options: ToolOptions) -> ToolReport:
    domain = _root_domain(target)
    report = ToolReport(tool="sniper", tool_name="Sniper: Recon Aggregator", target=target)
    report.params = [("Target", target), ("Domain", domain)]

    stages: list[tuple[str, callable]] = [
        ("Website Recon", lambda: recon_tool.run(target, options)),
        ("SSL/TLS", lambda: ssl_scan.run(domain, options)),
        ("Port Scan", lambda: ports_tool.run(domain, options)),
        ("Subdomains", lambda: subdomains_tool.run(domain, options)),
        ("Subdomain Takeover", lambda: takeover_tool.run(domain, options)),
    ]

    summary_rows: list[list[str]] = []

    # Website vulnerability scan (its own engine) feeds findings + fingerprints.
    try:
        scan = run_scan(ScanOptions(target=target, offline=options.offline,
                                    verify_tls=options.verify_tls, timeout=options.timeout))
        for finding in scan.findings:
            report.findings.append(finding)
        counts = scan.rating_counts
        summary_rows.append(["Website Scanner", scan.status,
                             f"{len(scan.findings)} findings ({counts['High']}H/{counts['Low']}L/{counts['Info']}I)"])
    except Exception as exc:  # noqa: BLE001
        report.errors.append(f"Website scan failed: {type(exc).__name__}: {exc}")
        summary_rows.append(["Website Scanner", "Failed", str(exc)[:80]])

    for label, runner in stages:
        try:
            sub = runner()
            report.findings.extend(sub.findings)
            # Fold each tool's key section into the aggregate report.
            for section in sub.sections:
                if section.table and section.table.rows:
                    report.sections.append(Section(
                        title=f"{label}: {section.title}", intro=section.intro,
                        table=section.table))
                elif section.kv:
                    report.sections.append(Section(title=f"{label}: {section.title}", kv=section.kv))
            summary_rows.append([label, sub.status, f"{len(sub.findings)} findings"])
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"{label} failed: {type(exc).__name__}: {exc}")
            summary_rows.append([label, "Failed", str(exc)[:80]])

    # Aggregated summary at the top.
    report.sections.insert(0, Section(
        title="Modules run",
        intro="Sniper aggregates the recon and detection tools. It does not exploit, obtain "
              "shells, or access the target filesystem.",
        table=Table(columns=["Module", "Status", "Result"], rows=summary_rows),
    ))
    report.stats = [("Modules", str(len(summary_rows))), ("Total findings", str(len(report.findings)))]
    return report.finish()
