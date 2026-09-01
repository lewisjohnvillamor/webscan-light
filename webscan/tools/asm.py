"""Attack Surface Monitoring: inventory a domain's exposure in one report.

Composes subdomain discovery, per-host ports, TLS, DNS/email posture and
takeover checks into an asset inventory. Every asset is emitted as an INFO
finding, so when this tool is scheduled the existing new-finding diff alerts on
*changes* — a new subdomain, a newly opened port, a new CVE — for free.
"""
from __future__ import annotations

from webscan.core.models import Confidence, Finding, Severity, Table
from webscan.core.toolreport import Section, ToolReport

from . import dns_email, ports as ports_tool, ssl_scan, subdomains as subdomains_tool, takeover
from .base import ToolOptions, tool
from .subdomains import _root_domain


@tool(id="asm", name="Attack Surface Monitor", category="Recon", glyph="🛰", order=5,
      target_hint="root domain (e.g. example.com)",
      description="Inventory subdomains, open ports, TLS and DNS posture; schedule it to get "
                  "alerts when your exposure changes.")
def run(target: str, options: ToolOptions) -> ToolReport:
    domain = _root_domain(target)
    report = ToolReport(tool="asm", tool_name="Attack Surface Monitor", target=domain)
    report.params = [("Domain", domain)]
    module_rows: list[list[str]] = []

    def _stage(label, fn):
        try:
            sub = fn()
            report.findings.extend(sub.findings)
            module_rows.append([label, sub.status, f"{len(sub.findings)} findings"])
            return sub
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"{label} failed: {type(exc).__name__}: {exc}")
            module_rows.append([label, "Failed", str(exc)[:60]])
            return None

    # 1) Subdomains -> the asset list.
    subs = _stage("Subdomains", lambda: subdomains_tool.run(domain, options))
    asset_rows: list[list[str]] = []
    hostnames = [domain]
    if subs and subs.sections and subs.sections[0].table:
        for row in subs.sections[0].table.rows:
            host, a_records = row[0], row[1]
            asset_rows.append([host, a_records])
            hostnames.append(host)
    hostnames = list(dict.fromkeys(hostnames))

    # Each live host is an asset -> INFO finding (drives change alerts).
    for host, *_ in asset_rows or [[domain, ""]]:
        report.findings.append(Finding(
            test_id=f"asset_{host}", title=f"Asset: {host}", severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            table=Table(["Host"], [[host]]),
            risk_description="A live host in your attack surface. Tracked so a newly appearing "
                             "host raises an alert when this monitor is scheduled.",
            recommendation="Confirm this host should be public and is in your scanning scope."))

    # 2) DNS/email posture + TLS + takeover for the apex.
    _stage("DNS & Email", lambda: dns_email.run(domain, options))
    _stage("SSL/TLS", lambda: ssl_scan.run(domain, options))
    _stage("Takeover", lambda: takeover.run(domain, options))

    # 3) Ports for the apex host (and a few subdomains, bounded).
    port_rows: list[list[str]] = []
    scan_hosts = hostnames[: (options.max_items or 5)]
    for host in scan_hosts:
        result = _stage(f"Ports: {host}", lambda h=host: ports_tool.run(h, options))
        if result and result.sections and result.sections[0].table:
            for row in result.sections[0].table.rows:
                port_rows.append([host, row[0], row[2]])
                report.findings.append(Finding(
                    test_id=f"port_{host}_{row[0]}", title=f"Open port: {host}:{row[0]} ({row[2]})",
                    severity=Severity.INFO, confidence=Confidence.CONFIRMED, port=f"{row[0]}/tcp",
                    table=Table(["Host", "Port", "Service"], [[host, row[0], row[2]]]),
                    risk_description="An open port in your attack surface, tracked for change "
                                     "detection.",
                    recommendation="Confirm this service should be exposed."))

    report.sections.append(Section(
        title="Modules", intro="Attack-surface inventory. Schedule this tool to be alerted when "
                               "your exposure changes (new host, new port, new finding).",
        table=Table(["Module", "Status", "Result"], module_rows)))
    report.sections.append(Section(
        title=f"Hosts ({len(asset_rows)})",
        table=Table(["Host", "A record(s)"], asset_rows or [[domain, "-"]])))
    if port_rows:
        report.sections.append(Section(
            title=f"Open ports ({len(port_rows)})",
            table=Table(["Host", "Port", "Service"], port_rows)))
    report.stats = [("Hosts", str(len(hostnames))), ("Open ports", str(len(port_rows))),
                    ("Total findings", str(len(report.findings)))]
    return report.finish()
