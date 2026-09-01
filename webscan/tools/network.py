"""Network scanner: host discovery across a CIDR/range, then a port sweep."""
from __future__ import annotations

import concurrent.futures
import ipaddress
import socket

from webscan.core.models import Confidence, Finding, Table
from webscan.core.toolreport import Section, ToolReport

from .base import ToolOptions, tool
from .ports import RISKY_EXPOSED, SERVICE_NAMES, parse_ports

DISCOVERY_PORTS = [80, 443, 22, 3389, 445, 8080, 21, 25, 3306]


def _hosts(target: str, limit: int) -> list[str]:
    target = target.strip()
    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            return [str(h) for h in list(net.hosts())[:limit]]
        if "-" in target and target.count(".") == 3:
            base, _, end = target.rpartition(".")
            lo, _, hi = end.partition("-")
            return [f"{base}.{i}" for i in range(int(lo), int(hi) + 1)][:limit]
        return [str(ipaddress.ip_address(target))]
    except ValueError:
        try:
            return [socket.gethostbyname(target)]
        except OSError:
            return []


def _alive(host: str, timeout: float) -> tuple[str, list[int]]:
    found = []
    for port in DISCOVERY_PORTS:
        try:
            with socket.create_connection((host, port), timeout=min(timeout, 2.0)):
                found.append(port)
        except OSError:
            continue
    return host, found


@tool(id="network", name="Network Scanner", category="Recon", glyph="🖧", order=35,
      target_hint="IP, hostname, CIDR (10.0.0.0/24) or range (10.0.0.1-50)", active=True,
      description="Discover live hosts across a network range and sweep their common ports.")
def run(target: str, options: ToolOptions) -> ToolReport:
    report = ToolReport(tool="network", tool_name="Network Scanner", target=target)
    limit = options.max_items or 256
    hosts = _hosts(target, limit)
    if not hosts:
        report.errors.append(f"Could not interpret '{target}' as an IP, host, CIDR or range.")
        return report.finish("Failed")
    report.params = [("Target", target), ("Hosts in scope", str(len(hosts)))]

    ports = parse_ports(options.ports) if options.ports else DISCOVERY_PORTS
    timeout = min(options.timeout, 3.0)

    alive: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(30, options.workers)) as pool:
        for host, found in pool.map(lambda h: _alive(h, timeout), hosts):
            if found:
                alive.append(host)

    rows: list[list[str]] = []

    def sweep(host: str):
        host_rows = []
        for port in ports:
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    host_rows.append([host, str(port), SERVICE_NAMES.get(port, "unknown")])
            except OSError:
                continue
        return host_rows

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(20, options.workers)) as pool:
        for host_rows in pool.map(sweep, alive):
            rows.extend(host_rows)
            for _, port_str, _service in host_rows:
                port = int(port_str)
                if port in RISKY_EXPOSED:
                    name, severity = RISKY_EXPOSED[port]
                    report.findings.append(Finding(
                        test_id=f"net_{host_rows[0][0]}_{port}",
                        title=f"{name} exposed on {host_rows[0][0]}:{port}",
                        severity=severity, confidence=Confidence.CONFIRMED, port=f"{port}/tcp",
                        table=Table(columns=["Host", "Port", "Service"], rows=[[host_rows[0][0], port_str, name]]),
                        risk_description=f"{name} is reachable on the network. Exposed datastores "
                                         "and admin services are a common pivot to full compromise.",
                        recommendation="Firewall the port to trusted sources and require authentication.",
                    ))

    report.sections.append(Section(
        title=f"Live hosts ({len(alive)})",
        intro="No live hosts responded on the discovery ports." if not alive else "",
        table=Table(columns=["Host", "Port", "Service"], rows=rows),
    ))
    report.stats = [("Hosts scanned", str(len(hosts))), ("Live hosts", str(len(alive))),
                    ("Open ports", str(len(rows)))]
    return report.finish()
