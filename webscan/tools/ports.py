"""TCP port scanner (connect scan) with lightweight service fingerprinting."""
from __future__ import annotations

import concurrent.futures
import socket
import ssl
from urllib.parse import urlparse

from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.toolreport import Section, ToolReport

from .base import ToolOptions, tool
from .dnsutil import resolve

TOP_100 = [
    7, 20, 21, 22, 23, 25, 53, 69, 80, 110, 111, 123, 135, 137, 138, 139, 143, 161,
    389, 443, 445, 465, 500, 512, 513, 514, 515, 543, 544, 548, 554, 587, 631, 636,
    993, 995, 1080, 1433, 1434, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
    2181, 2222, 2375, 2376, 3000, 3128, 3306, 3389, 3690, 4443, 4444, 5000, 5432,
    5433, 5601, 5672, 5900, 5984, 6379, 6443, 7001, 7002, 8000, 8008, 8009, 8080,
    8081, 8088, 8180, 8443, 8888, 9000, 9042, 9092, 9200, 9300, 9418, 9999, 10000,
    11211, 15672, 27017, 27018, 50000,
]
SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 465: "smtps", 587: "smtp",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
    2375: "docker", 5601: "kibana", 15672: "rabbitmq-mgmt", 9092: "kafka", 7001: "weblogic",
}
RISKY_EXPOSED = {
    3306: ("MySQL", Severity.MEDIUM), 5432: ("PostgreSQL", Severity.MEDIUM),
    6379: ("Redis", Severity.HIGH), 27017: ("MongoDB", Severity.HIGH),
    9200: ("Elasticsearch", Severity.HIGH), 11211: ("Memcached", Severity.HIGH),
    2375: ("Docker API", Severity.HIGH), 1433: ("MSSQL", Severity.MEDIUM),
    3389: ("RDP", Severity.MEDIUM), 23: ("Telnet", Severity.HIGH),
    5900: ("VNC", Severity.MEDIUM), 15672: ("RabbitMQ management", Severity.MEDIUM),
    9042: ("Cassandra", Severity.MEDIUM), 1521: ("Oracle DB", Severity.MEDIUM),
}


def parse_ports(spec: str) -> list[int]:
    spec = (spec or "").strip().lower()
    if not spec or spec == "top100":
        return TOP_100
    if spec == "top1000":
        return sorted(set(TOP_100) | set(range(1, 1001)))
    if spec == "all":
        return list(range(1, 65536))
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, _, b = part.partition("-")
            if a.isdigit() and b.isdigit():
                ports.update(range(int(a), min(int(b), 65535) + 1))
        elif part.isdigit():
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def _grab_banner(host: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in (443, 8443, 993, 995, 465, 4443):
                try:
                    ctx = ssl._create_unverified_context()
                    with ctx.wrap_socket(sock, server_hostname=host) as tls:
                        return f"TLS {tls.version()}"
                except (ssl.SSLError, OSError):
                    return ""
            try:
                data = sock.recv(160)
                return data.decode("latin-1", "replace").strip().split("\n")[0][:120]
            except OSError:
                if port in (80, 8080, 8000):
                    try:
                        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        data = sock.recv(200)
                        for line in data.decode("latin-1", "replace").splitlines():
                            if line.lower().startswith("server:"):
                                return line.strip()
                        return data.decode("latin-1", "replace").splitlines()[0][:120] if data else ""
                    except OSError:
                        return ""
                return ""
    except OSError:
        return ""


def _scan_port(host: str, port: int, timeout: float) -> tuple[int, bool]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, True
    except OSError:
        return port, False


@tool(id="ports", name="Port Scanner", category="Recon", glyph="📡", order=30,
      target_hint="hostname or IP", active=True,
      description="TCP connect scan for open ports, with service and banner fingerprinting.")
def run(target: str, options: ToolOptions) -> ToolReport:
    host = urlparse(target if "://" in target else "//" + target, scheme="").hostname or target.strip()
    report = ToolReport(tool="ports", tool_name="Port Scanner", target=host)
    ports = parse_ports(options.ports)
    report.params = [("Host", host), ("Ports scanned", str(len(ports)))]

    addrs = resolve(host, "A", options.timeout)
    if addrs:
        report.params.append(("Resolved IP", ", ".join(addrs[:3])))

    open_ports: list[int] = []
    timeout = min(options.timeout, 4.0)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(20, options.workers)) as pool:
        futures = [pool.submit(_scan_port, host, p, timeout) for p in ports]
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
    open_ports.sort()

    rows = []
    for port in open_ports:
        service = SERVICE_NAMES.get(port, "unknown")
        banner = _grab_banner(host, port, timeout)
        rows.append([str(port), "tcp", service, banner or "-"])
    report.sections.append(Section(
        title=f"Open ports ({len(open_ports)})",
        intro="No open ports were found in the scanned range." if not open_ports else "",
        table=Table(columns=["Port", "Proto", "Service", "Banner / fingerprint"], rows=rows),
    ))
    report.stats = [("Ports scanned", str(len(ports))), ("Open", str(len(open_ports)))]

    for port in open_ports:
        if port in RISKY_EXPOSED:
            name, severity = RISKY_EXPOSED[port]
            report.findings.append(Finding(
                test_id=f"port_{port}", title=f"Sensitive service exposed: {name} (port {port})",
                severity=severity, confidence=Confidence.CONFIRMED, port=f"{port}/tcp",
                table=Table(columns=["Port", "Service"], rows=[[str(port), name]]),
                risk_description=f"{name} is reachable from the scanning host. Datastores and "
                                 "admin services exposed to untrusted networks are frequently "
                                 "unauthenticated or weakly authenticated and lead to full compromise.",
                recommendation=f"Bind {name} to localhost or a private network, enforce "
                               "authentication, and firewall the port from the public internet.",
                classification=Classification(cwe=["CWE-668"]),
            ))
    return report.finish()
