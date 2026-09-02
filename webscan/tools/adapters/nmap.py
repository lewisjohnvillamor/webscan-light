"""nmap adapter - optional deep port/service scanning.

Our native port scanner is a fast TCP-connect probe. When the `nmap` binary is
present this adapter offers nmap's service/version detection (`-sV`) instead,
parsing its XML output into the same report model. nmap's own licence (NPSL)
restricts redistribution, so we only ever *call* an already-installed nmap - it
is never bundled.

Active/intrusive, so gated behind --authorized. Falls back to install guidance
when nmap is absent.
"""
from __future__ import annotations

import shutil
import subprocess  # nosec B404: fixed argv list, no shell
import xml.etree.ElementTree as ET  # nosec B405: parsing our own subprocess output
from urllib.parse import urlparse

from webscan.core.models import Classification, Confidence, Finding, Table
from webscan.core.toolreport import Section, ToolReport

from ..base import ToolOptions, tool
from ..ports import RISKY_EXPOSED, parse_ports

BINARY = "nmap"
INSTALL_HINT = (
    "nmap is not installed on this host. Install it from your package manager "
    "(`apt install nmap`, `brew install nmap`) or use the `webscan-light:full` "
    "Docker image to enable this tool.")


def path() -> str | None:
    return shutil.which(BINARY)


def version() -> str:
    binary = path()
    if not binary:
        return ""
    try:
        out = subprocess.run(  # nosec B603: fixed argv, no shell
            [binary, "--version"], capture_output=True, text=True, timeout=10)
    except (subprocess.TimeoutExpired, OSError):
        return ""
    return (out.stdout or "").splitlines()[0].strip() if out.stdout else ""


def _host(target: str) -> str:
    if "://" in target:
        return urlparse(target).hostname or target.strip()
    return target.strip().split("/")[0].split(":")[0]


@tool(id="nmapscan", name="Nmap (service scan)", category="Recon", glyph="NMP",
      order=31, target_hint="hostname or IP", active=True,
      description="Deep port and service/version detection via the external nmap engine "
                  "(optional; results folded into the report).")
def run(target: str, options: ToolOptions) -> ToolReport:
    host = _host(target)
    report = ToolReport(tool="nmapscan", tool_name="Nmap (service scan)", target=host)

    binary = path()
    if not binary:
        report.params = [("Host", host), ("Engine", "nmap (not installed)")]
        report.sections.append(Section(title="nmap not available", intro=INSTALL_HINT))
        report.errors.append(INSTALL_HINT)
        return report.finish("Skipped")

    if not options.authorized:
        report.params = [("Host", host), ("Engine", version() or "nmap")]
        report.errors.append(
            "nmap is active/intrusive. Re-run with --authorized (CLI) or tick the "
            "authorization box (UI) to confirm you are permitted to scan this host.")
        return report.finish("Blocked")

    if host.startswith("-"):
        report.errors.append("Refusing an unsafe target that begins with '-'.")
        return report.finish("Blocked")

    ports = parse_ports(options.ports)
    port_spec = ",".join(str(p) for p in ports) if len(ports) <= 1200 else "1-65535"
    budget = 600.0

    command = [
        binary, "-Pn", "-sV", "--version-light", "-T4", "-oX", "-",
        "--host-timeout", "300s", "-p", port_spec, host,
    ]
    report.params = [
        ("Host", host), ("Engine", version() or "nmap"),
        ("Ports", str(len(ports))), ("Detection", "-sV --version-light"),
    ]

    try:
        result = subprocess.run(  # nosec B603: fixed argv, no shell
            command, capture_output=True, text=True, timeout=budget)
    except subprocess.TimeoutExpired:
        report.errors.append(f"nmap hit the {int(budget)}s time budget.")
        return report.finish("Error")
    except OSError as exc:
        report.errors.append(f"Could not run nmap: {exc}")
        return report.finish("Error")

    if not (result.stdout or "").strip().startswith("<?xml"):
        report.errors.append((result.stderr or "nmap produced no XML output").strip()[:200])
        return report.finish("Error")

    rows, open_ports = _parse(result.stdout)
    report.sections.append(Section(
        title=f"Open ports ({len(rows)})",
        intro="No open ports were found." if not rows else "",
        table=Table(columns=["Port", "Proto", "State", "Service", "Product / version"], rows=rows),
    ))
    report.stats = [("Ports scanned", str(len(ports))), ("Open", str(len(rows)))]

    for port in open_ports:
        if port in RISKY_EXPOSED:
            name, severity = RISKY_EXPOSED[port]
            report.findings.append(Finding(
                test_id=f"nmap_port_{port}",
                title=f"Sensitive service exposed: {name} (port {port})",
                severity=severity, confidence=Confidence.CONFIRMED, port=f"{port}/tcp",
                table=Table(columns=["Port", "Service"], rows=[[str(port), name]]),
                risk_description=f"{name} is reachable on port {port}. Datastores and admin "
                                 "services exposed to untrusted networks are a frequent entry point.",
                recommendation=f"Bind {name} to localhost or a private network, require "
                               "authentication, and firewall the port from the public internet.",
                classification=Classification(cwe=["CWE-668"]),
            ))
    return report.finish("Finished")


def _parse(xml: str) -> tuple[list[list[str]], list[int]]:
    rows: list[list[str]] = []
    open_ports: list[int] = []
    try:
        root = ET.fromstring(xml)  # nosec B314: input is our own nmap subprocess output
    except ET.ParseError:
        return rows, open_ports
    for port in root.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        portid = port.get("portid", "")
        proto = port.get("protocol", "tcp")
        service = port.find("service")
        name = service.get("name", "") if service is not None else ""
        product = ""
        if service is not None:
            product = " ".join(
                v for v in (service.get("product"), service.get("version"),
                            service.get("extrainfo")) if v)
        rows.append([portid, proto, "open", name or "-", product or "-"])
        if portid.isdigit():
            open_ports.append(int(portid))
    return rows, open_ports
