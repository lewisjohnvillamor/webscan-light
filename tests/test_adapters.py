"""Optional external-tool adapters (nuclei, nmap).

The binaries are not assumed present in CI, so these tests cover registration,
graceful skip/gating, and the output-parsing/mapping logic directly.
"""
from __future__ import annotations

from webscan.core.models import Severity
from webscan.report import generic
from webscan.tools.adapters import nmap, nuclei
from webscan.tools.base import ToolOptions, all_tools, get_tool, load_tools


def test_adapters_registered():
    load_tools()
    ids = {s.id for s in all_tools()}
    assert {"nuclei", "nmapscan"} <= ids


def test_adapters_skip_when_binary_absent(monkeypatch):
    load_tools()
    monkeypatch.setattr(nuclei.shutil, "which", lambda _: None)
    monkeypatch.setattr(nmap.shutil, "which", lambda _: None)
    for tid in ("nuclei", "nmapscan"):
        report = get_tool(tid).func("https://example.com", ToolOptions(authorized=True))
        assert report.status == "Skipped"
        assert any("not installed" in e for e in report.errors)


def test_nuclei_blocks_without_authorization(monkeypatch):
    load_tools()
    monkeypatch.setattr(nuclei, "path", lambda: "/usr/bin/nuclei")
    monkeypatch.setattr(nuclei, "version", lambda: "nuclei 3.0")
    report = get_tool("nuclei").func("https://example.com", ToolOptions(authorized=False))
    assert report.status == "Blocked"
    assert any("authoriz" in e.lower() for e in report.errors)


def test_nuclei_maps_jsonl_entry():
    entry = {
        "template-id": "CVE-2021-44228",
        "type": "http",
        "matched-at": "https://example.com:8443/api",
        "matcher-name": "log4j",
        "extracted-results": ["abc"],
        "info": {
            "name": "Apache Log4j RCE",
            "severity": "critical",
            "description": "Log4Shell",
            "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            "classification": {
                "cve-id": ["CVE-2021-44228"],
                "cwe-id": ["CWE-502"],
                "cvss-score": 10.0,
                "epss-score": 0.97,
            },
        },
    }
    finding = nuclei._finding(entry)
    assert finding.severity == Severity.CRITICAL
    assert finding.title == "Apache Log4j RCE"
    assert finding.port == "8443"
    assert finding.classification.cve == ["CVE-2021-44228"]
    assert finding.classification.cvss_v3 == 10.0
    assert "nvd.nist.gov" in finding.references[0]


def test_nmap_parses_xml_and_flags_risky():
    xml = """<?xml version="1.0"?><nmaprun>
      <host><ports>
        <port protocol="tcp" portid="6379"><state state="open"/>
          <service name="redis" product="Redis" version="6.2"/></port>
        <port protocol="tcp" portid="22"><state state="open"/>
          <service name="ssh" product="OpenSSH" version="8.9"/></port>
        <port protocol="tcp" portid="81"><state state="closed"/></port>
      </ports></host></nmaprun>"""
    rows, open_ports = nmap._parse(xml)
    assert ["6379", "tcp", "open", "redis", "Redis 6.2"] in rows
    assert 6379 in open_ports and 22 in open_ports and 81 not in open_ports


def test_nuclei_report_renders():
    report = get_tool("nuclei").func("https://example.com", ToolOptions())
    # not installed -> Skipped, but must still render cleanly
    assert generic.render(report)
