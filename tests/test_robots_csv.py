"""Tests for robots.txt-aware crawling and CSV export."""
from __future__ import annotations

from webscan.core.models import Classification, Confidence, Finding, ScanResult, Severity
from webscan.core.robots import RobotsPolicy
from webscan.report import csvout


def test_robots_disabled_allows_everything():
    p = RobotsPolicy.disabled()
    assert p.allowed("https://x/anything")


def test_robots_policy_parses_disallow():
    from urllib.robotparser import RobotFileParser
    rp = RobotFileParser()
    rp.parse(["User-agent: *", "Disallow: /private"])
    p = RobotsPolicy(user_agent="webscan", _parser=rp, present=True)
    assert p.allowed("https://x/public")
    assert not p.allowed("https://x/private/secret")


def test_csv_export_has_header_and_rows():
    r = ScanResult(target="https://example.com/")
    r.findings = [
        Finding("a", "Weak cipher", Severity.HIGH, Confidence.CONFIRMED,
                classification=Classification(cve=["CVE-2021-1"], cvss_v3=9.8,
                                              cwe=["CWE-327"], cisa_kev=True)),
        Finding("b", "Missing header", Severity.LOW, Confidence.CONFIRMED,
                recommendation="Add the header."),
    ]
    out = csvout.render_csv(r)
    lines = out.strip().splitlines()
    assert lines[0].startswith("target,https://example.com/")
    assert "severity,confidence,title" in lines[1]
    assert any("Weak cipher" in ln and "CVE-2021-1" in ln and "9.8" in ln for ln in lines)
    assert any("Missing header" in ln and "Add the header." in ln for ln in lines)


def test_crawl_respect_robots_smoke(server):
    from webscan.core.http import HttpClient
    from webscan.core.spider import crawl
    client = HttpClient(timeout=5)
    result = crawl(client, server, max_pages=5, max_depth=1, respect_robots=True)
    assert result.pages  # fixture is crawlable; must not crash with robots on
