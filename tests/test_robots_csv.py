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


def _fake_response(text: str, status: int = 200):
    from webscan.core.http import Response
    return Response(url="https://x/sitemap.xml", status_code=status,
                    headers={"Content-Type": "application/xml"}, text=text,
                    content=text.encode(), elapsed_ms=1, request_method="GET",
                    request_headers={})


class _FakeClient:
    """Minimal stand-in for HttpClient.get(), keyed by URL."""
    def __init__(self, routes: dict[str, str]):
        self.routes = routes

    def get(self, url, cache=True):  # noqa: ARG002
        body = self.routes.get(url)
        if body is None:
            return _fake_response("", status=404)
        return _fake_response(body)


def test_sitemap_urls_parses_urlset():
    from webscan.core.spider import _sitemap_urls
    xml = ('<?xml version="1.0"?>'
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
           '<url><loc>https://x/a</loc></url>'
           '<url><loc>https://x/b</loc></url>'
           '</urlset>')
    client = _FakeClient({"https://x/sitemap.xml": xml})
    urls = _sitemap_urls(client, "https://x/sitemap.xml")
    assert urls == ["https://x/a", "https://x/b"]


def test_sitemap_urls_follows_sitemap_index():
    from webscan.core.spider import _sitemap_urls
    index = ('<?xml version="1.0"?>'
            '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            '<sitemap><loc>https://x/sub.xml</loc></sitemap>'
            '</sitemapindex>')
    sub = ('<?xml version="1.0"?>'
          '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
          '<url><loc>https://x/page</loc></url></urlset>')
    client = _FakeClient({"https://x/sitemap.xml": index, "https://x/sub.xml": sub})
    assert _sitemap_urls(client, "https://x/sitemap.xml") == ["https://x/page"]


def test_sitemap_urls_handles_malformed_xml():
    from webscan.core.spider import _sitemap_urls
    client = _FakeClient({"https://x/sitemap.xml": "<not valid xml"})
    assert _sitemap_urls(client, "https://x/sitemap.xml") == []


def test_config_iac_respects_max_files(tmp_path):
    from webscan.tools.codescan import _config_iac
    for i in range(5):
        (tmp_path / f"Dockerfile.{i}").write_text("FROM node:latest\n")
    findings = _config_iac(tmp_path, lambda p: str(p), max_files=2)
    # only 2 of the 5 unpinned Dockerfiles should have been visited
    hits = next(f for f in findings if f.test_id == "cfg_dockerfile")
    assert len(hits.table.rows) <= 2 * 2  # <=2 files, up to 2 rows each (latest + no-USER)
