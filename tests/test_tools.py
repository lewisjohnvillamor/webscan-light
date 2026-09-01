"""Tool-suite tests. Network-touching tools run against the local fixture server."""
from __future__ import annotations

import json

import pytest

from webscan.core.toolreport import Section, ToolReport
from webscan.core.models import Finding, Severity
from webscan.report import generic
from webscan.tools.base import ToolOptions, all_tools, get_tool, load_tools
from webscan.tools.ports import parse_ports


def test_all_tools_register():
    load_tools()
    ids = {spec.id for spec in all_tools()}
    for expected in ("recon", "ssl", "ports", "network", "subdomains", "vhosts",
                     "takeover", "dorks", "api", "urlfuzzer", "xss", "sqli", "sniper"):
        assert expected in ids


def test_parse_ports_forms():
    assert parse_ports("80,443,8080") == [80, 443, 8080]
    assert parse_ports("1-10") == list(range(1, 11))
    assert 443 in parse_ports("top100")
    assert len(parse_ports("top1000")) >= 1000
    assert parse_ports("") == parse_ports("top100")


def test_active_tools_refuse_without_authorization():
    load_tools()
    for tool_id in ("xss", "sqli"):
        report = get_tool(tool_id).func("http://127.0.0.1:9/", ToolOptions(authorized=False))
        assert report.status == "Blocked"
        assert any("authoriz" in e.lower() for e in report.errors)


def test_dorks_generates_queries():
    load_tools()
    report = get_tool("dorks").func("example.com", ToolOptions())
    assert report.status == "Finished"
    assert report.sections
    queries = [row[0] for section in report.sections for row in (section.table.rows if section.table else [])]
    assert any("site:example.com" in q for q in queries)


def test_url_fuzzer_finds_paths(server):
    load_tools()
    report = get_tool("urlfuzzer").func(server, ToolOptions(timeout=5, max_items=60, workers=20))
    assert report.status == "Finished"
    paths = {row[0] for row in report.sections[0].table.rows}
    assert "robots.txt" in paths


def test_ports_scans_fixture(server):
    load_tools()
    from urllib.parse import urlparse
    port = urlparse(server).port
    report = get_tool("ports").func(f"127.0.0.1", ToolOptions(ports=str(port), timeout=3))
    assert report.status == "Finished"
    assert any(row[0] == str(port) for row in report.sections[0].table.rows)


def test_generic_report_renders_html_and_json():
    report = ToolReport(tool="ssl", tool_name="SSL/TLS Scanner", target="https://x/")
    report.sections = [Section("Certificate", kv=[("Issuer", "<b>x</b>")])]
    report.findings = [Finding("c", "Weak cipher <script>", Severity.MEDIUM)]
    report.finish()
    markup = generic.render(report)
    assert "SSL/TLS Scanner" in markup
    assert "<script>" not in markup            # untrusted content escaped
    assert "Weak cipher" in markup
    payload = json.loads(generic.render_json(report))
    assert payload["tool"] == "ssl"
    assert payload["overall_risk"] == "Medium"


def test_generic_report_escapes_section_tables():
    from webscan.core.models import Table
    report = ToolReport(tool="ports", tool_name="Port Scanner", target="x")
    report.sections = [Section("Ports", table=Table(["Port"], [["<img onerror=x>"]]))]
    report.finish()
    markup = generic.render(report)
    assert "<img onerror=x>" not in markup


def test_scope_guard():
    from webscan.core.scope import check
    assert check("example.com", allow_private=False)[0] is True
    assert check("http://169.254.169.254/", allow_private=False)[0] is False
    assert check("10.0.0.5", allow_private=False)[0] is False
    assert check("127.0.0.1", allow_private=False)[0] is False
    assert check("10.0.0.5", allow_private=True)[0] is True


def test_new_tools_registered():
    from webscan.tools.base import all_tools, load_tools
    load_tools()
    ids = {s.id for s in all_tools()}
    for expected in ("dnsemail", "deps", "webmisc", "cloud", "secrets", "typosquat", "asm"):
        assert expected in ids


def test_manifest_parsing(tmp_path):
    from webscan.tools.manifests import find_and_parse
    (tmp_path / "requirements.txt").write_text("jinja2==3.1.2\nrequests==2.20.0\n")
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.11"}}}')
    deps = find_and_parse(str(tmp_path))
    names = {(d["ecosystem"], d["name"]) for d in deps}
    assert ("PyPI", "jinja2") in names
    assert ("npm", "lodash") in names


def test_secrets_scanner_detects_planted(tmp_path):
    from webscan.tools.base import ToolOptions, get_tool, load_tools
    load_tools()
    # Build the token at runtime so no literal secret pattern is committed
    # (GitHub push protection scans committed blobs).
    fake = "sk_" + "live_" + "abcdef0123456789abcdef01"
    (tmp_path / "cfg.py").write_text(f'stripe = "{fake}"\n')
    report = get_tool("secrets").func(str(tmp_path), ToolOptions())
    assert report.status == "Finished"
    assert any("Stripe" in f.title for f in report.findings)


def test_secrets_ignores_placeholders(tmp_path):
    from webscan.tools.base import ToolOptions, get_tool, load_tools
    load_tools()
    (tmp_path / "cfg.py").write_text('api_key = "your-api-key-here-example"\n')
    report = get_tool("secrets").func(str(tmp_path), ToolOptions())
    assert not report.findings


def test_scoring_and_badge():
    from webscan.report.scoring import grade_from_counts
    from webscan.report.badge import grade_badge
    assert grade_from_counts({"Critical": 1, "High": 0, "Medium": 0, "Low": 0, "Info": 0})[0] == "F"
    assert grade_from_counts({"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0})[0] == "A"
    assert "<svg" in grade_badge("B")


def test_typosquat_variants():
    from webscan.tools.typosquat import _variants
    v = _variants("google", "com")
    assert "gogle.com" in v          # omission
    assert any(d.endswith(".net") for d in v)  # TLD swap
    assert "google.com" not in v     # excludes the original
