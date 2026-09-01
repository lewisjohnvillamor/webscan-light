"""End-to-end scans against the local fixture server (no internet required)."""
from __future__ import annotations

import json

import pytest

from webscan.core.engine import ScanOptions, run_scan
from webscan.core.models import Severity
from webscan.core.registry import all_checks, load_checks
from webscan.report import html as html_report
from webscan.report import jsonout, sarif


@pytest.fixture(scope="module")
def result(server):
    return run_scan(ScanOptions(target=server, max_pages=8, max_depth=2, offline=True))


def titles(result) -> list[str]:
    return [finding.title for finding in result.findings]


def find(result, test_id: str):
    return next((f for f in result.findings if f.test_id == test_id), None)


def test_scan_finishes_and_records_stats(result):
    assert result.status == "Finished"
    assert result.stats.urls_spidered >= 3
    assert result.stats.http_requests > 0
    assert result.duration_seconds >= 0


def test_every_registered_check_is_reported_as_performed(result):
    load_checks()
    assert len(result.tests_performed) == len(all_checks())
    assert "Scanned for robots.txt file" in result.tests_performed


def test_detects_missing_security_headers(result):
    assert find(result, "csp") is not None
    assert find(result, "xcto") is not None
    assert find(result, "referrer_policy") is not None
    # The fixture is plain HTTP, so HSTS is not applicable and must not be reported.
    assert find(result, "hsts") is None


def test_detects_robots_txt(result):
    finding = find(result, "robots")
    assert finding is not None
    assert finding.severity is Severity.INFO
    assert finding.table.rows[0][0].endswith("/robots.txt")


def test_reports_missing_security_txt(result):
    finding = find(result, "security_txt")
    assert finding is not None
    assert "Missing:" in finding.table.rows[0][0]


def test_detects_http_options(result):
    finding = find(result, "http_options")
    assert finding is not None
    assert "Allow: GET, HEAD" in finding.table.rows[0][2]


def test_fingerprints_server_and_technologies(result):
    finding = find(result, "technologies")
    assert finding is not None
    software = [row[0] for row in finding.table.rows]
    assert "Nginx 1.18.0" in software
    assert "Ubuntu" in software
    assert any(name.startswith("WordPress") for name in software)


def test_detects_email_exposure(result):
    finding = find(result, "emails")
    assert finding is not None
    assert any("support@testsite.local" in row[3] for row in finding.table.rows)


def test_detects_sensitive_data_and_path_disclosure(result):
    assert find(result, "sensitive_data") is not None
    assert find(result, "path_disclosure") is not None


def test_detects_insecure_password_submission(result):
    assert find(result, "login_interfaces") is not None
    assert find(result, "password_unencrypted") is not None
    assert find(result, "password_in_url") is not None
    assert find(result, "secure_password_submission") is not None


def test_detects_file_upload_and_session_token_in_url(result):
    assert find(result, "file_upload") is not None
    assert find(result, "session_token_in_url") is not None


def test_detects_interesting_comments(result):
    finding = find(result, "code_comments")
    assert finding is not None
    assert any("password" in row[1].lower() for row in finding.table.rows)


def test_detects_cross_domain_script_without_integrity(result):
    finding = find(result, "cross_domain_inclusion")
    assert finding is not None
    assert any("cdn.example.com" in row[1] for row in finding.table.rows)


def test_no_https_check_flags_plain_http_target(result):
    finding = find(result, "secure_communication")
    assert finding is not None
    assert finding.severity is Severity.HIGH


def test_cookie_flags_are_checked(result):
    # The fixture sets a cookie with neither HttpOnly nor Secure over plain HTTP.
    assert find(result, "cookie_httponly") is not None
    assert find(result, "cookie_secure") is None  # Secure is only meaningful over HTTPS


def test_only_and_skip_filters_narrow_the_run(server):
    only = run_scan(ScanOptions(target=server, max_pages=2, offline=True, only=["robots"]))
    assert only.tests_performed == ["Scanned for robots.txt file"]
    assert {f.test_id for f in only.findings} <= {"robots"}

    skipped = run_scan(ScanOptions(target=server, max_pages=2, offline=True, skip=["robots"]))
    assert find(skipped, "robots") is None


def test_unreachable_target_fails_cleanly():
    result = run_scan(ScanOptions(target="http://127.0.0.1:1/", timeout=2, offline=True))
    assert result.status == "Failed"
    assert result.errors


def test_html_report_contains_the_report_sections(result):
    markup = html_report.render(result)
    for expected in ("Website Vulnerability Scanner Report", "Summary", "Findings",
                     "Scan coverage information", "Scan parameters", "Scan stats",
                     "Overall risk level"):
        assert expected in markup
    assert f"List of tests performed ({len(result.tests_performed)})" in markup


def test_html_report_escapes_untrusted_content(result):
    from webscan.core.models import Finding, Table

    result.findings.append(
        Finding(test_id="x", title="<script>alert(1)</script>", severity=Severity.INFO,
                table=Table(columns=["URL"], rows=[["<img onerror=alert(2)>"]]))
    )
    try:
        markup = html_report.render(result)
        assert "<script>alert(1)</script>" not in markup
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in markup
        assert "<img onerror=alert(2)>" not in markup
    finally:
        result.findings.pop()


def test_json_report_round_trips(result):
    payload = json.loads(jsonout.render(result))
    assert payload["scanner"] == "webscan-light"
    assert payload["target"] == result.target
    assert len(payload["findings"]) == len(result.findings)
    assert payload["overall_risk"] == result.overall_risk.label


def test_sarif_report_is_well_formed(result):
    document = json.loads(sarif.render(result))
    assert document["version"] == "2.1.0"
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "webscan-light"
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    for entry in run["results"]:
        assert entry["ruleId"] in rule_ids
        assert entry["level"] in ("error", "warning", "note")
