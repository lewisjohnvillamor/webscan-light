"""Authenticated-scanning and JS-render wiring tests."""
from __future__ import annotations

from webscan.core.engine import ScanOptions, _apply_auth, run_scan
from webscan.core.http import HttpClient
from webscan.core.models import ScanResult


def test_cookie_string_loaded_into_session():
    client = HttpClient()
    client.set_cookie_string("session=abc; csrf=def; empty")
    jar = dict(client.session.cookies)
    assert jar["session"] == "abc" and jar["csrf"] == "def"


def test_apply_auth_marks_authenticated():
    client = HttpClient()
    result = ScanResult(target="https://example.com/")
    applied = _apply_auth(client, ScanOptions(target="https://example.com/", cookie="a=b"), result)
    assert applied and result.authentication is True
    assert dict(client.session.cookies)["a"] == "b"


def test_unauthenticated_scan_reports_false(server):
    result = run_scan(ScanOptions(target=server, max_pages=2, offline=True))
    assert result.authentication is False


def test_authenticated_scan_reports_true(server):
    result = run_scan(ScanOptions(target=server, max_pages=2, offline=True, cookie="sid=xyz"))
    assert result.authentication is True


def test_header_auth_counts_as_authenticated(server):
    result = run_scan(ScanOptions(target=server, max_pages=2, offline=True,
                                  extra_headers={"Authorization": "Bearer t0ken"}))
    assert result.authentication is True


def test_render_option_defaults_off_and_scan_still_works(server):
    # render defaults to False; a normal scan must be unaffected.
    result = run_scan(ScanOptions(target=server, max_pages=2, offline=True))
    assert result.status == "Finished"


def test_spider_merges_rendered_dom():
    from webscan.core.http import Response
    from webscan.core.spider import Page, _merge_rendered
    resp = Response(url="https://x/", status_code=200, headers={"Content-Type": "text/html"},
                    text="<html></html>", content=b"", elapsed_ms=1, request_method="GET",
                    request_headers={})
    page = Page(url="https://x/", response=resp)
    page.links = ["https://x/static"]
    _merge_rendered(page, '<a href="/spa-route">x</a><script src="/app.js"></script>', "https://x/")
    assert "https://x/spa-route" in page.links      # JS-only link added
    assert "https://x/static" in page.links         # static link preserved
    assert "https://x/app.js" in page.scripts
