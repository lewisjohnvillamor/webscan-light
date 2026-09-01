"""Web app tests using the in-process test client (no real network needed
beyond the local fixture server the tools hit)."""
from __future__ import annotations

import time

import pytest

pytest.importorskip("httpx")

# The test fixture server runs on loopback, which the SSRF scope guard blocks by
# default. Opt into private targets before importing the app.
import os
os.environ["WEBSCAN_ALLOW_PRIVATE"] = "1"
os.environ["WEBSCAN_NO_CONSENT"] = "1"
os.environ["WEBSCAN_SCAN_TTL"] = "0"  # disable reuse so each test scans fresh
os.environ.pop("WEBSCAN_TOKEN", None)

from starlette.testclient import TestClient

from webscan.web.app import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _wait(client, job_id, timeout=25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        state = client.get(f"/api/job/{job_id}").json()["state"]
        if state in ("finished", "failed", "blocked"):
            return state
        time.sleep(0.3)
    return "timeout"


def test_index_lists_tools(client):
    body = client.get("/").text
    assert "webscan-light" in body
    assert "SSL/TLS Scanner" in body
    assert "Website Scanner" in body


def test_tool_form_renders(client):
    assert client.get("/tool/ssl").status_code == 200
    assert client.get("/tool/website").status_code == 200
    assert client.get("/tool/nope").status_code == 404


def test_website_scan_flow(client, server):
    resp = client.post("/tool/website", data={"target": server, "max_items": 4, "timeout": 8},
                       follow_redirects=False)
    assert resp.status_code == 303
    job_id = resp.headers["location"].rsplit("/", 1)[-1]
    assert _wait(client, job_id) == "finished"
    assert client.get(f"/job/{job_id}/report.html").status_code == 200
    assert client.get(f"/job/{job_id}/report.json").status_code == 200
    assert client.get(f"/job/{job_id}/report.sarif").status_code == 200


def test_tool_flow_and_json(client, server):
    from urllib.parse import urlparse
    port = urlparse(server).port
    resp = client.post("/tool/ports", data={"target": "127.0.0.1", "ports": str(port),
                                            "timeout": 3}, follow_redirects=False)
    job_id = resp.headers["location"].rsplit("/", 1)[-1]
    assert _wait(client, job_id) == "finished"
    payload = client.get(f"/job/{job_id}/report.json").json()
    assert payload["tool"] == "ports"
    # SARIF is website-only.
    assert client.get(f"/job/{job_id}/report.sarif").status_code == 404


def test_active_tool_blocked_without_authorization(client):
    resp = client.post("/tool/xss", data={"target": "http://127.0.0.1:9/", "timeout": 3},
                       follow_redirects=False)
    job_id = resp.headers["location"].rsplit("/", 1)[-1]
    assert _wait(client, job_id) == "blocked"


def test_request_logger_captures(client):
    resp = client.post("/logger", data={"label": "t"}, follow_redirects=False)
    token = resp.headers["location"].rsplit("/", 1)[-1]
    assert client.get(f"/logger/{token}/callback", params={"x": "1"}).status_code == 200
    client.post(f"/logger/{token}/beacon", data="stolen=1")
    data = client.get(f"/api/logger/{token}").json()
    assert len(data["requests"]) == 2
    assert client.get("/api/logger/unknown-token").status_code == 404


def test_scope_guard_blocks_metadata_when_private_disallowed(client, monkeypatch):
    monkeypatch.setenv("WEBSCAN_ALLOW_PRIVATE", "0")
    resp = client.post("/tool/ssl", data={"target": "http://169.254.169.254/"},
                       follow_redirects=False)
    assert resp.status_code == 400
    assert "out of scope" in resp.text.lower()
    monkeypatch.setenv("WEBSCAN_ALLOW_PRIVATE", "1")


def test_auth_required_when_token_set(monkeypatch):
    monkeypatch.setenv("WEBSCAN_TOKEN", "s3cret")
    with TestClient(app) as c:
        # API caller without token -> 401
        assert c.get("/api/job/x").status_code == 401
        # health and logger capture stay public
        assert c.get("/health").status_code == 200
        # bearer token works
        assert c.get("/tool/ssl", headers={"Authorization": "Bearer s3cret"}).status_code == 200
        # wrong token rejected
        assert c.get("/tool/ssl", headers={"Authorization": "Bearer nope"},
                     follow_redirects=False).status_code in (401, 303)


def test_consent_gate_redirects_without_cookie(monkeypatch):
    monkeypatch.setenv("WEBSCAN_NO_CONSENT", "0")
    with TestClient(app) as c:
        r = c.get("/", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/consent")
        # posting consent sets the cookie and lets pages load
        c.post("/consent", data={"next": "/"}, follow_redirects=False)
        assert c.get("/", follow_redirects=False).status_code == 200
    monkeypatch.setenv("WEBSCAN_NO_CONSENT", "1")


def test_recent_scan_is_reused(client, server, monkeypatch):
    monkeypatch.setenv("WEBSCAN_SCAN_TTL", "600")
    from urllib.parse import urlparse
    port = urlparse(server).port
    r1 = client.post("/tool/ports", data={"target": "127.0.0.1", "ports": str(port), "timeout": 3},
                     follow_redirects=False)
    jid = r1.headers["location"].rsplit("/", 1)[-1]
    assert _wait(client, jid) == "finished"
    # a second identical scan should redirect to the stored result, not a new job
    r2 = client.post("/tool/ports", data={"target": "127.0.0.1", "ports": str(port), "timeout": 3},
                     follow_redirects=False)
    assert r2.status_code == 303 and "/stored/" in r2.headers["location"]
    monkeypatch.setenv("WEBSCAN_SCAN_TTL", "0")


def test_one_click_monitor_creates_asm_schedule(client):
    from webscan.core import database
    before = len(database.list_schedules())
    client.post("/schedules/monitor", data={"target": "example.com"}, follow_redirects=False)
    after = database.list_schedules()
    assert len(after) == before + 1
    assert after[0]["tool_id"] == "asm"


def test_filesystem_tools_blocked_in_web(client):
    for tool_id in ("secrets", "deps"):
        r = client.post(f"/tool/{tool_id}", data={"target": "/etc"}, follow_redirects=False)
        assert r.status_code == 400
        assert "disabled in the web UI" in r.text or "local filesystem" in r.text


def test_consent_next_blocks_open_redirect(monkeypatch):
    monkeypatch.setenv("WEBSCAN_NO_CONSENT", "0")
    with TestClient(app) as c:
        # protocol-relative and absolute externals must not be honoured
        for bad in ["//evil.com", "https://evil.com", "/\\evil.com"]:
            r = c.post("/consent", data={"next": bad}, follow_redirects=False)
            assert r.headers["location"] == "/" or r.headers["location"].startswith("/")
            assert "evil.com" not in r.headers["location"]
        # a genuine same-site path is preserved
        r = c.post("/consent", data={"next": "/schedules"}, follow_redirects=False)
        assert r.headers["location"] == "/schedules"
    monkeypatch.setenv("WEBSCAN_NO_CONSENT", "1")
