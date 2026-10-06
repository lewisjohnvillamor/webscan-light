"""Tests for the unified code security scan (SAST + supply-chain + IaC + secrets)."""
from __future__ import annotations

import json

from webscan.tools.base import ToolOptions, get_tool, load_tools
from webscan.tools.codescan import _lev1


def test_lev1_distance():
    assert _lev1("expres", "express")       # insertion
    assert _lev1("lodas", "lodash")         # single deletion
    assert _lev1("chalkk", "chalk")         # single insertion
    assert not _lev1("react", "react")      # identical -> not a typo
    assert not _lev1("totally", "different")


def _make_project(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "demo", "scripts": {"postinstall": "node x.js"},
        "dependencies": {"expres": "^4", "react": "^18"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3, "packages": {
            "node_modules/evil": {"version": "1.0.0",
                                  "resolved": "git+https://github.com/x/evil.git",
                                  "hasInstallScript": True}}}))
    (tmp_path / "src" / "app.py").write_text(
        "import subprocess, hashlib, pickle\n"
        "subprocess.run('ls '+u, shell=True)\n"
        "hashlib.md5(b'x')\n"
        "pickle.loads(u)\n")
    fake = "sk_" + "live_" + "abcd1234abcd1234abcd1234"  # built at runtime; not a real key
    (tmp_path / ".env").write_text(f"API_KEY={fake}\n")
    (tmp_path / "Dockerfile").write_text("FROM node:latest\nRUN curl https://x.sh | bash\n")
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "on: pull_request_target\npermissions: write-all\n"
        "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n")
    return tmp_path


def test_code_scan_detects_all_classes(tmp_path):
    load_tools()
    proj = _make_project(tmp_path)
    report = get_tool("code").func(str(proj), ToolOptions())
    assert report.status == "Finished"
    titles = " | ".join(f.title for f in report.findings)
    assert "Shell command execution" in titles
    assert "Unsafe deserialization" in titles
    assert "Weak hashing" in titles
    assert "typosquat" in titles.lower()
    assert "install scripts" in titles.lower()
    assert "non-registry" in titles.lower()
    assert "Environment file committed" in titles
    assert "write-all" in titles
    assert "pull_request_target" in titles
    assert "Stripe" in titles


def test_code_scan_blocked_in_web():
    load_tools()
    assert get_tool("code").local_fs is True


def test_code_scan_clean_project(tmp_path):
    load_tools()
    (tmp_path / "ok.py").write_text("def add(a, b):\n    return a + b\n")
    report = get_tool("code").func(str(tmp_path), ToolOptions())
    assert report.status == "Finished"
    assert not report.findings
