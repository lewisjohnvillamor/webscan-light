"""Upload-to-scan flow for local-filesystem tools (code/secrets/deps) in the web UI."""
from __future__ import annotations

import io
import os
import tempfile
import time
import zipfile

import pytest

pytest.importorskip("httpx")

os.environ["WEBSCAN_ALLOW_PRIVATE"] = "1"
os.environ["WEBSCAN_NO_CONSENT"] = "1"
os.environ.pop("WEBSCAN_TOKEN", None)

from starlette.testclient import TestClient

from webscan.web.app import app
from webscan.web.uploads import UploadError, extract_zip


def _zip_bytes(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in files.items():
            z.writestr(name, body)
    return buf.getvalue()


def test_zip_slip_blocked():
    with tempfile.TemporaryDirectory() as d:
        zp = os.path.join(d, "b.zip")
        open(zp, "wb").write(_zip_bytes({"../evil.txt": "x"}))
        with pytest.raises(UploadError):
            extract_zip(zp, os.path.join(d, "out"))


def test_extract_ok():
    with tempfile.TemporaryDirectory() as d:
        zp = os.path.join(d, "ok.zip")
        open(zp, "wb").write(_zip_bytes({"proj/a.py": "x=1\n", "proj/b.py": "y=2\n"}))
        files, total = extract_zip(zp, os.path.join(d, "out"))
        assert files == 2 and total > 0


def test_upload_code_scan_end_to_end():
    secret = "sk_" + "live_" + "abcd1234abcd1234abcd1234"
    data = _zip_bytes({
        "proj/app.py": "import subprocess\nsubprocess.run('ls '+u, shell=True)\n",
        "proj/package.json": '{"dependencies":{"expres":"^4"}}',
        "proj/.env": f"API_KEY={secret}\n"})
    with TestClient(app) as c:
        r = c.post("/upload/code",
                   files={"archive": ("proj.zip", data, "application/zip")},
                   follow_redirects=False)
        assert r.status_code == 303
        job = r.headers["location"].split("/job/")[1]
        state = "queued"
        for _ in range(50):
            state = c.get(f"/api/job/{job}").json()["state"]
            if state in ("finished", "failed", "blocked"):
                break
            time.sleep(0.2)
        assert state == "finished"
        html = c.get(f"/job/{job}/report.html").text
        assert "Shell command execution" in html
        assert "typosquat" in html.lower()
        assert "proj.zip" in html                 # friendly name shown
        assert "webscan-upload-" not in html      # server temp path never leaks


def test_upload_rejects_non_zip():
    with TestClient(app) as c:
        r = c.post("/upload/code",
                   files={"archive": ("notes.txt", b"hello", "text/plain")},
                   follow_redirects=False)
        assert r.status_code == 400
        assert ".zip" in r.text


def test_upload_unknown_tool_404():
    with TestClient(app) as c:
        r = c.post("/upload/website",
                   files={"archive": ("x.zip", _zip_bytes({"a": "b"}), "application/zip")},
                   follow_redirects=False)
        assert r.status_code == 404
