"""A local target server, so the test suite never touches the internet."""
from __future__ import annotations

import http.server
import threading

import pytest

VULNERABLE_INDEX = """<!DOCTYPE html>
<html><head>
  <title>Test app</title>
  <meta name="generator" content="WordPress 6.1">
  <meta property="og:title" content="Test">
</head>
<body>
  <!-- TODO: remove the temporary admin password before launch -->
  <p>Contact us at support@testsite.local</p>
  <a href="/about">About</a>
  <a href="/login">Login</a>
  <a href="/session?sid=abc123def456">Resume session</a>
  <form action="http://testsite.local/login" method="GET">
    <input type="text" name="username">
    <input type="password" name="password">
  </form>
  <form action="/upload" method="POST"><input type="file" name="document"></form>
  <script src="http://cdn.example.com/lib.js"></script>
  <script src="/static/jquery-3.4.1.min.js"></script>
  <img src="http://insecure.example.com/pixel.png">
  <p>AWS key AKIAIOSFODNN7EXAMPLE is in the page</p>
  <p>Failure in /var/www/html/app/index.php on line 42</p>
</body></html>
"""

ROBOTS = "User-agent: *\nDisallow: /admin\n"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # silence the test server
        pass

    def _send(self, body: str, status: int = 200, ctype: str = "text/html",
              extra: dict[str, str] | None = None) -> None:
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Server", "nginx/1.18.0 (Ubuntu)")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self._send(VULNERABLE_INDEX, extra={
                "Set-Cookie": "sessionid=xyz; Path=/; Domain=.testsite.local",
            })
        elif path == "/robots.txt":
            self._send(ROBOTS, ctype="text/plain")
        elif path == "/about":
            self._send("<html><body>About page</body></html>")
        elif path == "/login":
            self._send('<html><body><form method="POST" action="/login">'
                       '<input type="password" name="password"></form></body></html>')
        elif path == "/secure":
            self._send("<html>ok</html>", extra={
                "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security": "max-age=31536000",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
            })
        elif path == "/boom":
            self._send("Traceback (most recent call last): oops", status=500)
        else:
            self._send("<html>not found</html>", status=404)

    def do_OPTIONS(self):
        self.send_response(405)
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture(scope="session")
def server() -> str:
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/"
    httpd.shutdown()
