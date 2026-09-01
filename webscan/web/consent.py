"""One-time scan-safety acknowledgement gate for the web UI."""
from __future__ import annotations

import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse

COOKIE = "webscan_consent"
# Only gate interactive HTML pages; never the API, downloads, logger capture, etc.
GATED = ("/", "/tool", "/schedules", "/history", "/logger")
EXEMPT = ("/consent", "/login", "/health")


def _is_gated(path: str) -> bool:
    if any(path == e or path.startswith(e + "/") for e in EXEMPT):
        return False
    if path.startswith("/logger/") and path not in ("/logger",):
        return False  # capture endpoints and views handled below
    if path == "/logger" or path.startswith("/logger/view"):
        return True
    return path == "/" or path.startswith("/tool") or path.startswith("/schedules") \
        or path.startswith("/history")


class ConsentMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if os.environ.get("WEBSCAN_NO_CONSENT", "").lower() in ("1", "true", "yes", "on"):
            return await call_next(request)
        if request.method == "GET" and _is_gated(request.url.path) \
                and request.cookies.get(COOKIE) != "1":
            return RedirectResponse(url=f"/consent?next={request.url.path}", status_code=303)
        return await call_next(request)
