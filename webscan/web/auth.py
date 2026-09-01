"""Optional token auth for the web UI and API — standard library only.

If WEBSCAN_TOKEN is set, every route except the exempt ones requires it. A
browser authenticates once at /login (the token is verified and a signed,
HttpOnly cookie is set); programmatic callers send the token as a
`Authorization: Bearer <token>` or `X-Webscan-Token` header. If no token is
configured, the app is open (intended for loopback-only use) and the server
prints a warning when bound to a non-loopback address.
"""
from __future__ import annotations

import hashlib
import hmac
import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

COOKIE = "webscan_auth"
# Paths reachable without auth: login, health, and the logger capture URLs
# (they carry their own unguessable token and are meant for external callers).
EXEMPT_PREFIXES = ("/login", "/health", "/logger/")


def configured_token() -> str:
    return os.environ.get("WEBSCAN_TOKEN", "").strip()


def _cookie_value(token: str) -> str:
    return hmac.new(token.encode(), b"webscan-auth-v1", hashlib.sha256).hexdigest()


def valid_cookie(token: str, value: str | None) -> bool:
    return bool(value) and hmac.compare_digest(value, _cookie_value(token))


def valid_bearer(token: str, request: Request) -> bool:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        if hmac.compare_digest(header[7:].strip(), token):
            return True
    supplied = request.headers.get("x-webscan-token", "")
    return bool(supplied) and hmac.compare_digest(supplied, token)


def _is_exempt(path: str) -> bool:
    # /logger and /logger/view/* are UI pages (guarded); only /logger/<token>[/...]
    # capture endpoints are public. Guard the two UI paths explicitly.
    if path in ("/logger",) or path.startswith("/logger/view"):
        return False
    return any(path == p.rstrip("/") or path.startswith(p) for p in EXEMPT_PREFIXES)


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        token = configured_token()
        if not token or _is_exempt(request.url.path):
            return await call_next(request)
        if valid_cookie(token, request.cookies.get(COOKIE)) or valid_bearer(token, request):
            return await call_next(request)
        # Unauthenticated: browsers get a redirect to login, API callers a 401.
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            return RedirectResponse(url="/login", status_code=303)
        return JSONResponse({"error": "authentication required"}, status_code=401)


def set_auth_cookie(response, token: str, secure: bool) -> None:
    response.set_cookie(COOKIE, _cookie_value(token), httponly=True, samesite="lax",
                        secure=secure, max_age=60 * 60 * 24 * 30, path="/")
