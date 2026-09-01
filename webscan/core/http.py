"""Instrumented HTTP client.

Every request made by every check goes through here so the report's
"Scan stats" section (request count, average response time) is accurate.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
)


@dataclass
class Response:
    """A thin, always-safe wrapper around a requests response."""

    url: str
    status_code: int
    headers: dict[str, str]
    text: str
    content: bytes
    elapsed_ms: int
    request_method: str
    request_headers: dict[str, str]
    cookies: list[str] = field(default_factory=list)
    history: list[str] = field(default_factory=list)
    error: str | None = None
    tls: dict[str, Any] | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def header(self, name: str) -> str | None:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return None

    def raw_exchange(self) -> str:
        """A printable request/response pair, as shown in the reference report."""
        lines = [f"{self.request_method} {self.url}"]
        lines += [f"{k}: {v}" for k, v in self.request_headers.items()]
        lines.append("")
        lines.append(f"HTTP {self.status_code}")
        lines += [f"{k}: {v}" for k, v in self.headers.items()]
        return "\n".join(lines)


def _set_cookie_headers(raw: requests.Response) -> list[str]:
    """Every Set-Cookie header, unjoined.

    ``requests`` collapses repeated headers into one comma-separated string, which
    corrupts cookies containing commas in their Expires attribute; urllib3 keeps
    the individual values.
    """
    try:
        return list(raw.raw.headers.getlist("Set-Cookie"))  # type: ignore[union-attr]
    except AttributeError:
        value = raw.headers.get("Set-Cookie")
        return [value] if value else []


class HttpClient:
    def __init__(
        self,
        timeout: float = 15.0,
        user_agent: str = DEFAULT_UA,
        verify_tls: bool = True,
        max_bytes: int = 3_000_000,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.timeout = timeout
        self.user_agent = user_agent
        self.verify_tls = verify_tls
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self.request_count = 0
        self.total_elapsed_ms = 0
        self.session = requests.Session()
        adapter = HTTPAdapter(pool_connections=16, pool_maxsize=16, max_retries=0)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.base_headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if extra_headers:
            self.base_headers.update(extra_headers)
        self._cache: dict[tuple[str, str], Response] = {}

    def request(
        self,
        method: str,
        url: str,
        *,
        allow_redirects: bool = True,
        cache: bool = False,
        **kwargs: Any,
    ) -> Response:
        key = (method.upper(), url)
        if cache and key in self._cache:
            return self._cache[key]

        headers = dict(self.base_headers)
        headers.update(kwargs.pop("headers", {}) or {})
        started = time.monotonic()
        try:
            raw = self.session.request(
                method,
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                verify=self.verify_tls,
                stream=True,
                **kwargs,
            )
            body = raw.raw.read(self.max_bytes, decode_content=True) or b""
            elapsed_ms = int((time.monotonic() - started) * 1000)
            try:
                text = body.decode(raw.encoding or "utf-8", errors="replace")
            except (LookupError, TypeError):
                text = body.decode("utf-8", errors="replace")
            response = Response(
                url=raw.url,
                status_code=raw.status_code,
                headers=dict(raw.headers),
                text=text,
                content=body,
                elapsed_ms=elapsed_ms,
                request_method=method.upper(),
                request_headers=headers,
                cookies=_set_cookie_headers(raw),
                history=[h.url for h in raw.history],
            )
            raw.close()
        except requests.RequestException as exc:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            response = Response(
                url=url,
                status_code=0,
                headers={},
                text="",
                content=b"",
                elapsed_ms=elapsed_ms,
                request_method=method.upper(),
                request_headers=headers,
                error=f"{type(exc).__name__}: {exc}",
            )

        with self._lock:
            self.request_count += 1
            self.total_elapsed_ms += elapsed_ms
        if cache:
            self._cache[key] = response
        return response

    def get(self, url: str, **kwargs: Any) -> Response:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Response:
        return self.request("HEAD", url, **kwargs)

    @property
    def average_response_ms(self) -> int:
        if not self.request_count:
            return 0
        return int(self.total_elapsed_ms / self.request_count)


def normalize_target(target: str) -> str:
    """Accept ``example.com`` as readily as a full URL."""
    target = target.strip()
    if not target:
        raise ValueError("empty target")
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme: {parsed.scheme}")
    if not parsed.netloc:
        raise ValueError(f"invalid target: {target}")
    path = parsed.path or "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def join(base: str, href: str) -> str:
    return urljoin(base, href)


def default_port(url: str) -> str:
    parsed = urlparse(url)
    if parsed.port:
        return f"{parsed.port}/tcp"
    return "443/tcp" if parsed.scheme == "https" else "80/tcp"
