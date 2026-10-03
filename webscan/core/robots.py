"""robots.txt awareness for the crawler.

A responsible scanner can honour a site's robots.txt. We fetch it through the
same instrumented HttpClient (so the SSRF scope guard, caching and throttling
still apply) and parse it with the standard library. Disabled by default so an
authorised owner gets full coverage; enable it for polite, production-safe runs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser


@dataclass
class RobotsPolicy:
    user_agent: str
    _parser: RobotFileParser | None = None
    sitemaps: list[str] = field(default_factory=list)
    present: bool = False

    def allowed(self, url: str) -> bool:
        if self._parser is None:
            return True
        try:
            return self._parser.can_fetch(self.user_agent, url)
        except Exception:  # noqa: BLE001 - never let a malformed rule block a scan
            return True

    @classmethod
    def disabled(cls, user_agent: str = "*") -> RobotsPolicy:
        return cls(user_agent=user_agent, _parser=None)

    @classmethod
    def fetch(cls, client, start_url: str, user_agent: str) -> RobotsPolicy:
        parts = urlparse(start_url)
        robots_url = urljoin(f"{parts.scheme}://{parts.netloc}", "/robots.txt")
        try:
            resp = client.get(robots_url, cache=True)
        except Exception:  # noqa: BLE001
            return cls.disabled(user_agent)
        if not getattr(resp, "ok", False) or not (resp.text or "").strip():
            return cls.disabled(user_agent)
        parser = RobotFileParser()
        try:
            parser.parse(resp.text.splitlines())
        except Exception:  # noqa: BLE001
            return cls.disabled(user_agent)
        sitemaps = []
        try:
            sitemaps = parser.site_maps() or []
        except Exception:  # noqa: BLE001
            sitemaps = []
        return cls(user_agent=user_agent, _parser=parser, sitemaps=list(sitemaps), present=True)
