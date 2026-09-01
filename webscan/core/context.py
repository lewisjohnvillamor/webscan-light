"""The object every check receives."""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

from .http import HttpClient, Response, default_port, join
from .spider import CrawlResult, Page


@dataclass
class ScanContext:
    target: str
    client: HttpClient
    crawl: CrawlResult
    tls: dict[str, Any] = field(default_factory=dict)
    shared: dict[str, Any] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def cached(self, key: str, factory: Callable[[], Any]) -> Any:
        """Compute ``factory`` once and share it across checks (thread-safe).

        Checks run in parallel; without this a fingerprint or cookie parse could
        run several times. The double-check keeps the common (hit) path lock-free.
        """
        if key in self.shared:
            return self.shared[key]
        with self._lock:
            if key not in self.shared:
                self.shared[key] = factory()
            return self.shared[key]

    @property
    def port(self) -> str:
        return default_port(self.target)

    @property
    def origin(self) -> str:
        parsed = urlparse(self.target)
        return f"{parsed.scheme}://{parsed.netloc}"

    @property
    def hostname(self) -> str:
        return urlparse(self.target).hostname or ""

    @property
    def is_https(self) -> bool:
        return urlparse(self.target).scheme == "https"

    @property
    def root(self) -> Page | None:
        return self.crawl.root

    @property
    def root_response(self) -> Response | None:
        return self.crawl.root.response if self.crawl.root else None

    @property
    def html_pages(self) -> list[Page]:
        return [page for page in self.crawl.pages if page.is_html]

    def url_for(self, path: str) -> str:
        return join(self.origin + "/", path.lstrip("/"))

    def fetch(self, path: str, **kwargs: Any) -> Response:
        return self.client.get(self.url_for(path), cache=True, **kwargs)
