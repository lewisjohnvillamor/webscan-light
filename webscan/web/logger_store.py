"""HTTP request logger.

Creates unique tokens; any HTTP request to /logger/{token}/... is recorded so
you can test for blind/out-of-band issues (SSRF, blind XSS callbacks, webhook
verification). Data is kept in memory only.
"""
from __future__ import annotations

import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class LoggedRequest:
    method: str
    path: str
    query: str
    headers: dict[str, str]
    body: str
    remote: str
    at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_dict(self) -> dict:
        return {
            "method": self.method, "path": self.path, "query": self.query,
            "headers": self.headers, "body": self.body[:2000], "remote": self.remote,
            "at": self.at.isoformat(),
        }


@dataclass
class LoggerToken:
    token: str
    label: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    requests: deque = field(default_factory=lambda: deque(maxlen=200))


class LoggerStore:
    def __init__(self, max_tokens: int = 50) -> None:
        self._tokens: dict[str, LoggerToken] = {}
        self._lock = threading.Lock()
        self.max_tokens = max_tokens

    def create(self, label: str = "") -> LoggerToken:
        token = uuid.uuid4().hex[:16]
        entry = LoggerToken(token=token, label=label)
        with self._lock:
            self._tokens[token] = entry
            while len(self._tokens) > self.max_tokens:
                oldest = min(self._tokens.values(), key=lambda t: t.created_at)
                del self._tokens[oldest.token]
        return entry

    def record(self, token: str, request: LoggedRequest) -> bool:
        entry = self._tokens.get(token)
        if not entry:
            return False
        entry.requests.appendleft(request)
        return True

    def get(self, token: str) -> LoggerToken | None:
        return self._tokens.get(token)

    def all(self) -> list[LoggerToken]:
        with self._lock:
            return sorted(self._tokens.values(), key=lambda t: t.created_at, reverse=True)
