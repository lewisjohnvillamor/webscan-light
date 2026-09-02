"""Shared injection-point discovery for the active detectors."""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from webscan.core.http import HttpClient
from webscan.core.spider import crawl


@dataclass
class InjectionPoint:
    method: str          # GET or POST
    url: str             # request URL (query stripped for POST)
    param: str           # parameter name
    base_params: dict    # the other parameters, kept at their original values

    def build(self, value: str) -> tuple[str, str, dict]:
        """Return (method, url, data-or-None) with ``param`` set to ``value``."""
        params = dict(self.base_params)
        params[self.param] = value
        if self.method == "GET":
            parsed = urlparse(self.url)
            query = urlencode(params)
            return "GET", urlunparse(parsed._replace(query=query)), None
        return "POST", self.url, params


def discover(client: HttpClient, target: str, max_pages: int, max_depth: int,
             render: bool = False) -> list[InjectionPoint]:
    """Crawl the target and enumerate GET/POST parameters worth testing."""
    result = crawl(client, target, max_pages=max_pages, max_depth=max_depth, render=render)
    points: list[InjectionPoint] = []
    seen: set[tuple] = set()

    for page in result.pages:
        query = dict(parse_qsl(urlparse(page.url).query))
        for name in query:
            key = ("GET", urlparse(page.url).path, name)
            if key not in seen:
                seen.add(key)
                points.append(InjectionPoint("GET", page.url, name, query))

    for form in result.forms:
        params = {i.get("name", ""): (i.get("value", "") or "test")
                  for i in form.inputs if i.get("name")}
        for name in list(params):
            key = (form.method, urlparse(form.action).path, name)
            if key in seen:
                continue
            seen.add(key)
            points.append(InjectionPoint(form.method, form.action, name, params))
    return points
