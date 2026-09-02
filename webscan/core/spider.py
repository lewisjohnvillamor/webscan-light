"""A small, polite, breadth-first crawler.

The checks operate on the pages it collects, so a single crawl feeds every
content-based test instead of each test re-fetching the site.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urldefrag, urlparse

from bs4 import BeautifulSoup

from .http import HttpClient, Response, join, same_origin

SKIP_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".mp3", ".zip",
    ".gz", ".pdf", ".dmg", ".exe",
)


@dataclass
class Form:
    action: str
    method: str
    inputs: list[dict[str, str]] = field(default_factory=list)
    page_url: str = ""

    @property
    def field_names(self) -> list[str]:
        return [i.get("name", "") for i in self.inputs if i.get("name")]

    @property
    def has_password(self) -> bool:
        return any(i.get("type", "").lower() == "password" for i in self.inputs)

    @property
    def has_file_upload(self) -> bool:
        return any(i.get("type", "").lower() == "file" for i in self.inputs)


@dataclass
class Page:
    url: str
    response: Response
    soup: BeautifulSoup | None = None
    forms: list[Form] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)

    @property
    def is_html(self) -> bool:
        ctype = self.response.header("Content-Type") or ""
        return "html" in ctype.lower()


@dataclass
class CrawlResult:
    pages: list[Page] = field(default_factory=list)
    injection_points: set[str] = field(default_factory=set)

    @property
    def root(self) -> Page | None:
        return self.pages[0] if self.pages else None

    @property
    def forms(self) -> list[Form]:
        return [form for page in self.pages for form in page.forms]


def _parse_page(url: str, response: Response) -> Page:
    page = Page(url=url, response=response)
    ctype = (response.header("Content-Type") or "").lower()
    if "html" not in ctype or not response.text:
        return page
    soup = BeautifulSoup(response.text, "html.parser")
    page.soup = soup

    for anchor in soup.find_all(["a", "area"], href=True):
        href = anchor["href"].strip()
        if href.lower().startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
            continue
        page.links.append(join(url, href))

    for script in soup.find_all("script", src=True):
        page.scripts.append(join(url, script["src"].strip()))

    for element in soup.find_all("form"):
        form = Form(
            action=join(url, (element.get("action") or "").strip() or url),
            method=(element.get("method") or "GET").upper(),
            page_url=url,
        )
        for field_el in element.find_all(["input", "textarea", "select"]):
            form.inputs.append(
                {
                    "name": field_el.get("name", "") or "",
                    "type": (field_el.get("type") or field_el.name or "").lower(),
                    "id": field_el.get("id", "") or "",
                }
            )
        page.forms.append(form)
    return page


def _merge_rendered(page: Page, dom: str, url: str) -> None:
    """Union links/forms/scripts discovered in a rendered DOM into ``page``."""
    try:
        soup = BeautifulSoup(dom, "html.parser")
    except Exception:  # noqa: BLE001
        return
    known_links = set(page.links)
    for anchor in soup.find_all(["a", "area"], href=True):
        href = anchor["href"].strip()
        if href.lower().startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
            continue
        full = join(url, href)
        if full not in known_links:
            known_links.add(full)
            page.links.append(full)
    known_scripts = set(page.scripts)
    for script in soup.find_all("script", src=True):
        src = join(url, script["src"].strip())
        if src not in known_scripts:
            known_scripts.add(src)
            page.scripts.append(src)
    seen_forms = {(f.action, tuple(f.field_names)) for f in page.forms}
    for element in soup.find_all("form"):
        form = Form(
            action=join(url, (element.get("action") or "").strip() or url),
            method=(element.get("method") or "GET").upper(), page_url=url)
        for field_el in element.find_all(["input", "textarea", "select"]):
            form.inputs.append({"name": field_el.get("name", "") or "",
                                "type": (field_el.get("type") or field_el.name or "").lower(),
                                "id": field_el.get("id", "") or ""})
        if (form.action, tuple(form.field_names)) not in seen_forms:
            seen_forms.add((form.action, tuple(form.field_names)))
            page.forms.append(form)


def crawl(
    client: HttpClient,
    start_url: str,
    max_pages: int = 15,
    max_depth: int = 2,
    render: bool = False,
) -> CrawlResult:
    result = CrawlResult()
    seen: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(start_url, 0)])

    while queue and len(result.pages) < max_pages:
        url, depth = queue.popleft()
        url, _ = urldefrag(url)
        if url in seen:
            continue
        seen.add(url)
        if urlparse(url).path.lower().endswith(SKIP_EXTENSIONS):
            continue

        response = client.get(url, cache=True)
        if not response.ok:
            continue
        page = _parse_page(url, response)
        if render and page.is_html:
            from .render import render_html
            dom = render_html(url)
            if dom:
                _merge_rendered(page, dom, url)
        result.pages.append(page)

        for name, _value in parse_qsl(urlparse(url).query):
            result.injection_points.add(f"{urlparse(url).path}?{name}")
        for form in page.forms:
            for name in form.field_names:
                result.injection_points.add(f"{urlparse(form.action).path}#{name}")

        if depth < max_depth:
            for link in page.links:
                if same_origin(start_url, link) and link not in seen:
                    queue.append((link, depth + 1))
    return result
