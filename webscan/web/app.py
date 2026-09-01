"""Starlette web app: tool launcher, runners, reports and request logger.

Deliberately built on Starlette alone (no FastAPI/pydantic) to keep the
self-hosted footprint small.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from starlette.middleware import Middleware
from starlette.routing import Route
from starlette.templating import Jinja2Templates

from webscan import __version__
from webscan.core.engine import ScanOptions
from webscan.core.http import normalize_target
from webscan.core.registry import load_checks
from webscan.core import scope
from webscan.report import generic
from webscan.report import html as html_report
from webscan.report import jsonout, pdf, sarif
from webscan.tools.base import ToolOptions, all_tools, get_tool, load_tools

from . import auth
from .logger_store import LoggedRequest, LoggerStore
from .store import JobStore

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

jobs = JobStore()
logger = LoggerStore()

load_checks()
load_tools()

REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'"

WEBSITE_CARD = {
    "id": "website", "name": "Website Scanner", "category": "Vulnerability",
    "code": "WEB", "active": False,
    "description": "Full 40-test light scan: headers, tech, CVEs, cookies, exposure and more.",
    "target_hint": "URL or hostname",
}


def _tool_cards() -> list[dict]:
    cards = [WEBSITE_CARD]
    for spec in all_tools():
        cards.append({
            "id": spec.id, "name": spec.name, "category": spec.category,
            "code": generic.TOOL_GLYPHS.get(spec.id, "WS"), "active": spec.active,
            "description": spec.description, "target_hint": spec.target_hint,
        })
    order = {"Recon": 0, "Vulnerability": 1, "Exploit": 2}
    cards.sort(key=lambda c: (order.get(c["category"], 9), c["name"]))
    return cards


def _truthy(value: str | None) -> bool:
    return str(value).lower() in ("true", "1", "on", "yes")


async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {
        "version": __version__, "cards": _tool_cards(), "recent": jobs.recent(),
        "categories": ["Recon", "Vulnerability", "Exploit"],
    })


async def tool_form(request: Request):
    tool_id = request.path_params["tool_id"]
    if tool_id == "website":
        card = WEBSITE_CARD
    else:
        if not get_tool(tool_id):
            raise HTTPException(status_code=404, detail="unknown tool")
        card = next(c for c in _tool_cards() if c["id"] == tool_id)
    return templates.TemplateResponse(request, "tool.html", {"version": __version__, "card": card})


async def start(request: Request):
    tool_id = request.path_params["tool_id"]
    form = await request.form()
    target = (form.get("target") or "").strip()
    if not target:
        return _tool_error(request, tool_id, "A target is required.")

    allowed, reason = scope.check(target)
    if not allowed:
        return _tool_error(
            request, tool_id,
            f"Blocked: {reason}. This target is out of scope for the web UI. "
            "Set WEBSCAN_ALLOW_PRIVATE=1 to permit private/internal targets.")

    def num(name, default):
        try:
            return type(default)(form.get(name) or default)
        except (TypeError, ValueError):
            return default

    if tool_id == "website":
        try:
            normalize_target(target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        job = jobs.start_website(ScanOptions(
            target=target, offline=_truthy(form.get("offline")),
            verify_tls=not _truthy(form.get("insecure")),
            timeout=num("timeout", 15.0), max_pages=int(num("max_items", 0)) or 15))
        return RedirectResponse(url=f"/job/{job.id}", status_code=303)

    if not get_tool(tool_id):
        raise HTTPException(status_code=404, detail="unknown tool")
    options = ToolOptions(
        timeout=num("timeout", 10.0), offline=_truthy(form.get("offline")),
        verify_tls=not _truthy(form.get("insecure")), ports=form.get("ports") or "",
        wordlist=form.get("wordlist") or "", max_items=int(num("max_items", 0)),
        active=True, authorized=_truthy(form.get("authorized")),
        extra={"time_based": "1"} if _truthy(form.get("time_based")) else {})
    job = jobs.start_tool(tool_id, target, options)
    return RedirectResponse(url=f"/job/{job.id}", status_code=303)


async def job_page(request: Request):
    job = _job_or_404(request.path_params["job_id"])
    if job.state in ("queued", "running"):
        return templates.TemplateResponse(request, "progress.html", {"version": __version__, "job": job})
    if job.state in ("failed", "blocked"):
        return templates.TemplateResponse(request, "error.html", {"version": __version__, "job": job})
    return templates.TemplateResponse(request, "result.html", {
        "version": __version__, "job": job, "pdf_available": pdf.available(),
        "is_website": job.kind == "website"})


async def job_status(request: Request):
    return JSONResponse(_job_or_404(request.path_params["job_id"]).as_dict())


def _render_html(job) -> str:
    return html_report.render(job.result) if job.kind == "website" else generic.render(job.result)


async def report_html(request: Request):
    job = _finished_or_404(request.path_params["job_id"])
    return HTMLResponse(_render_html(job), headers={"Content-Security-Policy": REPORT_CSP})


async def report_json(request: Request):
    job = _finished_or_404(request.path_params["job_id"])
    body = jsonout.render(job.result) if job.kind == "website" else generic.render_json(job.result)
    return Response(body, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="webscan-{job.id}.json"'})


async def report_sarif(request: Request):
    job = _finished_or_404(request.path_params["job_id"])
    if job.kind != "website":
        raise HTTPException(status_code=404, detail="SARIF is available for website scans only")
    return Response(sarif.render(job.result), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="webscan-{job.id}.sarif.json"'})


async def report_pdf(request: Request):
    job = _finished_or_404(request.path_params["job_id"])
    try:
        directory = Path(tempfile.mkdtemp(prefix="webscan-pdf-"))
        output = pdf.html_to_pdf(_render_html(job), directory / f"webscan-{job.id}.pdf")
    except pdf.PdfUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return FileResponse(output, media_type="application/pdf", filename=output.name)


async def health(request: Request):
    return JSONResponse({"status": "ok", "version": __version__,
                         "tools": len(all_tools()) + 1, "jobs": len(jobs.recent(1000))})


# ---- HTTP request logger -------------------------------------------------
async def logger_page(request: Request):
    return templates.TemplateResponse(request, "logger.html",
                                      {"version": __version__, "tokens": logger.all()})


async def logger_create(request: Request):
    form = await request.form()
    entry = logger.create((form.get("label") or "").strip())
    return RedirectResponse(url=f"/logger/view/{entry.token}", status_code=303)


async def logger_view(request: Request):
    entry = logger.get(request.path_params["token"])
    if not entry:
        raise HTTPException(status_code=404, detail="unknown token")
    return templates.TemplateResponse(request, "logger_view.html", {"version": __version__, "entry": entry})


async def logger_api(request: Request):
    entry = logger.get(request.path_params["token"])
    if not entry:
        raise HTTPException(status_code=404, detail="unknown token")
    return JSONResponse({"token": entry.token, "label": entry.label,
                         "requests": [r.as_dict() for r in entry.requests]})


async def logger_capture(request: Request):
    token = request.path_params["token"]
    subpath = request.path_params.get("subpath", "")
    body = (await request.body()).decode("utf-8", "replace")
    recorded = logger.record(token, LoggedRequest(
        method=request.method, path="/" + subpath, query=request.url.query,
        headers=dict(request.headers), body=body,
        remote=request.client.host if request.client else "-"))
    if not recorded:
        raise HTTPException(status_code=404, detail="unknown logger token")
    return PlainTextResponse("ok")


def _job_or_404(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="unknown job id")
    return job


def _finished_or_404(job_id: str):
    job = _job_or_404(job_id)
    if job.state != "finished" or not job.result:
        raise HTTPException(status_code=409, detail=f"job is {job.state}")
    return job


def _tool_error(request: Request, tool_id: str, message: str):
    if tool_id == "website":
        card = WEBSITE_CARD
    else:
        card = next((c for c in _tool_cards() if c["id"] == tool_id), WEBSITE_CARD)
    return templates.TemplateResponse(request, "tool.html",
                                      {"version": __version__, "card": card, "error": message},
                                      status_code=400)


async def login(request: Request):
    token = auth.configured_token()
    if not token:
        return RedirectResponse(url="/", status_code=303)
    error = ""
    if request.method == "POST":
        form = await request.form()
        supplied = (form.get("token") or "").strip()
        import hmac as _hmac
        if supplied and _hmac.compare_digest(supplied, token):
            response = RedirectResponse(url="/", status_code=303)
            auth.set_auth_cookie(response, token, secure=request.url.scheme == "https")
            return response
        error = "Incorrect token."
    return templates.TemplateResponse(request, "login.html",
                                      {"version": __version__, "error": error})


_CAPTURE_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

routes = [
    Route("/", index),
    Route("/health", health),
    Route("/login", login, methods=["GET", "POST"]),
    Route("/tool/{tool_id}", tool_form),
    Route("/tool/{tool_id}", start, methods=["POST"]),
    Route("/job/{job_id}", job_page),
    Route("/api/job/{job_id}", job_status),
    Route("/job/{job_id}/report.html", report_html),
    Route("/job/{job_id}/report.json", report_json),
    Route("/job/{job_id}/report.sarif", report_sarif),
    Route("/job/{job_id}/report.pdf", report_pdf),
    Route("/logger", logger_page),
    Route("/logger", logger_create, methods=["POST"]),
    Route("/logger/view/{token}", logger_view),
    Route("/api/logger/{token}", logger_api),
    Route("/logger/{token}", logger_capture, methods=_CAPTURE_METHODS),
    Route("/logger/{token}/{subpath:path}", logger_capture, methods=_CAPTURE_METHODS),
]

app = Starlette(routes=routes, middleware=[Middleware(auth.AuthMiddleware)])
