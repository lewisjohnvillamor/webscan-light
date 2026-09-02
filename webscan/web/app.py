"""Starlette web app: tool launcher, runners, reports and request logger.

Deliberately built on Starlette alone (no FastAPI/pydantic) to keep the
self-hosted footprint small.
"""
from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from starlette.routing import Route
from starlette.templating import Jinja2Templates

from webscan import __version__
from webscan.core import database, history, notify, scope
from webscan.core import scheduler as scheduler_mod
from webscan.core.engine import ScanOptions
from webscan.core.http import normalize_target
from webscan.core.registry import load_checks
from webscan.report import generic, jsonout, pdf, sarif
from webscan.report import html as html_report
from webscan.tools.base import ToolOptions, all_tools, get_tool, load_tools

from . import auth
from .consent import ConsentMiddleware
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
    "code": "WEB", "active": False, "local_fs": False,
    "description": "Full 40-test light scan: headers, tech, CVEs, cookies, exposure and more.",
    "target_hint": "URL or hostname",
}


def _tool_cards() -> list[dict]:
    cards = [WEBSITE_CARD]
    for spec in all_tools():
        cards.append({
            "id": spec.id, "name": spec.name, "category": spec.category,
            "code": generic.TOOL_GLYPHS.get(spec.id, "WS"), "active": spec.active,
            "local_fs": spec.local_fs,
            "description": spec.description, "target_hint": spec.target_hint,
        })
    order = {"Recon": 0, "Vulnerability": 1, "Exploit": 2}
    cards.sort(key=lambda c: (order.get(c["category"], 9), c["name"]))
    return cards


def _truthy(value: str | None) -> bool:
    return str(value).lower() in ("true", "1", "on", "yes")


def _safe_next(value: str | None) -> str:
    """Only allow same-site absolute paths (blocks //evil.com and scheme://)."""
    value = (value or "/").strip()
    # Normalise backslashes (browsers treat \ as /) before validating.
    normalised = value.replace("\\", "/")
    if not normalised.startswith("/") or normalised.startswith("//") or "://" in normalised:
        return "/"
    return value


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
            timeout=num("timeout", 15.0), max_pages=int(num("max_items", 0)) or 15,
            delay=num("delay", 0.0), render=_truthy(form.get("render")),
            cookie=form.get("cookie") or ""))
        return RedirectResponse(url=f"/job/{job.id}", status_code=303)

    spec = get_tool(tool_id)
    if not spec:
        raise HTTPException(status_code=404, detail="unknown tool")
    if spec.local_fs:
        return _tool_error(request, tool_id,
                           "This tool reads the server's local filesystem and is disabled in the "
                           "web UI for safety. Run it from the CLI instead, e.g. "
                           f"`webscan run {tool_id} /path/to/project`.")
    options = ToolOptions(
        timeout=num("timeout", 10.0), offline=_truthy(form.get("offline")),
        verify_tls=not _truthy(form.get("insecure")), ports=form.get("ports") or "",
        wordlist=form.get("wordlist") or "", max_items=int(num("max_items", 0)),
        delay=num("delay", 0.0),
        active=True, authorized=_truthy(form.get("authorized")),
        render=_truthy(form.get("render")), cookie=form.get("cookie") or "",
        extra={"time_based": "1"} if _truthy(form.get("time_based")) else {})
    cached = _reuse(request, tool_id, target, form)
    if cached:
        return cached
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


class _StoredJob:
    """A job-like view over a persisted scan, for the result page after reuse/restart."""
    def __init__(self, row: dict):
        import json as _json
        self.id = row["id"]
        self.tool_id = row["tool_id"]
        self.tool_name = row["tool_name"]
        self.target = row["target"]
        self.kind = row["kind"]
        self.state = "finished"
        counts = _json.loads(row.get("rating_counts") or "{}")
        self.summary = {"overall_risk": row["overall_risk"], "rating_counts": counts,
                        "findings": row["findings_count"], "duration_seconds": row["duration"]}


async def stored_result(request: Request):
    row = _stored_or_404(request.path_params["scan_id"])
    return templates.TemplateResponse(request, "result.html", {
        "version": __version__, "job": _StoredJob(row), "pdf_available": pdf.available(),
        "is_website": row["kind"] == "website",
        "cached": request.query_params.get("cached") == "1"})


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


def _scan_ttl() -> int:
    try:
        return int(os.environ.get("WEBSCAN_SCAN_TTL", "600"))
    except ValueError:
        return 600


def _reuse(request: Request, tool_id: str, target: str, form):
    """Serve a recent identical scan instead of re-running, unless forced."""
    ttl = _scan_ttl()
    if ttl <= 0 or _truthy(form.get("force")):
        return None
    row = database.recent_scan(tool_id, target, ttl)
    if row:
        return RedirectResponse(url=f"/stored/{row['id']}?cached=1", status_code=303)
    return None


def _tool_error(request: Request, tool_id: str, message: str):
    if tool_id == "website":
        card = WEBSITE_CARD
    else:
        card = next((c for c in _tool_cards() if c["id"] == tool_id), WEBSITE_CARD)
    return templates.TemplateResponse(request, "tool.html",
                                      {"version": __version__, "card": card, "error": message},
                                      status_code=400)


def _parse_duration(text: str) -> int:
    text = (text or "").strip().lower()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if text and text[-1] in units and text[:-1].replace(".", "", 1).isdigit():
        return max(60, int(float(text[:-1]) * units[text[-1]]))
    if text.isdigit():
        return max(60, int(text))
    return 86400  # default daily


async def schedules_page(request: Request):
    rows = scheduler_mod.database.list_schedules()
    return templates.TemplateResponse(request, "schedules.html", {
        "version": __version__, "schedules": rows, "cards": _tool_cards(),
        "channels": notify.channels_configured()})


async def schedule_add(request: Request):
    form = await request.form()
    tool_id = (form.get("tool_id") or "").strip()
    target = (form.get("target") or "").strip()
    every = _parse_duration(form.get("every") or "1d")
    if not target or not (tool_id == "website" or get_tool(tool_id)):
        raise HTTPException(status_code=400, detail="tool and target are required")
    allowed, reason = scope.check(target)
    if not allowed:
        raise HTTPException(status_code=400, detail=f"blocked: {reason}")
    scheduler_mod.add_schedule(tool_id, target, every,
                               {"authorized": _truthy(form.get("authorized"))})
    return RedirectResponse(url="/schedules", status_code=303)


async def schedule_monitor(request: Request):
    form = await request.form()
    target = (form.get("target") or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="a domain is required")
    allowed, reason = scope.check(target)
    if not allowed:
        raise HTTPException(status_code=400, detail=f"blocked: {reason}")
    scheduler_mod.add_schedule("asm", target, 86400, {"authorized": True})
    return RedirectResponse(url="/schedules", status_code=303)


async def schedule_delete(request: Request):
    scheduler_mod.database.delete_schedule(request.path_params["schedule_id"])
    return RedirectResponse(url="/schedules", status_code=303)


async def schedule_run(request: Request):
    sched = scheduler_mod.database.get_schedule(request.path_params["schedule_id"])
    if sched:
        scheduler_mod.database.update_schedule_run(
            sched["id"], sched["last_run"] or "", scheduler_mod._now().isoformat(),
            sched["last_scan_id"])
        scheduler_mod.run_due()
    return RedirectResponse(url="/schedules", status_code=303)


async def history_page(request: Request):
    q = request.query_params.get("q", "").strip()
    scans = history.list_scans(limit=200, target=q or None)
    return templates.TemplateResponse(request, "history.html",
                                      {"version": __version__, "scans": scans, "q": q})


def _stored_or_404(scan_id: str) -> dict:
    row = history.get_scan(scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="unknown report id")
    return row


async def stored_html(request: Request):
    row = _stored_or_404(request.path_params["scan_id"])
    return HTMLResponse(row["html"] or "", headers={"Content-Security-Policy": REPORT_CSP})


async def stored_json(request: Request):
    row = _stored_or_404(request.path_params["scan_id"])
    name = row["id"]
    return Response(row["json"] or "{}", media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="webscan-{name}.json"'})


async def stored_sarif(request: Request):
    row = _stored_or_404(request.path_params["scan_id"])
    if not row["sarif"]:
        raise HTTPException(status_code=404, detail="SARIF is available for website scans only")
    name = row["id"]
    return Response(row["sarif"], media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="webscan-{name}.sarif.json"'})


async def stored_pdf(request: Request):
    row = _stored_or_404(request.path_params["scan_id"])
    try:
        directory = Path(tempfile.mkdtemp(prefix="webscan-pdf-"))
        output = pdf.html_to_pdf(row["html"] or "", directory / f"webscan-{row['id']}.pdf")
    except pdf.PdfUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return FileResponse(output, media_type="application/pdf", filename=output.name)


async def stored_badge(request: Request):
    import json as _json

    from webscan.report import badge, scoring
    row = _stored_or_404(request.path_params["scan_id"])
    letter, _ = scoring.grade_from_counts(_json.loads(row["rating_counts"] or "{}"))
    return Response(badge.grade_badge(letter), media_type="image/svg+xml",
                    headers={"Cache-Control": "no-cache"})


async def stored_compliance(request: Request):
    from webscan.report import compliance
    row = _stored_or_404(request.path_params["scan_id"])
    return HTMLResponse(compliance.render(row), headers={"Content-Security-Policy": REPORT_CSP})


CONSENT_COOKIE = "webscan_consent"


async def consent(request: Request):
    if request.method == "POST":
        nxt = _safe_next((await request.form()).get("next"))
        response = RedirectResponse(url=nxt, status_code=303)
        response.set_cookie(CONSENT_COOKIE, "1", max_age=60 * 60 * 24 * 365,
                            httponly=True, samesite="lax", path="/")
        return response
    return templates.TemplateResponse(request, "consent.html",
                                      {"version": __version__,
                                       "next": request.query_params.get("next", "/")})


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
    Route("/consent", consent, methods=["GET", "POST"]),
    Route("/history", history_page),
    Route("/schedules", schedules_page),
    Route("/schedules", schedule_add, methods=["POST"]),
    Route("/schedules/monitor", schedule_monitor, methods=["POST"]),
    Route("/schedules/{schedule_id}/delete", schedule_delete, methods=["POST"]),
    Route("/schedules/{schedule_id}/run", schedule_run, methods=["POST"]),
    Route("/report/{scan_id}.json", stored_json),
    Route("/report/{scan_id}.sarif", stored_sarif),
    Route("/report/{scan_id}.pdf", stored_pdf),
    Route("/report/{scan_id}/badge.svg", stored_badge),
    Route("/report/{scan_id}/compliance", stored_compliance),
    Route("/report/{scan_id}", stored_html),
    Route("/tool/{tool_id}", tool_form),
    Route("/tool/{tool_id}", start, methods=["POST"]),
    Route("/job/{job_id}", job_page),
    Route("/stored/{scan_id}", stored_result),
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

_scheduler = scheduler_mod.Scheduler()


@contextlib.asynccontextmanager
async def _lifespan(app):
    if os.environ.get("WEBSCAN_NO_SCHEDULER", "").lower() not in ("1", "true", "yes", "on"):
        _scheduler.start()
    try:
        yield
    finally:
        _scheduler.stop()


app = Starlette(routes=routes, middleware=[Middleware(auth.AuthMiddleware), Middleware(ConsentMiddleware)],
                lifespan=_lifespan)
