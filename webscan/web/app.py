"""FastAPI application: tool launcher, runners, reports and request logger."""
from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.templating import Jinja2Templates

from webscan import __version__
from webscan.core.engine import ScanOptions
from webscan.core.http import normalize_target
from webscan.core.registry import all_checks, load_checks
from webscan.report import generic
from webscan.report import html as html_report
from webscan.report import jsonout, pdf, sarif
from webscan.tools.base import ToolOptions, all_tools, get_tool, load_tools

from .logger_store import LoggedRequest, LoggerStore
from .store import JobStore

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(title="webscan-light", version=__version__, docs_url="/api/docs")
jobs = JobStore()
logger = LoggerStore()

load_checks()
load_tools()

REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'"

# The website scanner presented alongside the tool cards.
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


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {
        "version": __version__, "cards": _tool_cards(), "recent": jobs.recent(),
        "categories": ["Recon", "Vulnerability", "Exploit"],
    })


@app.get("/tool/{tool_id}", response_class=HTMLResponse)
def tool_form(request: Request, tool_id: str):
    if tool_id == "website":
        card = WEBSITE_CARD
    else:
        spec = get_tool(tool_id)
        if not spec:
            raise HTTPException(status_code=404, detail="unknown tool")
        card = next(c for c in _tool_cards() if c["id"] == tool_id)
    return templates.TemplateResponse(request, "tool.html", {
        "version": __version__, "card": card,
    })


@app.post("/tool/{tool_id}")
def start(tool_id: str, target: str = Form(...), ports: str = Form(""),
          wordlist: str = Form(""), max_items: int = Form(0), timeout: float = Form(10.0),
          offline: bool = Form(False), insecure: bool = Form(False),
          authorized: bool = Form(False), time_based: bool = Form(False)):
    target = target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="a target is required")
    if tool_id == "website":
        try:
            normalize_target(target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        job = jobs.start_website(ScanOptions(
            target=target, offline=offline, verify_tls=not insecure,
            timeout=timeout or 15, max_pages=max_items or 15))
        return RedirectResponse(url=f"/job/{job.id}", status_code=303)

    if not get_tool(tool_id):
        raise HTTPException(status_code=404, detail="unknown tool")
    options = ToolOptions(
        timeout=timeout or 10, offline=offline, verify_tls=not insecure,
        ports=ports, wordlist=wordlist, max_items=max_items, active=True,
        authorized=authorized, extra={"time_based": "1"} if time_based else {})
    job = jobs.start_tool(tool_id, target, options)
    return RedirectResponse(url=f"/job/{job.id}", status_code=303)


@app.get("/job/{job_id}", response_class=HTMLResponse)
def job_page(request: Request, job_id: str):
    job = _job_or_404(job_id)
    if job.state in ("queued", "running"):
        return templates.TemplateResponse(request, "progress.html",
                                          {"version": __version__, "job": job})
    if job.state in ("failed", "blocked"):
        return templates.TemplateResponse(request, "error.html",
                                          {"version": __version__, "job": job})
    return templates.TemplateResponse(request, "result.html", {
        "version": __version__, "job": job, "pdf_available": pdf.available(),
        "is_website": job.kind == "website",
    })


@app.get("/api/job/{job_id}")
def job_status(job_id: str):
    return JSONResponse(_job_or_404(job_id).as_dict())


def _render_html(job) -> str:
    if job.kind == "website":
        return html_report.render(job.result)
    return generic.render(job.result)


@app.get("/job/{job_id}/report.html", response_class=HTMLResponse)
def report_html(job_id: str):
    job = _finished_or_404(job_id)
    return HTMLResponse(_render_html(job), headers={"Content-Security-Policy": REPORT_CSP})


@app.get("/job/{job_id}/report.json")
def report_json(job_id: str):
    job = _finished_or_404(job_id)
    body = jsonout.render(job.result) if job.kind == "website" else generic.render_json(job.result)
    return Response(body, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="webscan-{job_id}.json"'})


@app.get("/job/{job_id}/report.sarif")
def report_sarif(job_id: str):
    job = _finished_or_404(job_id)
    if job.kind != "website":
        raise HTTPException(status_code=404, detail="SARIF is available for website scans only")
    return Response(sarif.render(job.result), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="webscan-{job_id}.sarif.json"'})


@app.get("/job/{job_id}/report.pdf")
def report_pdf(job_id: str):
    job = _finished_or_404(job_id)
    try:
        directory = Path(tempfile.mkdtemp(prefix="webscan-pdf-"))
        output = pdf.html_to_pdf(_render_html(job), directory / f"webscan-{job_id}.pdf")
    except pdf.PdfUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return FileResponse(output, media_type="application/pdf", filename=output.name)


# ---- HTTP request logger -------------------------------------------------
@app.get("/logger", response_class=HTMLResponse)
def logger_page(request: Request):
    return templates.TemplateResponse(request, "logger.html", {
        "version": __version__, "tokens": logger.all(),
    })


@app.post("/logger")
def logger_create(label: str = Form("")):
    entry = logger.create(label.strip())
    return RedirectResponse(url=f"/logger/view/{entry.token}", status_code=303)


@app.get("/logger/view/{token}", response_class=HTMLResponse)
def logger_view(request: Request, token: str):
    entry = logger.get(token)
    if not entry:
        raise HTTPException(status_code=404, detail="unknown token")
    return templates.TemplateResponse(request, "logger_view.html", {
        "version": __version__, "entry": entry,
    })


@app.get("/api/logger/{token}")
def logger_api(token: str):
    entry = logger.get(token)
    if not entry:
        raise HTTPException(status_code=404, detail="unknown token")
    return JSONResponse({"token": token, "label": entry.label,
                         "requests": [r.as_dict() for r in entry.requests]})


async def _capture(request: Request, token: str, subpath: str) -> Response:
    body = (await request.body()).decode("utf-8", "replace")
    recorded = logger.record(token, LoggedRequest(
        method=request.method, path="/" + subpath, query=request.url.query,
        headers={k: v for k, v in request.headers.items()}, body=body,
        remote=request.client.host if request.client else "-",
    ))
    if not recorded:
        raise HTTPException(status_code=404, detail="unknown logger token")
    return PlainTextResponse("ok")


@app.api_route("/logger/{token}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def logger_capture_root(request: Request, token: str):
    return await _capture(request, token, "")


@app.api_route("/logger/{token}/{subpath:path}",
               methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def logger_capture(request: Request, token: str, subpath: str):
    return await _capture(request, token, subpath)


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
