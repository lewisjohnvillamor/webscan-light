"""FastAPI application serving the local web UI."""
from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from fastapi.templating import Jinja2Templates

from webscan import __version__
from webscan.core.engine import ScanOptions
from webscan.core.http import normalize_target
from webscan.core.registry import all_checks, load_checks
from webscan.report import html as html_report
from webscan.report import jsonout, pdf, sarif

from .store import ScanStore

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(title="webscan-light", version=__version__, docs_url="/api/docs")
store = ScanStore()

load_checks()


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "version": __version__,
            "tests": all_checks(),
            "recent": store.recent(10),
            "pdf_available": pdf.available(),
        },
    )


@app.post("/scan")
def start_scan(
    target: str = Form(...),
    max_pages: int = Form(15),
    max_depth: int = Form(2),
    min_cvss: float = Form(0.0),
    offline: bool = Form(False),
    insecure: bool = Form(False),
):
    try:
        normalize_target(target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    options = ScanOptions(
        target=target,
        max_pages=max(1, min(max_pages, 100)),
        max_depth=max(0, min(max_depth, 4)),
        min_cvss=min_cvss,
        offline=offline,
        verify_tls=not insecure,
    )
    job = store.start(options)
    return RedirectResponse(url=f"/scan/{job.id}", status_code=303)


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
def scan_page(request: Request, scan_id: str):
    job = _job_or_404(scan_id)
    if job.state in ("queued", "running"):
        return templates.TemplateResponse(
            request, "progress.html", {"job": job, "version": __version__}
        )
    if job.state == "failed":
        return templates.TemplateResponse(
            request, "error.html", {"job": job, "version": __version__}
        )
    return templates.TemplateResponse(
        request,
        "result.html",
        {"job": job, "version": __version__, "pdf_available": pdf.available()},
    )


@app.get("/api/scan/{scan_id}")
def scan_status(scan_id: str):
    return JSONResponse(_job_or_404(scan_id).as_dict())


# The report embeds text taken from the scanned site. It is escaped on render, and
# this policy is the second line of defence should anything slip through.
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'"


@app.get("/scan/{scan_id}/report.html", response_class=HTMLResponse)
def report_html(scan_id: str, exchanges: bool = False):
    job = _finished_or_404(scan_id)
    return HTMLResponse(
        html_report.render(job.result, include_exchanges=exchanges),
        headers={"Content-Security-Policy": REPORT_CSP},
    )


@app.get("/scan/{scan_id}/report.json")
def report_json(scan_id: str):
    job = _finished_or_404(scan_id)
    return Response(
        content=jsonout.render(job.result),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="webscan-{scan_id}.json"'},
    )


@app.get("/scan/{scan_id}/report.sarif")
def report_sarif(scan_id: str):
    job = _finished_or_404(scan_id)
    return Response(
        content=sarif.render(job.result),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="webscan-{scan_id}.sarif.json"'},
    )


@app.get("/scan/{scan_id}/report.pdf")
def report_pdf(scan_id: str, exchanges: bool = False):
    job = _finished_or_404(scan_id)
    try:
        directory = Path(tempfile.mkdtemp(prefix="webscan-pdf-"))
        output = pdf.write(job.result, directory / f"webscan-{scan_id}.pdf",
                           include_exchanges=exchanges)
    except pdf.PdfUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return FileResponse(output, media_type="application/pdf", filename=output.name)


def _job_or_404(scan_id: str):
    job = store.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="unknown scan id")
    return job


def _finished_or_404(scan_id: str):
    job = _job_or_404(scan_id)
    if job.state != "finished" or not job.result:
        raise HTTPException(status_code=409, detail=f"scan is {job.state}")
    return job
