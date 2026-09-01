"""Scan orchestration."""
from __future__ import annotations

import concurrent.futures
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from webscan.intel.feeds import Intel

from . import tlsinfo
from .context import ScanContext
from .http import HttpClient, default_port, normalize_target
from .models import ScanResult, ScanStats
from .registry import all_checks, load_checks
from .spider import crawl

log = logging.getLogger("webscan")

ProgressHook = Callable[[str, int, int], None]


@dataclass
class ScanOptions:
    target: str
    max_pages: int = 15
    max_depth: int = 2
    timeout: float = 15.0
    workers: int = 8
    verify_tls: bool = True
    offline: bool = False
    min_cvss: float = 0.0
    user_agent: str | None = None
    extra_headers: dict[str, str] = field(default_factory=dict)
    only: list[str] = field(default_factory=list)
    skip: list[str] = field(default_factory=list)


def run_scan(options: ScanOptions, progress: ProgressHook | None = None) -> ScanResult:
    load_checks()
    target = normalize_target(options.target)
    result = ScanResult(target=target, ports=[default_port(target).split("/")[0]])

    client_kwargs = {
        "timeout": options.timeout,
        "verify_tls": options.verify_tls,
        "extra_headers": options.extra_headers,
    }
    if options.user_agent:
        client_kwargs["user_agent"] = options.user_agent
    client = HttpClient(**client_kwargs)

    def report(stage: str, done: int, total: int) -> None:
        if progress:
            progress(stage, done, total)

    report("Crawling", 0, 1)
    crawl_result = crawl(client, target, max_pages=options.max_pages, max_depth=options.max_depth)
    if not crawl_result.pages:
        probe = client.get(target)
        result.status = "Failed"
        result.finish_time = datetime.now(timezone.utc)
        result.errors.append(
            f"Could not fetch {target}: {probe.error or f'HTTP {probe.status_code}'}"
        )
        return result

    report("Inspecting TLS", 0, 1)
    tls = tlsinfo.inspect(target, timeout=options.timeout)

    intel = Intel(offline=options.offline)
    context = ScanContext(
        target=target,
        client=client,
        crawl=crawl_result,
        tls=tls,
        shared={"intel": intel, "min_cvss": options.min_cvss},
    )

    checks = all_checks()
    if options.only:
        checks = [spec for spec in checks if spec.test_id in options.only]
    if options.skip:
        checks = [spec for spec in checks if spec.test_id not in options.skip]

    result.tests_performed = [spec.description for spec in checks]
    total = len(checks)
    completed = 0
    report("Running checks", 0, total)

    # The CVE lookup is rate-limited and must not be run concurrently with itself,
    # so it runs first on its own; the rest are independent and run in parallel.
    ordered = sorted(checks, key=lambda spec: spec.order)
    findings_by_id: dict[str, list] = {}

    serial = [spec for spec in ordered if spec.test_id in ("technologies", "version_vulns")]
    parallel = [spec for spec in ordered if spec not in serial]

    for spec in serial:
        findings_by_id[spec.test_id] = _run_check(spec, context, result)
        completed += 1
        report(spec.test_id, completed, total)

    with concurrent.futures.ThreadPoolExecutor(max_workers=options.workers) as pool:
        futures = {pool.submit(_run_check, spec, context, result): spec for spec in parallel}
        for future in concurrent.futures.as_completed(futures):
            spec = futures[future]
            findings_by_id[spec.test_id] = future.result()
            completed += 1
            report(spec.test_id, completed, total)

    for spec in ordered:
        result.findings.extend(findings_by_id.get(spec.test_id, []))

    result.errors.extend(intel.errors)
    result.stats = ScanStats(
        unique_injection_points=len(crawl_result.injection_points),
        urls_spidered=len(crawl_result.pages),
        http_requests=client.request_count,
        average_response_ms=client.average_response_ms,
    )
    result.finish_time = datetime.now(timezone.utc)
    result.status = "Finished"
    return result


def _run_check(spec, context: ScanContext, result: ScanResult) -> list:
    """Run one check; a failing check is recorded but never aborts the scan."""
    try:
        return list(spec.func(context) or [])
    except Exception as exc:  # noqa: BLE001 - isolate third-party/site weirdness
        log.warning("check %s failed: %s", spec.test_id, exc, exc_info=True)
        result.errors.append(f"Check '{spec.test_id}' failed: {type(exc).__name__}: {exc}")
        return []
