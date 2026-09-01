"""URL fuzzer: brute-force directories and files, report interesting responses."""
from __future__ import annotations

import concurrent.futures

from webscan.core.http import HttpClient, normalize_target
from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.toolreport import Section, ToolReport

from .base import ToolOptions, tool
from .wordlists import DIRECTORIES, load_words

SENSITIVE = {".env", ".git/config", ".git", "wp-config.php.bak", "config.php", "backup.sql",
             "dump.sql", ".htpasswd", "web.config", ".DS_Store", "phpinfo.php", "server-status",
             ".svn", "composer.lock", "docker-compose.yml", "Dockerfile", "database", "backup"}


@tool(id="urlfuzzer", name="URL Fuzzer", category="Recon", glyph="🗂", order=60,
      target_hint="base URL (e.g. https://example.com)", active=True,
      description="Brute-force hidden directories and files using a wordlist.")
def run(target: str, options: ToolOptions) -> ToolReport:
    base = normalize_target(target).rstrip("/")
    report = ToolReport(tool="urlfuzzer", tool_name="URL Fuzzer", target=base)
    words = load_words(DIRECTORIES, options.wordlist)
    if options.max_items:
        words = words[: options.max_items]
    report.params = [("Base URL", base), ("Paths tested", str(len(words)))]

    client = HttpClient(timeout=options.timeout, verify_tls=options.verify_tls, delay=options.delay)
    # Calibrate against a random path so we can recognise soft-404s.
    baseline = client.get(f"{base}/webscan-not-there-{abs(hash(base)) % 99999}")
    soft404_len = len(baseline.text) if baseline.ok and baseline.status_code == 200 else -1

    rows: list[list[str]] = []

    def probe(path: str):
        url = f"{base}/{path}"
        resp = client.get(url, allow_redirects=False)
        if not resp.ok:
            return None
        code = resp.status_code
        if code in (200, 201, 204, 301, 302, 307, 401, 403, 405, 500):
            if code == 200 and soft404_len > 0 and abs(len(resp.text) - soft404_len) < 32:
                return None  # looks like the catch-all page
            return [path, str(code), str(len(resp.content)),
                    resp.header("Location") or resp.header("Content-Type") or "-"]
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(10, options.workers)) as pool:
        for result in pool.map(probe, words):
            if result:
                rows.append(result)

    rows.sort(key=lambda r: (r[0]))
    report.sections.append(Section(
        title=f"Discovered paths ({len(rows)})",
        intro="Nothing notable responded." if not rows else "",
        table=Table(columns=["Path", "Status", "Size", "Location / Type"], rows=rows),
    ))
    report.stats = [("Paths tested", str(len(words))), ("Hits", str(len(rows))),
                    ("HTTP requests", str(client.request_count))]

    for path, code, *_ in rows:
        base_path = path.split("?")[0]
        if base_path in SENSITIVE and code in ("200", "301", "302", "403"):
            sev = Severity.HIGH if code == "200" else Severity.MEDIUM
            report.findings.append(Finding(
                test_id=f"fuzz_{base_path}", title=f"Sensitive path exposed: /{path} ({code})",
                severity=sev, confidence=Confidence.CONFIRMED,
                table=Table(columns=["Path", "Status"], rows=[[f"/{path}", code]]),
                risk_description="This path commonly holds secrets, source control data or "
                                 "backups. Even a 403 confirms it exists and may be reachable "
                                 "through path tricks.",
                recommendation="Remove the file from the web root or block access to it at the "
                               "web-server level.",
                classification=Classification(cwe=["CWE-538"]),
            ))
    return report.finish()
