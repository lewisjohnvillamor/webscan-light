"""Command line interface."""
from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from webscan import __version__
from webscan.core.engine import ScanOptions, run_scan
from webscan.core.models import ScanResult, Severity
from webscan.core.registry import all_checks, load_checks
from webscan.report import html as html_report
from webscan.report import jsonout, pdf, sarif

SEVERITY_BY_NAME = {s.name.lower(): s for s in Severity}

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webscan",
        description="webscan-light — a free, self-hosted website vulnerability scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  webscan scan example.com\n"
            "  webscan scan https://example.com -f html -o report.html --open\n"
            "  webscan scan example.com -f pdf -o report.pdf\n"
            "  webscan scan example.com -f json --fail-on high\n"
            "  webscan serve --port 8000\n"
            "  webscan list-tests\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"webscan-light {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan a website and produce a report")
    scan.add_argument("target", help="URL or hostname to scan")
    scan.add_argument("-f", "--format", default="terminal",
                      choices=["terminal", "html", "pdf", "json", "sarif"],
                      help="report format (default: terminal)")
    scan.add_argument("-o", "--output", help="write the report to this path")
    scan.add_argument("--open", action="store_true", dest="open_report",
                      help="open the generated report in the default application")
    scan.add_argument("--max-pages", type=int, default=15, help="pages to crawl (default: 15)")
    scan.add_argument("--max-depth", type=int, default=2, help="crawl depth (default: 2)")
    scan.add_argument("--timeout", type=float, default=15.0, help="per-request timeout in seconds")
    scan.add_argument("--workers", type=int, default=8, help="parallel checks (default: 8)")
    scan.add_argument("--insecure", action="store_true",
                      help="do not verify the target's TLS certificate")
    scan.add_argument("--offline", action="store_true",
                      help="skip online CVE/EPSS/KEV lookups and use only cached data")
    scan.add_argument("--min-cvss", type=float, default=0.0,
                      help="ignore CVEs scoring below this value (default: 0)")
    scan.add_argument("--user-agent", help="override the User-Agent header")
    scan.add_argument("-H", "--header", action="append", default=[], metavar="'Name: value'",
                      help="extra request header; repeatable (e.g. a session cookie)")
    scan.add_argument("--only", default="", metavar="IDS",
                      help="comma-separated test ids to run exclusively")
    scan.add_argument("--skip", default="", metavar="IDS",
                      help="comma-separated test ids to skip")
    scan.add_argument("--include-exchanges", action="store_true",
                      help="embed raw request/response pairs in HTML and PDF reports")
    scan.add_argument("--fail-on", choices=list(SEVERITY_BY_NAME), metavar="SEVERITY",
                      help="exit with status 2 if a finding at or above this severity is found")
    scan.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    scan.add_argument("-v", "--verbose", action="store_true", help="log check failures in detail")

    serve = subparsers.add_parser("serve", help="run the local web UI")
    serve.add_argument("--host", default="127.0.0.1",
                       help="bind address (default: 127.0.0.1, loopback only)")
    serve.add_argument("--port", type=int, default=8000, help="port (default: 8000)")
    serve.add_argument("--reload", action="store_true", help="auto-reload on code changes")

    subparsers.add_parser("list-tests", help="list every test the website scanner performs")
    subparsers.add_parser("tools", help="list every tool in the suite")

    run_p = subparsers.add_parser("run", help="run a specific tool (see 'webscan tools')")
    run_p.add_argument("tool", help="tool id, e.g. ssl, ports, subdomains, xss")
    run_p.add_argument("target", help="URL, hostname, IP or CIDR (depends on the tool)")
    run_p.add_argument("-f", "--format", default="terminal",
                       choices=["terminal", "html", "pdf", "json"], help="report format")
    run_p.add_argument("-o", "--output", help="write the report to this path")
    run_p.add_argument("--open", action="store_true", dest="open_report",
                       help="open the generated report")
    run_p.add_argument("--ports", default="", help="ports for port/network scans (top100|top1000|1-1024|80,443)")
    run_p.add_argument("--wordlist", default="", help="custom wordlist for fuzz/subdomain tools")
    run_p.add_argument("--max-items", type=int, default=0, help="cap results / crawl breadth")
    run_p.add_argument("--timeout", type=float, default=10.0, help="per-request timeout")
    run_p.add_argument("--workers", type=int, default=40, help="parallel workers")
    run_p.add_argument("--offline", action="store_true", help="skip online lookups")
    run_p.add_argument("--insecure", action="store_true", help="do not verify TLS")
    run_p.add_argument("--authorized", action="store_true",
                       help="confirm you are permitted to actively test this target (xss, sqli)")
    run_p.add_argument("--time-based", action="store_true", help="enable time-based SQLi probe")
    run_p.add_argument("--fail-on", choices=list(SEVERITY_BY_NAME), metavar="SEVERITY",
                       help="exit 2 if a finding at or above this severity is found")
    run_p.add_argument("-q", "--quiet", action="store_true")

    hist = subparsers.add_parser("history", help="list stored scans")
    hist.add_argument("query", nargs="?", default="", help="filter by target substring")
    hist.add_argument("--limit", type=int, default=30, help="rows to show (default: 30)")

    update = subparsers.add_parser("update", help="pre-warm the CVE/EPSS/KEV cache")
    update.add_argument("software", nargs="*",
                        help="'vendor:product@version' pairs, e.g. f5:nginx@1.18.0")
    update.add_argument("--kev", action="store_true", help="refresh only the CISA KEV catalog")
    return parser


def _parse_headers(values: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for value in values:
        if ":" not in value:
            raise SystemExit(f"invalid --header value (expected 'Name: value'): {value}")
        name, _, content = value.partition(":")
        headers[name.strip()] = content.strip()
    return headers


def _default_output(target: str, extension: str) -> Path:
    host = urlparse(target if "://" in target else f"https://{target}").hostname or "scan"
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path(f"webscan-{host}-{stamp}.{extension}")


def cmd_list_tests() -> int:
    load_checks()
    specs = all_checks()
    width = max(len(spec.test_id) for spec in specs)
    print(f"webscan-light performs {len(specs)} tests:\n")
    for spec in specs:
        print(f"  {spec.test_id.ljust(width)}  {spec.description}")
    return 0


def cmd_tools() -> int:
    from webscan.tools.base import all_tools, load_tools
    load_tools()
    specs = all_tools()
    width = max(len(s.id) for s in specs)
    print(f"webscan-light suite — {len(specs)} tools (plus 'webscan scan' for the website scanner):\n")
    order = {"Recon": 0, "Vulnerability": 1, "Exploit": 2}
    specs = sorted(specs, key=lambda s: (order.get(s.category, 9), s.order, s.name))
    current = ""
    for spec in specs:
        if spec.category != current:
            current = spec.category
            print(f"  {current}:")
        flag = "  [active]" if spec.active else ""
        print(f"    {spec.id.ljust(width)}  {spec.name}{flag}")
        print(f"    {' '.ljust(width)}  {spec.description}")
    print("\n  Run one with:  webscan run <tool> <target>")
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    from webscan.core import history
    rows = history.list_scans(limit=args.limit, target=args.query or None)
    if not rows:
        print("No stored scans yet.")
        return 0
    print(f"{'DATE':<17} {'RISK':<9} {'FINDINGS':<9} {'TOOL':<20} TARGET")
    for r in rows:
        when = (r["created_at"] or "")[:16].replace("T", " ")
        print(f"{when:<17} {r['overall_risk']:<9} {str(r['findings_count']):<9} "
              f"{r['tool_name'][:20]:<20} {r['target']}")
    print(f"\n{len(rows)} scans. Open a full report with 'webscan serve' -> History.")
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    from webscan.intel.feeds import Intel
    intel = Intel()
    if args.kev or not args.software:
        count = len(intel.kev_ids())
        print(f"CISA KEV catalog refreshed: {count} entries cached.")
        if args.kev:
            return 0
    total = 0
    for pair in args.software:
        if "@" not in pair:
            print(f"skipping '{pair}' (expected vendor:product@version)", file=sys.stderr)
            continue
        vp, _, version = pair.partition("@")
        cves = intel.cves_for(vp, version)
        intel.enrich_epss(cves)
        intel.enrich_kev(cves)
        total += len(cves)
        print(f"  {pair}: {len(cves)} CVEs cached")
    if args.software:
        print(f"Done. {total} CVEs cached for {len(args.software)} products.")
    for error in intel.errors:
        print(f"note: {error}", file=sys.stderr)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    from webscan.report import generic
    from webscan.tools.base import ToolOptions, get_tool, load_tools
    load_tools()
    spec = get_tool(args.tool)
    if not spec:
        print(f"error: unknown tool '{args.tool}'. Run 'webscan tools' to list them.",
              file=sys.stderr)
        return 1

    options = ToolOptions(
        timeout=args.timeout, workers=args.workers, offline=args.offline,
        verify_tls=not args.insecure, ports=args.ports, wordlist=args.wordlist,
        max_items=args.max_items, active=True, authorized=args.authorized,
        extra={"time_based": "1"} if args.time_based else {},
    )
    if spec.active and not args.quiet and sys.stderr.isatty():
        print(f"  Running {spec.name} against {args.target} — only test systems you are "
              "authorised to.", file=sys.stderr)

    report = spec.func(args.target, options)
    if report.status == "Finished":
        try:
            from webscan.core import history
            history.record(report)
        except Exception:  # noqa: BLE001
            pass

    fmt = args.format
    if fmt == "terminal":
        _print_tool_terminal(report)
    else:
        extension = {"html": "html", "pdf": "pdf", "json": "json"}[fmt]
        if args.output:
            output = Path(args.output)
        elif fmt == "json" and not sys.stdout.isatty():
            print(generic.render_json(report))
            return _tool_exit(report, args)
        else:
            output = _default_output(f"{spec.id}-{report.target}", extension)
        if fmt == "html":
            generic.write(report, output)
        elif fmt == "json":
            output.write_text(generic.render_json(report), encoding="utf-8")
        else:
            try:
                pdf.html_to_pdf(generic.render(report), output)
            except pdf.PdfUnavailable as exc:
                print(f"error: {exc}", file=sys.stderr)
                fallback = output.with_suffix(".html")
                generic.write(report, fallback)
                print(f"wrote HTML instead: {fallback}", file=sys.stderr)
                return _tool_exit(report, args)
        print(f"report written to {output}")
        if args.open_report:
            _open(output)
    return _tool_exit(report, args)


def _tool_exit(report, args) -> int:
    if report.status in ("Failed", "Blocked"):
        for error in report.errors:
            print(f"note: {error}", file=sys.stderr)
        return 1 if report.status == "Failed" else 0
    if getattr(args, "fail_on", None):
        threshold = SEVERITY_BY_NAME[args.fail_on]
        if any(f.severity >= threshold for f in report.findings):
            return 2
    return 0


def _print_tool_terminal(report) -> None:
    try:
        from rich.console import Console
        from rich.table import Table as RichTable
    except ImportError:
        print(f"\n{report.tool_name} — {report.target}  [{report.status}]")
        for f in report.sorted_findings:
            print(f"  [{f.severity.label.upper()}] {f.title}")
        return
    console = Console()
    console.print()
    console.rule(f"[bold]{report.tool_name}[/] · {report.target}")
    style = SEVERITY_STYLE[report.overall_risk]
    console.print(f"  Overall risk: [{style}]{report.overall_risk.label}[/]  "
                  f"· {len(report.findings)} findings · {report.duration_seconds}s\n")
    for section in report.sections:
        if section.table and section.table.rows:
            table = RichTable(title=section.title, title_justify="left", header_style="bold",
                              show_lines=False)
            for column in section.table.columns:
                table.add_column(column)
            for row in section.table.rows[:40]:
                table.add_row(*[str(c)[:80] for c in row])
            console.print(table)
        elif section.kv:
            console.print(f"[bold]{section.title}[/]")
            for k, v in section.kv:
                console.print(f"  {k}: {v}")
        console.print()
    if report.findings:
        table = RichTable(title="Findings", title_justify="left", header_style="bold")
        table.add_column("Risk", no_wrap=True)
        table.add_column("Finding")
        for f in report.sorted_findings:
            table.add_row(f"[{SEVERITY_STYLE[f.severity]}]{f.severity.label}[/]", f.title)
        console.print(table)
    for error in report.errors:
        console.print(f"  [yellow]note:[/] {error}")
    console.print()


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        print("The web UI needs starlette and uvicorn:\n  pip install 'webscan-light[web]'",
              file=sys.stderr)
        return 1
    reload = args.reload
    if reload:
        try:
            import watchfiles  # noqa: F401
        except ImportError:
            print("note: --reload needs watchfiles (pip install watchfiles); starting without it",
                  file=sys.stderr)
            reload = False
    import os
    exposed = args.host not in ("127.0.0.1", "localhost", "::1")
    if exposed and not os.environ.get("WEBSCAN_TOKEN", "").strip():
        print("WARNING: binding to a non-loopback address without WEBSCAN_TOKEN set.\n"
              "         Anyone who can reach this port can drive scans from your server.\n"
              "         Set WEBSCAN_TOKEN=<secret> to require authentication.", file=sys.stderr)
    if exposed and os.environ.get("WEBSCAN_ALLOW_PRIVATE", "").lower() in ("1", "true", "yes", "on"):
        print("WARNING: WEBSCAN_ALLOW_PRIVATE is on and the server is exposed — targets may "
              "include your internal network.", file=sys.stderr)
    print(f"webscan-light UI -> http://{args.host}:{args.port}")
    uvicorn.run("webscan.web.app:app", host=args.host, port=args.port,
                reload=reload, log_level="info")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    options = ScanOptions(
        target=args.target,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        timeout=args.timeout,
        workers=args.workers,
        verify_tls=not args.insecure,
        offline=args.offline,
        min_cvss=args.min_cvss,
        user_agent=args.user_agent,
        extra_headers=_parse_headers(args.header),
        only=[i.strip() for i in args.only.split(",") if i.strip()],
        skip=[i.strip() for i in args.skip.split(",") if i.strip()],
    )

    progress = None if args.quiet else _make_progress()
    try:
        result = run_scan(options, progress=progress)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if progress:
            progress("done", 0, 0)

    try:
        from webscan.core import history
        history.record(result)
    except Exception:  # noqa: BLE001
        pass

    _emit(result, args)

    if result.status == "Failed":
        for error in result.errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    if args.fail_on:
        threshold = SEVERITY_BY_NAME[args.fail_on]
        if any(finding.severity >= threshold for finding in result.findings):
            return 2
    return 0


def _make_progress():
    """A one-line progress indicator that stays quiet when not on a terminal."""
    state = {"last": 0}
    is_tty = sys.stderr.isatty()

    def progress(stage: str, done: int, total: int) -> None:
        if stage == "done":
            if is_tty:
                print("\r" + " " * 70 + "\r", end="", file=sys.stderr)
            return
        if not is_tty:
            return
        if total and done != state["last"]:
            state["last"] = done
            bar_width = 24
            filled = int(bar_width * done / total)
            bar = "█" * filled + "░" * (bar_width - filled)
            print(f"\r  [{bar}] {done}/{total} checks", end="", file=sys.stderr, flush=True)
        elif not total:
            print(f"\r  {stage}…".ljust(60), end="", file=sys.stderr, flush=True)

    return progress


def _emit(result: ScanResult, args: argparse.Namespace) -> None:
    fmt = args.format
    if fmt == "terminal":
        _print_terminal(result)
        return

    extension = {"html": "html", "pdf": "pdf", "json": "json", "sarif": "sarif.json"}[fmt]
    if args.output:
        output = Path(args.output)
    elif fmt in ("json", "sarif") and not sys.stdout.isatty():
        # Piped machine-readable output goes to stdout.
        print(jsonout.render(result) if fmt == "json" else sarif.render(result))
        return
    else:
        output = _default_output(result.target, extension)

    if fmt == "html":
        html_report.write(result, output, include_exchanges=args.include_exchanges)
    elif fmt == "json":
        jsonout.write(result, output)
    elif fmt == "sarif":
        sarif.write(result, output)
    else:
        try:
            pdf.write(result, output, include_exchanges=args.include_exchanges)
        except pdf.PdfUnavailable as exc:
            print(f"error: {exc}", file=sys.stderr)
            fallback = output.with_suffix(".html")
            html_report.write(result, fallback, include_exchanges=args.include_exchanges)
            print(f"wrote HTML instead: {fallback}", file=sys.stderr)
            return

    print(f"report written to {output}")
    if args.open_report:
        _open(output)


def _open(path: Path) -> None:
    import subprocess
    opener = {"darwin": "open", "win32": "start"}.get(sys.platform, "xdg-open")
    try:
        subprocess.run([opener, str(path)], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        pass


def _print_terminal(result: ScanResult) -> None:
    try:
        from rich.console import Console
        from rich.table import Table as RichTable
    except ImportError:
        _print_plain(result)
        return

    console = Console()
    console.print()
    console.rule(f"[bold]Website Vulnerability Scanner Report ({result.scan_type})")
    console.print(f"  [bold]{result.target}[/]\n")

    summary = RichTable.grid(padding=(0, 3))
    summary.add_column()
    summary.add_column()
    style = SEVERITY_STYLE[result.overall_risk]
    summary.add_row("Overall risk level", f"[{style}]{result.overall_risk.label}[/]")
    for name, count in result.rating_counts.items():
        severity = SEVERITY_BY_NAME[name.lower()]
        value = f"[{SEVERITY_STYLE[severity]}]{count}[/]" if count else str(count)
        summary.add_row(f"  {name}", value)
    summary.add_row("Scan duration", f"{result.duration_seconds} sec")
    summary.add_row("Tests performed", str(len(result.tests_performed)))
    summary.add_row("URLs spidered", str(result.stats.urls_spidered))
    summary.add_row("HTTP requests", str(result.stats.http_requests))
    summary.add_row("Scan status", result.status)
    console.print(summary)

    if result.findings:
        console.print()
        table = RichTable(title="Findings", title_justify="left", header_style="bold")
        table.add_column("Risk", no_wrap=True)
        table.add_column("Finding")
        table.add_column("Confidence", no_wrap=True)
        for finding in result.sorted_findings:
            table.add_row(
                f"[{SEVERITY_STYLE[finding.severity]}]{finding.severity.label}[/]",
                finding.title,
                finding.confidence.value.title(),
            )
        console.print(table)
        console.print(
            "\n  Run with [bold]-f html -o report.html[/] for the full report "
            "with evidence, recommendations and references."
        )
    else:
        console.print("\n  [green]No issues identified.[/]")

    for error in result.errors:
        console.print(f"  [yellow]note:[/] {error}")
    console.print()


def _print_plain(result: ScanResult) -> None:
    print(f"\nWebsite Vulnerability Scanner Report ({result.scan_type})")
    print(f"  {result.target}\n")
    print(f"  Overall risk level : {result.overall_risk.label}")
    for name, count in result.rating_counts.items():
        print(f"    {name:<9}: {count}")
    print(f"  Duration           : {result.duration_seconds} sec")
    print(f"  Tests performed    : {len(result.tests_performed)}")
    print(f"  Status             : {result.status}\n")
    for finding in result.sorted_findings:
        print(f"  [{finding.severity.label.upper():<8}] {finding.title} "
              f"({finding.confidence.value})")
    for error in result.errors:
        print(f"  note: {error}")
    print()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "serve":
        return cmd_serve(args)
    if args.command == "list-tests":
        return cmd_list_tests()
    if args.command == "tools":
        return cmd_tools()
    if args.command == "run":
        return cmd_run(args)
    if args.command == "update":
        return cmd_update(args)
    if args.command == "history":
        return cmd_history(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
