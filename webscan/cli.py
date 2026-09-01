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

    subparsers.add_parser("list-tests", help="list every test the scanner performs")
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


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        print("The web UI needs uvicorn and fastapi:\n  pip install 'webscan-light[web]'",
              file=sys.stderr)
        return 1
    print(f"webscan-light UI -> http://{args.host}:{args.port}")
    uvicorn.run("webscan.web.app:app", host=args.host, port=args.port,
                reload=args.reload, log_level="info")
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
    return 1


if __name__ == "__main__":
    sys.exit(main())
