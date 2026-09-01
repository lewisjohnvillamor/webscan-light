# webscan-light

A free, self-hosted website vulnerability scanner that produces a full
**Website Vulnerability Scanner Report (Light)** — the same report structure as
commercial light scanners, with no account, no quota and no data leaving your
machine.

Use it from the **CLI** or the **web UI**. Reports export to **HTML, PDF, JSON
and SARIF**.

```
Overall risk level   High
  Critical           0
  High               1
  Medium             0
  Low                3
  Info               5
Tests performed      40

┏━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┓
┃ Risk ┃ Finding                                          ┃ Confidence  ┃
┡━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━┩
│ High │ Vulnerabilities found for nginx 1.18.0           │ Unconfirmed │
│ Low  │ Missing security header: Content-Security-Policy │ Confirmed   │
│ Low  │ Security.txt file is missing                     │ Confirmed   │
│ Low  │ HTTP OPTIONS enabled                             │ Confirmed   │
│ Info │ Server software and technology found             │ Unconfirmed │
└──────┴──────────────────────────────────────────────────┴─────────────┘
```

## What it does

**40 tests**, run against every scan:

| Area | Tests |
| --- | --- |
| Version-based vulnerabilities | CVE matching against NVD, enriched with EPSS exploitation probability and the CISA KEV catalog |
| Fingerprinting | Web server, OS, frameworks, CMS, JS libraries, CDN, analytics — with versions |
| Security headers | CSP (missing and unsafe), HSTS, X-Content-Type-Options, Referrer-Policy, rate limiting |
| Well-known files | robots.txt, security.txt, crossdomain.xml, OpenAPI/Swagger, directory listing |
| Transport | Untrusted/expired certificates, HTTP→HTTPS redirection, mixed content, SRI on third-party scripts |
| Cookies | HttpOnly, Secure, over-broad Domain scoping |
| HTTP methods | OPTIONS, TRACE/TRACK/DEBUG and write methods |
| Information exposure | Emails, stack traces, debug output, developer comments, secrets and API keys, PEM private key material, full path disclosure, 5xx responses |
| Authentication surface | Login forms, passwords over HTTP, passwords in URLs, passwords echoed in responses, session tokens in URLs |
| Application surface | File upload endpoints, API endpoints, SQL fragments in parameters |

Run `webscan list-tests` for the full list with test ids.

**It is a light scan.** It does not send attack payloads — no SQL injection,
XSS, command injection, XXE or file-inclusion probing. A clean report is not
evidence that those classes of flaw are absent.

## Install

```bash
git clone https://github.com/lewisjohnvillamor/webscan-light.git
cd webscan-light
pip install -e ".[web]"       # or: pip install -e .   (CLI only)
```

Python 3.10+. No API keys required.

## CLI

```bash
webscan scan example.com                          # summary in the terminal
webscan scan example.com -f html -o report.html --open
webscan scan example.com -f pdf  -o report.pdf
webscan scan example.com -f json -o report.json
webscan scan example.com -f sarif -o report.sarif # for GitHub code scanning
webscan list-tests                                # every test and its id
```

Useful options:

| Option | Purpose |
| --- | --- |
| `--max-pages N`, `--max-depth N` | Crawl budget (default 15 pages, depth 2) |
| `--only IDS`, `--skip IDS` | Run or exclude specific tests by id |
| `--min-cvss N` | Drop CVEs below a CVSS score |
| `--offline` | Use only cached CVE/EPSS/KEV data; no outbound API calls |
| `-H 'Cookie: session=…'` | Extra request headers, e.g. to scan behind a login |
| `--insecure` | Do not verify the target's TLS certificate |
| `--include-exchanges` | Embed raw request/response pairs in HTML and PDF |
| `--fail-on high` | Exit 2 when a finding at or above that severity exists — for CI |

Exit codes: `0` clean, `1` scan error, `2` `--fail-on` threshold met.

## Web UI

```bash
webscan serve                 # http://127.0.0.1:8000
webscan serve --port 9000
```

Enter a target, watch the progress bar, then read the report inline or download
it as PDF/JSON/SARIF. The UI binds to **loopback only** by default — see
[Exposure](#exposure) before changing that.

## Docker

```bash
docker compose up -d          # UI on http://127.0.0.1:8000
docker compose run --rm webscan scan example.com -f json
```

## CI usage

```yaml
- name: Scan staging
  run: |
    pip install webscan-light
    webscan scan https://staging.example.com -f sarif -o results.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## How CVE matching works

1. The fingerprinter extracts `software + version` (e.g. `nginx 1.18.0`).
2. That is turned into a CPE and matched against the **NVD** API 2.0, which
   returns every CVE whose affected-version ranges cover it.
3. Each CVE is enriched with its **EPSS** score and percentile (FIRST) and
   checked against the **CISA KEV** catalog.
4. Results are cached on disk for 24 hours, so repeat scans are instant and
   `--offline` works.

All three feeds are free and need no key. NVD rate-limits anonymous callers to
5 requests per 30 seconds; set `WEBSCAN_NVD_API_KEY` for a
[free key](https://nvd.nist.gov/developers/request-an-api-key) and a much
higher quota.

Because this is version-based detection rather than active exploitation,
findings are reported as **Unconfirmed** and capped at **High** severity —
never Critical.

## Configuration

| Environment variable | Effect |
| --- | --- |
| `WEBSCAN_NVD_API_KEY` | NVD API key, for a higher rate limit |
| `WEBSCAN_CACHE_DIR` | Cache location (default `~/.cache/webscan-light`) |
| `WEBSCAN_CHROME` | Path to Chrome/Chromium for PDF export |

PDF export drives a headless Chromium. If none is found, `-f pdf` writes the
HTML report instead and tells you — every other format works without it.

## Exposure

The web UI has **no authentication**, and anyone who can reach it can make your
server issue HTTP requests to any address they name — including hosts on your
internal network. Keep it on loopback, or put it behind a reverse proxy that
authenticates, and restrict egress. `--host 0.0.0.0` is for trusted networks
only.

## Extending it

A check is a function that returns findings, registered with a decorator. The
description you register is the line that appears in the report's "tests
performed" list, so the coverage section can never drift from what actually ran.

```python
from webscan.core.registry import check
from webscan.core.models import Finding, Severity, Table

@check("my_test", "Scanned for my own condition")
def my_check(context):
    response = context.fetch("/some-path")
    if response.status_code != 200:
        return []
    return [Finding(
        test_id="my_test",
        title="Something noteworthy",
        severity=Severity.LOW,
        port=context.port,
        table=Table(columns=["URL"], rows=[[response.url]]),
        risk_description="Why this matters.",
        recommendation="What to do about it.",
    )]
```

Add the module to `webscan/checks/__init__.py` and it runs, appears in
`list-tests`, and shows up in every report format.

## Development

```bash
pip install -e ".[web,dev]"
pytest                        # runs against a local fixture server, no network
```

## Legal

Scan only systems you own or have written permission to test. Unauthorised
scanning is illegal in many jurisdictions. The authors accept no liability for
misuse.

## License

MIT
