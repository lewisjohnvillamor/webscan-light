# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Full tool suite (20 tools): website scanner, recon (SSL/TLS, ports, network,
  subdomains, vhosts, URL fuzzer, Google dorks, DNS & email, cloud storage,
  typosquat, Attack Surface Monitor), vulnerability (takeover, API, dependency,
  web-misconfig, secrets) and gated active tools (XSS, SQLi, sniper).
- Web UI with tool launcher, inline reports, HTML/PDF/JSON/SARIF export,
  request logger, scan history, scheduled scans with new-finding alerts, and a
  one-click "monitor this domain" (ASM).
- Security grade (A–F) with SVG badge and an OWASP/PCI-DSS/ASVS compliance view.
- SQLite persistence, disk caches (NVD/EPSS/KEV, OSV, DNS), and recent-scan
  reuse to reduce load.
- Optional token auth, an SSRF scope guard, a scan-safety consent gate, and a
  request-politeness `--delay`/throttle.

### Notes
- Version-based and heuristic findings are indicative; verify before acting.
- Relicensed to AGPL-3.0-or-later.
