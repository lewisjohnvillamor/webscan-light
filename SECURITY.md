# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories
("Report a vulnerability" on the repository's Security tab) rather than opening a
public issue. Include reproduction steps and impact. We aim to acknowledge
within a few days.

## Scope and intended use

webscan-light is a **defensive/authorised-testing** tool. It must only be run
against systems you own or have explicit written permission to test. See the
"Responsible use & precautions" section of the README.

## Hardening a self-hosted deployment

- Set `WEBSCAN_TOKEN` to require authentication for the web UI/API.
- Keep the default loopback bind, or place the UI behind an authenticating
  reverse proxy; restrict egress with `WEBSCAN_ALLOW_PRIVATE` left unset so the
  SSRF scope guard blocks internal/metadata targets.
- Treat the request-logger URLs and stored reports as sensitive (they may
  contain findings and captured requests).
