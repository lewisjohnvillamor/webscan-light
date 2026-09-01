"""Certificate inspection using only the standard library."""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse


def _parse_cert_date(value: str) -> datetime | None:
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def inspect(url: str, timeout: float = 10.0) -> dict[str, Any]:
    """Return certificate facts, plus why validation failed when it does."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return {"enabled": False}

    host = parsed.hostname or ""
    port = parsed.port or 443
    info: dict[str, Any] = {"enabled": True, "host": host, "port": port, "trusted": True}

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert() or {}
                info["protocol"] = tls_sock.version()
                info["cipher"] = tls_sock.cipher()[0] if tls_sock.cipher() else None
                info["cert"] = cert
    except ssl.SSLCertVerificationError as exc:
        info["trusted"] = False
        info["error"] = exc.verify_message or str(exc)
        info["error_code"] = getattr(exc, "verify_code", None)
        _fill_untrusted(info, host, port, timeout)
    except (OSError, ssl.SSLError) as exc:
        info["trusted"] = False
        info["error"] = f"{type(exc).__name__}: {exc}"
        _fill_untrusted(info, host, port, timeout)

    cert = info.get("cert") or {}
    if cert:
        info["subject"] = _flatten_name(cert.get("subject", ()))
        info["issuer"] = _flatten_name(cert.get("issuer", ()))
        info["not_after"] = cert.get("notAfter")
        info["not_before"] = cert.get("notBefore")
        expires = _parse_cert_date(cert.get("notAfter", "")) if cert.get("notAfter") else None
        info["expired"] = bool(expires and expires < datetime.now(timezone.utc))
        info["expires_at"] = expires.isoformat() if expires else None
        info["san"] = [value for key, value in cert.get("subjectAltName", ()) if key == "DNS"]
    return info


def _fill_untrusted(info: dict[str, Any], host: str, port: int, timeout: float) -> None:
    """Re-connect without verification so an untrusted cert can still be described."""
    try:
        context = ssl._create_unverified_context()  # nosec B323: a TLS scanner must inspect untrusted/invalid certs
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                info["protocol"] = tls_sock.version()
                der = tls_sock.getpeercert(binary_form=True)
                if der:
                    info["cert_der_len"] = len(der)
    except Exception:  # noqa: BLE001 - best effort only
        pass  # nosec B110: describing an untrusted cert is best-effort


def _flatten_name(name: tuple) -> str:
    parts = []
    for rdn in name:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)
