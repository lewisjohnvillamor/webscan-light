"""SSL/TLS scanner."""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.toolreport import Section, ToolReport

from .base import ToolOptions, tool

PROTOCOLS = [
    ("TLSv1.3", getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1_3, False),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2, False),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, True),
    ("TLSv1.0", ssl.TLSVersion.TLSv1, True),
]

WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES", "MD5", "NULL", "EXPORT", "anon", "CBC")


def _host_port(target: str) -> tuple[str, int]:
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    return parsed.hostname or "", parsed.port or 443


def _parse_date(value: str) -> datetime | None:
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _try_protocol(host: str, port: int, version, timeout: float) -> tuple[bool, str | None]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # nosec B323: probing protocol support requires no verification
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, OSError):
        return False, None
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cipher = tls.cipher()
                return True, cipher[0] if cipher else None
    except (ssl.SSLError, OSError):
        return False, None


@tool(id="ssl", name="SSL/TLS Scanner", category="Recon", glyph="🔒", order=20,
      target_hint="hostname (e.g. example.com or example.com:443)",
      description="Inspect the certificate, supported TLS versions and cipher strength.")
def run(target: str, options: ToolOptions) -> ToolReport:
    host, port = _host_port(target)
    report = ToolReport(tool="ssl", tool_name="SSL/TLS Scanner", target=f"{host}:{port}")
    report.params = [("Host", host), ("Port", str(port))]
    if not host:
        report.errors.append("Could not parse a hostname from the target.")
        return report.finish("Failed")

    port_label = f"{port}/tcp"

    # Certificate (validated first, so we learn whether it is trusted).
    trusted = True
    trust_error = ""
    cert = {}
    try:
        vctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=options.timeout) as sock:
            with vctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
    except ssl.SSLCertVerificationError as exc:
        trusted = False
        trust_error = exc.verify_message or str(exc)
    except (ssl.SSLError, OSError) as exc:
        # Retry without verification so we can still describe the certificate.
        try:
            uctx = ssl._create_unverified_context()  # nosec B323: describing an untrusted cert requires no verification
            with socket.create_connection((host, port), timeout=options.timeout) as sock:
                with uctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert() or {}
            trusted = False
            trust_error = str(exc)
        except OSError as exc2:
            report.errors.append(f"Could not establish a TLS connection: {exc2}")
            return report.finish("Failed")

    def flatten(name):
        return ", ".join(f"{k}={v}" for rdn in name for k, v in rdn)

    subject = flatten(cert.get("subject", ()))
    issuer = flatten(cert.get("issuer", ()))
    not_after = cert.get("notAfter", "")
    not_before = cert.get("notBefore", "")
    san = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    expires = _parse_date(not_after) if not_after else None
    now = datetime.now(timezone.utc)
    days_left = int((expires - now).total_seconds() // 86400) if expires else None

    report.sections.append(Section(
        title="Certificate",
        kv=[
            ("Subject", subject or "-"),
            ("Issuer", issuer or "-"),
            ("Valid from", not_before or "-"),
            ("Valid until", not_after or "-"),
            ("Days remaining", str(days_left) if days_left is not None else "-"),
            ("Subject Alternative Names", ", ".join(san) or "-"),
            ("Trusted by system store", "Yes" if trusted else "No"),
        ],
    ))

    # Protocol support matrix.
    proto_rows = []
    supported = {}
    for label, version, _is_weak in PROTOCOLS:
        if version is None:
            continue
        ok, cipher = _try_protocol(host, port, version, options.timeout)
        supported[label] = ok
        proto_rows.append([label, "Enabled" if ok else "Disabled", cipher or "-"])
    report.sections.append(Section(
        title="Protocol support",
        table=Table(columns=["Protocol", "Status", "Negotiated cipher"], rows=proto_rows),
    ))

    # ---- Findings ----
    if not trusted:
        report.findings.append(Finding(
            test_id="ssl_untrusted", title="Certificate not trusted by the system store",
            severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED, port=port_label,
            table=Table(columns=["Host", "Evidence"], rows=[[host, trust_error or "verification failed"]]),
            risk_description="Browsers warn on an untrusted certificate; users habituated to "
                             "clicking through such warnings are easier to man-in-the-middle.",
            recommendation="Install a certificate from a publicly trusted CA that matches the hostname.",
            classification=Classification(cwe=["CWE-295"]),
        ))
    if days_left is not None and days_left < 0:
        report.findings.append(Finding(
            test_id="ssl_expired", title="Certificate has expired", severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED, port=port_label,
            table=Table(columns=["Host", "Expired on"], rows=[[host, not_after]]),
            risk_description="An expired certificate breaks trust and causes browser errors.",
            recommendation="Renew the certificate and automate renewal (e.g. ACME/Let's Encrypt).",
            classification=Classification(cwe=["CWE-298"]),
        ))
    elif days_left is not None and days_left < 21:
        report.findings.append(Finding(
            test_id="ssl_expiring", title=f"Certificate expires soon ({days_left} days)",
            severity=Severity.LOW, confidence=Confidence.CONFIRMED, port=port_label,
            table=Table(columns=["Host", "Expires"], rows=[[host, not_after]]),
            risk_description="A certificate expiring imminently risks an outage if renewal fails.",
            recommendation="Renew now and automate renewal.",
            classification=Classification(cwe=["CWE-298"]),
        ))
    for label, _version, is_weak in PROTOCOLS:
        if is_weak and supported.get(label):
            report.findings.append(Finding(
                test_id=f"ssl_proto_{label}", title=f"Deprecated protocol enabled: {label}",
                severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED, port=port_label,
                table=Table(columns=["Protocol", "Status"], rows=[[label, "Enabled"]]),
                risk_description=f"{label} has known weaknesses and is deprecated; it enables "
                                 "downgrade and padding-oracle style attacks.",
                recommendation=f"Disable {label} and offer only TLS 1.2 and TLS 1.3.",
                classification=Classification(cwe=["CWE-327"]),
            ))
    for label in supported:
        cipher = next((r[2] for r in proto_rows if r[0] == label and r[1] == "Enabled"), "")
        if cipher and any(tok.lower() in cipher.lower() for tok in WEAK_CIPHER_TOKENS if tok != "CBC"):
            report.findings.append(Finding(
                test_id="ssl_weak_cipher", title=f"Weak cipher negotiated: {cipher}",
                severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED, port=port_label,
                table=Table(columns=["Protocol", "Cipher"], rows=[[label, cipher]]),
                risk_description="Weak ciphers (RC4, 3DES, export-grade, MD5) are broken or "
                                 "brute-forceable, undermining confidentiality.",
                recommendation="Restrict the cipher suite to modern AEAD ciphers (AES-GCM, ChaCha20).",
                classification=Classification(cwe=["CWE-327"]),
            ))
            break
    if not supported.get("TLSv1.3") and not supported.get("TLSv1.2"):
        report.findings.append(Finding(
            test_id="ssl_no_modern", title="No modern TLS (1.2/1.3) offered", severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED, port=port_label,
            risk_description="Without TLS 1.2/1.3 the server relies on deprecated protocols only.",
            recommendation="Enable TLS 1.2 and TLS 1.3.",
            classification=Classification(cwe=["CWE-327"]),
        ))

    return report.finish()
