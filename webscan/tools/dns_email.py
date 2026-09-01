"""DNS & email security posture: SPF, DKIM, DMARC, CAA, DNSSEC, MTA-STS, AXFR."""
from __future__ import annotations

import socket
import struct

from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.toolreport import Section, ToolReport

from .base import ToolOptions, tool
from .dnsutil import resolve
from .subdomains import _root_domain

COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "dkim", "mail",
    "smtp", "s1", "s2", "mandrill", "mailjet", "zoho", "protonmail", "protonmail2",
    "protonmail3", "fm1", "fm2", "fm3", "amazonses", "mailgun", "sendgrid",
]

AUTH_CLASS = Classification(cwe=["CWE-16"], owasp_2021=["A5 - Security Misconfiguration"],
                            owasp_2017=["A6 - Security Misconfiguration"],
                            owasp_2025=["A02 - Security Misconfiguration"])


def _txt(name: str, timeout: float) -> list[str]:
    return [v for v in resolve(name, "TXT", timeout)]


def _try_axfr(domain: str, ns_ip: str, timeout: float) -> bool:
    """Best-effort AXFR: a zone transfer that returns records is misconfigured."""
    # Minimal DNS query: header + question for <domain> AXFR (qtype 252) over TCP.
    tid = b"\x13\x37"
    header = tid + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    qname = b"".join(bytes([len(p)]) + p.encode() for p in domain.split(".")) + b"\x00"
    question = qname + struct.pack(">HH", 252, 1)  # AXFR, IN
    message = header + question
    packet = struct.pack(">H", len(message)) + message
    try:
        with socket.create_connection((ns_ip, 53), timeout=timeout) as sock:
            sock.sendall(packet)
            sock.settimeout(timeout)
            length_bytes = sock.recv(2)
            if len(length_bytes) < 2:
                return False
            (length,) = struct.unpack(">H", length_bytes)
            data = sock.recv(min(length, 4096))
            if len(data) < 8:
                return False
            ancount = struct.unpack(">H", data[6:8])[0]
            return ancount >= 2  # more than the SOA => zone data returned
    except (OSError, struct.error):
        return False


@tool(id="dnsemail", name="DNS & Email Security", category="Recon", glyph="📧", order=15,
      target_hint="domain (e.g. example.com)",
      description="Check SPF, DKIM, DMARC, CAA, DNSSEC, MTA-STS and zone-transfer exposure.")
def run(target: str, options: ToolOptions) -> ToolReport:
    domain = _root_domain(target)
    report = ToolReport(tool="dnsemail", tool_name="DNS & Email Security", target=domain)
    report.params = [("Domain", domain)]
    t = options.timeout
    rows: list[list[str]] = []

    # ---- SPF ----
    spf = next((r for r in _txt(domain, t) if r.lower().startswith("v=spf1")), None)
    if not spf:
        rows.append(["SPF", "Missing", "No v=spf1 TXT record"])
        report.findings.append(Finding(
            test_id="spf_missing", title="SPF record missing", severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            risk_description="Without SPF, anyone can send email claiming to be from your "
                             "domain; receivers cannot verify sending servers.",
            recommendation="Publish an SPF record listing your legitimate senders, ending in "
                           "'-all' (hard fail).", classification=AUTH_CLASS))
    else:
        soft = spf.strip().endswith("~all") or "?all" in spf or spf.strip().endswith("+all")
        rows.append(["SPF", "Present", spf[:120]])
        if spf.strip().endswith("+all"):
            report.findings.append(Finding(
                test_id="spf_permissive", title="SPF record allows any sender (+all)",
                severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                table=Table(["Record"], [[spf]]),
                risk_description="'+all' authorises every server on the internet to send as "
                                 "your domain — worse than having no SPF.",
                recommendation="Replace '+all' with '-all' and enumerate valid senders.",
                classification=AUTH_CLASS))
        elif soft:
            report.findings.append(Finding(
                test_id="spf_soft", title="SPF uses a soft/neutral policy (~all or ?all)",
                severity=Severity.LOW, confidence=Confidence.CONFIRMED,
                table=Table(["Record"], [[spf]]),
                risk_description="A soft-fail policy lets spoofed mail through with only a "
                                 "'suspicious' mark, which most receivers still deliver.",
                recommendation="Move to '-all' once you have confirmed all legitimate senders.",
                classification=AUTH_CLASS))

    # ---- DMARC ----
    dmarc = next((r for r in _txt(f"_dmarc.{domain}", t) if r.lower().startswith("v=dmarc1")), None)
    if not dmarc:
        rows.append(["DMARC", "Missing", "No _dmarc TXT record"])
        report.findings.append(Finding(
            test_id="dmarc_missing", title="DMARC record missing", severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            risk_description="Without DMARC, SPF/DKIM failures are not enforced and you receive "
                             "no reports of who is spoofing your domain.",
            recommendation="Publish a _dmarc record. Start at 'p=none' with rua reporting, then "
                           "move to 'quarantine' and 'reject'.", classification=AUTH_CLASS))
    else:
        policy = "none"
        for part in dmarc.split(";"):
            if part.strip().lower().startswith("p="):
                policy = part.strip()[2:].strip().lower()
        rows.append(["DMARC", f"Present (p={policy})", dmarc[:120]])
        if policy == "none":
            report.findings.append(Finding(
                test_id="dmarc_none", title="DMARC policy is 'none' (monitor only)",
                severity=Severity.LOW, confidence=Confidence.CONFIRMED,
                table=Table(["Record"], [[dmarc]]),
                risk_description="'p=none' takes no action on spoofed mail; it only reports.",
                recommendation="Progress to 'p=quarantine' then 'p=reject' after reviewing "
                               "reports.", classification=AUTH_CLASS))

    # ---- DKIM (probe common selectors) ----
    found_selectors = []
    for selector in COMMON_DKIM_SELECTORS:
        recs = _txt(f"{selector}._domainkey.{domain}", t)
        if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in recs):
            found_selectors.append(selector)
    if found_selectors:
        rows.append(["DKIM", "Present", "selectors: " + ", ".join(found_selectors)])
    else:
        rows.append(["DKIM", "Not found", "No common selector published a DKIM key"])
        report.findings.append(Finding(
            test_id="dkim_missing", title="No DKIM key found on common selectors",
            severity=Severity.LOW, confidence=Confidence.UNCONFIRMED,
            risk_description="DKIM signs outbound mail so receivers can verify it was not "
                             "altered. None of the common selectors resolved (you may use a "
                             "custom selector).",
            recommendation="Publish a DKIM key and sign outbound mail; confirm your selector.",
            classification=AUTH_CLASS))

    # ---- CAA ----
    caa = resolve(domain, "CAA", t)
    if caa:
        rows.append(["CAA", "Present", "; ".join(caa)[:120]])
    else:
        rows.append(["CAA", "Missing", "No CAA record"])
        report.findings.append(Finding(
            test_id="caa_missing", title="CAA record missing", severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            risk_description="Without CAA, any Certificate Authority may issue certificates for "
                             "your domain, widening the mis-issuance risk.",
            recommendation="Publish a CAA record naming only the CAs you use.",
            classification=AUTH_CLASS))

    # ---- DNSSEC ----
    dnskey = resolve(domain, "DNSKEY", t)
    rows.append(["DNSSEC", "Enabled" if dnskey else "Not enabled",
                 "DNSKEY present" if dnskey else "No DNSKEY record"])
    if not dnskey:
        report.findings.append(Finding(
            test_id="dnssec_missing", title="DNSSEC not enabled", severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            risk_description="Without DNSSEC, DNS responses for your domain are not "
                             "cryptographically signed and can be spoofed via cache poisoning.",
            recommendation="Enable DNSSEC at your DNS provider and add the DS record at your "
                           "registrar.", classification=AUTH_CLASS))

    # ---- MTA-STS ----
    mta = _txt(f"_mta-sts.{domain}", t)
    rows.append(["MTA-STS", "Present" if mta else "Not configured",
                 mta[0][:100] if mta else "No _mta-sts TXT record"])

    # ---- Zone transfer (AXFR) ----
    nameservers = resolve(domain, "NS", t)
    axfr_open = []
    for ns in nameservers[:4]:
        for ns_ip in resolve(ns.rstrip("."), "A", t)[:1]:
            if _try_axfr(domain, ns_ip, min(t, 6)):
                axfr_open.append(f"{ns.rstrip('.')} ({ns_ip})")
    if axfr_open:
        report.findings.append(Finding(
            test_id="axfr_open", title="DNS zone transfer (AXFR) allowed", severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED, port="53/tcp",
            table=Table(["Nameserver"], [[n] for n in axfr_open]),
            risk_description="An open AXFR lets anyone download your entire DNS zone, exposing "
                             "every hostname and internal record you publish.",
            recommendation="Restrict zone transfers to your secondary nameservers only.",
            classification=Classification(cwe=["CWE-200"])))
        rows.append(["Zone transfer", "OPEN", ", ".join(axfr_open)])
    else:
        rows.append(["Zone transfer", "Restricted", "AXFR refused by nameservers"])

    report.sections.append(Section(title="DNS & email records",
                                   table=Table(["Check", "Status", "Detail"], rows)))
    report.stats = [("Nameservers", str(len(nameservers))), ("Checks", str(len(rows)))]
    return report.finish()
