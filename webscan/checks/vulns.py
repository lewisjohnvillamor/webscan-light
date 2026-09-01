"""Version-based vulnerability detection.

The detected software versions are matched against NVD, then enriched with
EPSS exploitation probabilities and the CISA KEV catalog.
"""
from __future__ import annotations

from webscan.core.context import ScanContext
from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.registry import check
from webscan.intel.cpe import candidates_for
from webscan.intel.feeds import CVE, Intel

from .tech import detect

RISK_DESCRIPTION = (
    "The risk is that an attacker could search for an appropriate exploit (or create one "
    "himself) for any of these vulnerabilities and use it to attack the system.\n"
    "Since the vulnerabilities were discovered using only version-based testing, the risk "
    "level for this finding will not exceed 'high' severity. Critical risks will be assigned "
    "to vulnerabilities identified through accurate active testing methods."
)

RECOMMENDATION = (
    "In order to eliminate the risk of these vulnerabilities, we recommend you check the "
    "installed software version and upgrade to the latest version."
)


def _fmt(value: float | None) -> str:
    """EPSS probabilities: trim trailing zeros, they carry no meaning."""
    return f"{value:g}" if value is not None else "-"


def _fmt_cvss(value: float | None) -> str:
    """CVSS is always quoted to one decimal, so 7.0 never renders as '7'."""
    return f"{value:.1f}" if value is not None else "-"


@check("version_vulns",
       "Scanned for version-based vulnerabilities of server-side software",
       order=1)
def version_based_vulnerabilities(context: ScanContext) -> list[Finding]:
    intel: Intel | None = context.shared.get("intel")
    if intel is None:
        return []
    min_cvss: float = context.shared.get("min_cvss", 0.0)

    findings: list[Finding] = []
    for tech in detect(context):
        if not tech.version:
            continue
        cpes = candidates_for(tech.name, tech.cpe)
        if not cpes:
            continue

        collected: dict[str, CVE] = {}
        for vendor_product in cpes:
            for cve in intel.cves_for(vendor_product, tech.version):
                collected.setdefault(cve.id, cve)
        cves = [cve for cve in collected.values() if (cve.cvss or 0.0) >= min_cvss]
        if not cves:
            continue

        intel.enrich_epss(cves)
        intel.enrich_kev(cves)
        cves.sort(key=lambda c: (-(c.cvss or 0.0), c.id))

        max_cvss = max((cve.cvss or 0.0) for cve in cves)
        # A light scan only observes versions, so it never claims 'critical'.
        severity = min(Severity.from_cvss(max_cvss), Severity.HIGH)

        findings.append(
            Finding(
                test_id="version_vulns",
                title=f"Vulnerabilities found for {tech.name.lower()} {tech.version}",
                severity=severity,
                confidence=Confidence.UNCONFIRMED,
                port=context.port,
                table=Table(
                    columns=["CVE", "CVSS", "EPSS Score", "EPSS Percentile", "Summary"],
                    rows=[
                        [cve.id, _fmt_cvss(cve.cvss), _fmt(cve.epss_score),
                         _fmt(cve.epss_percentile), cve.summary]
                        for cve in cves
                    ],
                ),
                risk_description=RISK_DESCRIPTION,
                recommendation=RECOMMENDATION,
                classification=Classification(
                    cwe=["CWE-1035"],
                    cve=[cve.id for cve in cves],
                    cvss_v3=max_cvss,
                    epss_score=max((cve.epss_score for cve in cves if cve.epss_score is not None),
                                   default=None),
                    epss_percentile=max(
                        (cve.epss_percentile for cve in cves if cve.epss_percentile is not None),
                        default=None),
                    cisa_kev=any(cve.kev for cve in cves),
                ),
            )
        )
    return findings
