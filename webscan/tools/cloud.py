"""Cloud storage exposure: guess public buckets from the domain name."""
from __future__ import annotations

import concurrent.futures

import requests

from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.toolreport import Section, ToolReport

from .base import ToolOptions, tool
from .subdomains import _root_domain

PROVIDERS = [
    ("Amazon S3", "https://{n}.s3.amazonaws.com/", ("<ListBucketResult", "<Contents>")),
    ("Google Cloud Storage", "https://storage.googleapis.com/{n}/", ("<ListBucketResult", "<Contents>")),
    ("Azure Blob", "https://{n}.blob.core.windows.net/?comp=list", ("<EnumerationResults", "<Blob>")),
]


def _candidates(domain: str) -> list[str]:
    base = domain.split(".")[0]
    full = domain.replace(".", "-")
    names = {base, full, domain.replace(".", ""), f"{base}-assets", f"{base}-static",
             f"{base}-backup", f"{base}-backups", f"{base}-media", f"{base}-uploads",
             f"{base}-files", f"{base}-data", f"{base}-dev", f"{base}-prod", f"{base}-public",
             f"{base}-private", f"{base}-cdn", f"{base}-images", f"{base}-logs", f"assets-{base}",
             f"static-{base}", f"backup-{base}"}
    return sorted(n for n in names if n)


@tool(id="cloud", name="Cloud Storage Exposure", category="Recon", glyph="☁", order=44,
      target_hint="domain (e.g. example.com)", active=True,
      description="Guess S3/GCS/Azure bucket names from the domain and flag public ones.")
def run(target: str, options: ToolOptions) -> ToolReport:
    domain = _root_domain(target)
    report = ToolReport(tool="cloud", tool_name="Cloud Storage Exposure", target=domain)
    report.params = [("Domain", domain)]
    names = _candidates(domain)
    rows: list[list[str]] = []

    def probe(args):
        provider, template, markers, name = args
        url = template.format(n=name)
        try:
            resp = requests.get(url, timeout=options.timeout, headers={"User-Agent": "webscan-light"})
        except requests.RequestException:
            return None
        exists = resp.status_code in (200, 403)
        public = resp.status_code == 200 and any(m in resp.text for m in markers)
        if not exists:
            return None
        return [provider, name, str(resp.status_code),
                "PUBLIC — listing readable" if public else "exists (access denied)", url, public]

    jobs = [(p, t, m, n) for (p, t, m) in PROVIDERS for n in names]
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(10, options.workers)) as pool:
        for result in pool.map(probe, jobs):
            if not result:
                continue
            *display, url, public = result
            rows.append(display + [url])
            if public:
                report.findings.append(Finding(
                    test_id=f"bucket_{display[1]}", title=f"Public {display[0]} bucket: {display[1]}",
                    severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                    table=Table(["Provider", "Bucket", "URL"], [[display[0], display[1], url]]),
                    risk_description="The bucket lists its contents to anyone. Public buckets "
                                     "routinely expose backups, credentials and customer data.",
                    recommendation="Make the bucket private and audit what was exposed; rotate "
                                   "any secrets found inside.",
                    classification=Classification(cwe=["CWE-200"],
                                                  owasp_2021=["A5 - Security Misconfiguration"],
                                                  owasp_2017=["A6 - Security Misconfiguration"],
                                                  owasp_2025=["A02 - Security Misconfiguration"])))
    report.sections.append(Section(
        title=f"Matching buckets ({len(rows)})",
        intro="No buckets matched the guessed names." if not rows else
              "Names were guessed from the domain; a match is not proof of ownership.",
        table=Table(["Provider", "Bucket", "Status", "Access", "URL"], rows)))
    report.stats = [("Names tried", str(len(names))), ("Provider probes", str(len(jobs)))]
    return report.finish()
