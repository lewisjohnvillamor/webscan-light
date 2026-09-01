"""Dependency / SBOM vulnerability scanner (OSV.dev)."""
from __future__ import annotations

from collections import defaultdict

from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.toolreport import Section, ToolReport
from webscan.intel.osv import OSV

from .base import ToolOptions, tool
from .manifests import find_and_parse

_SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


@tool(id="deps", name="Dependency Scanner", category="Vulnerability", glyph="📦", order=56,
      target_hint="path to a project or manifest file",
      description="Find known-vulnerable open-source dependencies via OSV.dev (PyPI, npm, Go, …).")
def run(target: str, options: ToolOptions) -> ToolReport:
    report = ToolReport(tool="deps", tool_name="Dependency Scanner", target=target)
    report.params = [("Path", target)]

    deps = find_and_parse(target, max_files=options.max_items or 50)
    if not deps:
        report.errors.append(
            "No recognised, version-pinned manifests found (requirements.txt with '==', "
            "package-lock.json, poetry.lock, go.mod, Cargo.lock, composer.lock, Gemfile.lock, …).")
        report.sections.append(Section(title="Dependencies", intro="Nothing to scan."))
        return report.finish()

    by_eco = defaultdict(int)
    for d in deps:
        by_eco[d["ecosystem"]] += 1
    report.sections.append(Section(
        title=f"Dependencies scanned ({len(deps)})",
        intro=", ".join(f"{eco}: {n}" for eco, n in sorted(by_eco.items())),
        table=Table(["Ecosystem", "Package", "Version", "Source"],
                    [[d["ecosystem"], d["name"], d["version"], d.get("source", "")] for d in deps[:200]])))

    osv = OSV(offline=options.offline, timeout=options.timeout)
    hits = osv.query(deps)

    vuln_rows: list[list[str]] = []
    detail_cache: dict[str, dict] = {}
    fetched = 0
    for dep in deps:
        key = (dep["ecosystem"], dep["name"], dep["version"])
        ids = hits.get(key) or []
        if not ids:
            continue
        worst = Severity.INFO
        detail_lines = []
        cve_list: list[str] = []
        for vid in ids:
            detail = detail_cache.get(vid)
            if detail is None and fetched < 200:
                detail = osv.details(vid)
                detail_cache[vid] = detail
                fetched += 1
            detail = detail or {"id": vid, "summary": "", "severity": "UNKNOWN", "aliases": [], "fixed": ""}
            sev = _SEV.get(detail.get("severity", ""), Severity.MEDIUM)
            worst = max(worst, sev)
            cve_list += [a for a in detail.get("aliases", []) if a.startswith("CVE-")]
            detail_lines.append(f"{vid}: {detail.get('summary','')[:80]}")
        fixed = next((detail_cache.get(v, {}).get("fixed") for v in ids
                      if detail_cache.get(v, {}).get("fixed")), "")
        vuln_rows.append([f"{dep['name']} {dep['version']}", dep["ecosystem"], str(len(ids)),
                          worst.label, fixed or "-"])
        report.findings.append(Finding(
            test_id=f"dep_{dep['name']}", title=f"Vulnerable dependency: {dep['name']} {dep['version']}",
            severity=worst if worst != Severity.INFO else Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            table=Table(["Advisory", "Detail"], [[vid_line.split(':', 1)[0], vid_line.split(':', 1)[1].strip()]
                                                  for vid_line in detail_lines[:12]]),
            risk_description=f"{dep['name']} {dep['version']} ({dep['ecosystem']}) is affected by "
                             f"{len(ids)} known advisory(ies). Vulnerable dependencies are one of "
                             "the most common routes to compromise.",
            recommendation=(f"Upgrade {dep['name']} to {fixed} or later." if fixed
                            else f"Upgrade {dep['name']} to a fixed release (see the advisories)."),
            references=[f"https://osv.dev/vulnerability/{ids[0]}"],
            classification=Classification(cwe=["CWE-1104"], cve=sorted(set(cve_list)),
                                          owasp_2021=["A6 - Vulnerable and Outdated Components"],
                                          owasp_2017=["A9 - Using Components with Known Vulnerabilities"],
                                          owasp_2025=["A02 - Security Misconfiguration"])))

    if vuln_rows:
        report.sections.insert(0, Section(
            title=f"Vulnerable dependencies ({len(vuln_rows)})",
            table=Table(["Package", "Ecosystem", "Advisories", "Max severity", "Fixed in"], vuln_rows)))
    report.stats = [("Dependencies", str(len(deps))), ("Vulnerable", str(len(vuln_rows)))]
    report.errors.extend(osv.errors)
    return report.finish()
