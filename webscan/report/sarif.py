"""SARIF 2.1.0 output, for GitHub code scanning and other CI consumers."""
from __future__ import annotations

import json
from pathlib import Path

from webscan import __version__
from webscan.core.models import ScanResult, Severity

SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "warning",
    Severity.INFO: "note",
}


def render(result: ScanResult) -> str:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for finding in result.sorted_findings:
        rule_id = finding.test_id
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.risk_description or finding.title},
                "help": {
                    "text": finding.recommendation or "",
                    "markdown": _help_markdown(finding),
                },
                "properties": {
                    "tags": finding.classification.cwe + finding.classification.owasp_2021,
                    "security-severity": str(finding.classification.cvss_v3 or _proxy_score(finding.severity)),
                },
            }
        results.append({
            "ruleId": rule_id,
            "level": SARIF_LEVEL[finding.severity],
            "message": {"text": f"{finding.title} ({finding.severity.label})"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": result.target},
                    "region": {"startLine": 1},
                }
            }],
            "properties": {"confidence": finding.confidence.value, "port": finding.port},
        })

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "webscan-light",
                "version": __version__,
                "informationUri": "https://github.com/lewisjohnvillamor/webscan-light",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(document, indent=2, ensure_ascii=False)


def _proxy_score(severity: Severity) -> float:
    return {Severity.CRITICAL: 9.5, Severity.HIGH: 7.5, Severity.MEDIUM: 5.0,
            Severity.LOW: 3.0, Severity.INFO: 0.0}[severity]


def _help_markdown(finding) -> str:
    parts = []
    if finding.risk_description:
        parts.append(f"**Risk**\n\n{finding.risk_description}")
    if finding.recommendation:
        parts.append(f"**Recommendation**\n\n{finding.recommendation}")
    if finding.references:
        parts.append("**References**\n\n" + "\n".join(f"- {r}" for r in finding.references))
    return "\n\n".join(parts)


def write(result: ScanResult, path: str | Path) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render(result), encoding="utf-8")
    return output
