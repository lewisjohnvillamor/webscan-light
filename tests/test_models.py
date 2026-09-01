from webscan.core.models import (
    Classification,
    Confidence,
    Finding,
    ScanResult,
    Severity,
)


def make(severity: Severity, title: str = "x") -> Finding:
    return Finding(test_id="t", title=title, severity=severity)


def test_severity_from_cvss_boundaries():
    assert Severity.from_cvss(9.0) is Severity.CRITICAL
    assert Severity.from_cvss(8.9) is Severity.HIGH
    assert Severity.from_cvss(7.0) is Severity.HIGH
    assert Severity.from_cvss(6.9) is Severity.MEDIUM
    assert Severity.from_cvss(3.9) is Severity.LOW
    assert Severity.from_cvss(0.0) is Severity.INFO


def test_overall_risk_is_the_highest_finding():
    result = ScanResult(target="https://example.com/")
    result.findings = [make(Severity.LOW), make(Severity.HIGH), make(Severity.INFO)]
    assert result.overall_risk is Severity.HIGH


def test_overall_risk_of_a_clean_scan_is_info():
    assert ScanResult(target="https://example.com/").overall_risk is Severity.INFO


def test_rating_counts_cover_every_severity():
    result = ScanResult(target="https://example.com/")
    result.findings = [make(Severity.LOW), make(Severity.LOW), make(Severity.CRITICAL)]
    assert result.rating_counts == {
        "Critical": 1, "High": 0, "Medium": 0, "Low": 2, "Info": 0
    }


def test_findings_sort_highest_severity_first():
    result = ScanResult(target="https://example.com/")
    result.findings = [make(Severity.INFO, "i"), make(Severity.CRITICAL, "c"),
                       make(Severity.MEDIUM, "m")]
    assert [f.title for f in result.sorted_findings] == ["c", "m", "i"]


def test_classification_rows_are_ordered_and_skip_empty_fields():
    classification = Classification(cwe=["CWE-79"], owasp_2021=["A3 - Injection"], cvss_v3=7.5)
    labels = [label for label, _ in classification.as_rows()]
    assert labels == ["CVSS V3", "CWE", "OWASP Top 10 - 2021"]


def test_scan_result_serializes_to_json_safe_types():
    import json

    result = ScanResult(target="https://example.com/")
    result.findings = [
        Finding(test_id="t", title="x", severity=Severity.HIGH,
                confidence=Confidence.UNCONFIRMED)
    ]
    json.dumps(result.as_dict())  # must not raise
