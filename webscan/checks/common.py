"""Classification shorthands shared by many checks."""
from __future__ import annotations

from webscan.core.models import Classification

MISCONFIG_2017 = "A6 - Security Misconfiguration"
MISCONFIG_2021 = "A5 - Security Misconfiguration"
MISCONFIG_2025 = "A02 - Security Misconfiguration"
INSECURE_DESIGN_2025 = "A06 - Insecure Design"


def misconfig(cwe: str | list[str] | None = None, owasp_2025: str = MISCONFIG_2025) -> Classification:
    """The security-misconfiguration classification used by most checks."""
    cwes = [cwe] if isinstance(cwe, str) else list(cwe or [])
    return Classification(
        cwe=cwes,
        owasp_2017=[MISCONFIG_2017],
        owasp_2021=[MISCONFIG_2021],
        owasp_2025=[owasp_2025],
    )
