"""API scanner: find API definitions/endpoints and check for open access."""
from __future__ import annotations

import re

from webscan.core.http import HttpClient, normalize_target
from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.toolreport import Section, ToolReport

from .base import ToolOptions, tool

DEFINITION_PATHS = [
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml", "/v2/api-docs",
    "/v3/api-docs", "/api-docs", "/swagger-ui.html", "/swagger", "/api/swagger.json",
    "/api/openapi.json", "/redoc", "/graphql", "/api/graphql", "/.well-known/openapi.json",
]
GRAPHQL_INTROSPECTION = '{"query":"{__schema{queryType{name}}}"}'


@tool(id="api", name="API Scanner", category="Vulnerability", glyph="🧩", order=55,
      target_hint="base URL (e.g. https://api.example.com)", active=True,
      description="Discover API definitions and endpoints and flag open docs or introspection.")
def run(target: str, options: ToolOptions) -> ToolReport:
    base = normalize_target(target).rstrip("/")
    report = ToolReport(tool="api", tool_name="API Scanner", target=base)
    report.params = [("Base URL", base)]
    client = HttpClient(timeout=options.timeout, verify_tls=options.verify_tls, delay=options.delay)

    found_rows: list[list[str]] = []
    for path in DEFINITION_PATHS:
        url = f"{base}{path}"
        resp = client.get(url)
        if not resp.ok or resp.status_code != 200:
            continue
        body = resp.text[:5000]
        kind = ""
        if re.search(r'"(openapi|swagger)"\s*:', body) or re.search(r"(?m)^\s*(openapi|swagger)\s*:", body):
            kind = "OpenAPI/Swagger definition"
        elif "swagger-ui" in body.lower() or "redoc" in body.lower():
            kind = "Interactive API documentation"
        elif path.endswith("graphql"):
            kind = "GraphQL endpoint"
        if kind:
            found_rows.append([url, kind, str(resp.status_code)])
            report.findings.append(Finding(
                test_id="api_definition", title=f"{kind} publicly accessible",
                severity=Severity.LOW, confidence=Confidence.CONFIRMED,
                table=Table(columns=["URL", "Type"], rows=[[url, kind]]),
                risk_description="A public API definition hands an attacker the full list of "
                                 "endpoints, parameters and auth requirements.",
                recommendation="Restrict API definitions and documentation UIs to authenticated "
                               "internal users in production.",
                classification=Classification(cwe=["CWE-200"]),
            ))

    # GraphQL introspection.
    for gql in (f"{base}/graphql", f"{base}/api/graphql"):
        resp = client.request("POST", gql, data=GRAPHQL_INTROSPECTION,
                              headers={"Content-Type": "application/json"})
        if resp.ok and resp.status_code == 200 and "__schema" in resp.text:
            report.findings.append(Finding(
                test_id="graphql_introspection", title="GraphQL introspection enabled",
                severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
                table=Table(columns=["Endpoint", "Evidence"], rows=[[gql, "Introspection query returned a schema"]]),
                risk_description="Introspection exposes the entire GraphQL schema — every type, "
                                 "field and mutation — greatly easing attacks against the API.",
                recommendation="Disable introspection in production GraphQL servers.",
                classification=Classification(cwe=["CWE-200"]),
            ))
            found_rows.append([gql, "GraphQL with introspection", "200"])

    report.sections.append(Section(
        title=f"API surface ({len(found_rows)})",
        intro="No API definitions or endpoints were found at the common paths." if not found_rows else "",
        table=Table(columns=["URL", "Type", "Status"], rows=found_rows),
    ))
    report.stats = [("Paths probed", str(len(DEFINITION_PATHS) + 2)),
                    ("HTTP requests", str(client.request_count))]
    return report.finish()
