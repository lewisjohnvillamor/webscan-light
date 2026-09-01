"""Checks that inspect response bodies for exposed information."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlparse

from webscan.core.context import ScanContext
from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.registry import check

from .common import INSECURE_DESIGN_2025, misconfig

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# Filenames such as sprite@2x.png and versioned packages look like addresses.
EMAIL_NOISE = re.compile(r"\.(png|jpe?g|gif|svg|webp|css|js|woff2?|ttf)$", re.I)


def _insecure_design(cwe: str = "CWE-200") -> Classification:
    return Classification(
        cwe=[cwe],
        owasp_2017=["A6 - Security Misconfiguration"],
        owasp_2021=["A4 - Insecure Design"],
        owasp_2025=[INSECURE_DESIGN_2025],
        cisa_kev=False,
    )


@check("emails", "Scanned for emails", order=70)
def email_exposure(context: ScanContext) -> list[Finding]:
    rows: list[list[str]] = []
    seen: set[str] = set()
    for page in context.html_pages:
        for match in EMAIL_RE.findall(page.response.text):
            address = match.strip(".")
            if address in seen or EMAIL_NOISE.search(address):
                continue
            if address.split("@")[0].isdigit():
                continue
            seen.add(address)
            user_agent = page.response.request_headers.get("User-Agent", "")
            rows.append([
                page.url,
                page.response.request_method,
                f"Headers:\nUser-Agent={user_agent}",
                f"Email Address: {address}",
            ])
    if not rows:
        return []
    return [
        Finding(
            test_id="emails",
            title="Email Address Exposure",
            severity=Severity.INFO,
            confidence=Confidence.UNCONFIRMED,
            port=context.port,
            table=Table(
                columns=["URL", "Method", "Parameters", "Evidence"], rows=rows[:25]
            ),
            risk_description=(
                "The risk is that exposed email addresses within the application could be "
                "accessed by unauthorized parties. This could lead to privacy violations, "
                "spam, phishing attacks, or other forms of misuse."
            ),
            recommendation=(
                "Compartmentalize the application to have 'safe' areas where trust boundaries "
                "can be unambiguously drawn. Do not allow email addresses to go outside of the "
                "trust boundary, and always be careful when interfacing with a compartment "
                "outside of the safe area."
            ),
            references=["https://owasp.org/Top10/A04_2021-Insecure_Design/"],
            classification=_insecure_design(),
        )
    ]


ERROR_PATTERNS = [
    (re.compile(r"(?i)\bSQL syntax\b.{0,80}\bMySQL\b"), "MySQL error message"),
    (re.compile(r"(?i)\bORA-\d{5}\b"), "Oracle error message"),
    (re.compile(r"(?i)\bPostgreSQL\b.{0,40}\bERROR\b"), "PostgreSQL error message"),
    (re.compile(r"(?i)Microsoft OLE DB Provider for"), "Microsoft OLE DB error"),
    (re.compile(r"(?i)Unclosed quotation mark after the character string"), "MSSQL error message"),
    (re.compile(r"(?i)\bWarning\b:\s+\w+\(\)"), "PHP warning"),
    (re.compile(r"(?i)\bFatal error\b:\s"), "PHP fatal error"),
    (re.compile(r"Traceback \(most recent call last\):"), "Python traceback"),
    (re.compile(r"(?i)\bjava\.lang\.\w+Exception\b"), "Java exception"),
    (re.compile(r"(?i)System\.\w+\.\w+Exception:"), "ASP.NET exception"),
    (re.compile(r"(?i)\bstack trace\b:"), "Stack trace"),
]


@check("error_messages", "Scanned for error messages", order=71)
def error_messages(context: ScanContext) -> list[Finding]:
    rows: list[list[str]] = []
    for page in context.crawl.pages:
        for pattern, label in ERROR_PATTERNS:
            match = pattern.search(page.response.text)
            if match:
                rows.append([page.url, label, _snippet(page.response.text, match)])
    if not rows:
        return []
    return [
        Finding(
            test_id="error_messages",
            title="Verbose error messages exposed",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(columns=["URL", "Type", "Evidence"], rows=rows[:20]),
            risk_description=(
                "The risk is that detailed error output reveals the technology stack, file "
                "paths, SQL queries and application internals, which an attacker uses to build "
                "a more precise attack."
            ),
            recommendation=(
                "Disable verbose errors in production and return a generic error page, while "
                "logging the full detail server-side."
            ),
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/",
            ],
            classification=misconfig("CWE-209"),
        )
    ]


DEBUG_PATTERNS = [
    (re.compile(r"(?i)\bvar_dump\s*\("), "PHP var_dump output"),
    (re.compile(r"(?i)\bprint_r\s*\("), "PHP print_r output"),
    (re.compile(r"(?i)\bconsole\.(debug|trace)\s*\("), "Client-side debug logging"),
    (re.compile(r"(?i)\bdebug\s*[:=]\s*(true|1)\b"), "Debug mode flag enabled"),
    (re.compile(r"(?i)DEBUG\s*=\s*True"), "Framework debug setting enabled"),
    (re.compile(r"(?i)Werkzeug Debugger"), "Werkzeug interactive debugger"),
    (re.compile(r"(?i)Whoops\\Run"), "Whoops error handler"),
]


@check("debug_messages", "Scanned for debug messages", order=72)
def debug_messages(context: ScanContext) -> list[Finding]:
    rows: list[list[str]] = []
    for page in context.crawl.pages:
        for pattern, label in DEBUG_PATTERNS:
            match = pattern.search(page.response.text)
            if match:
                rows.append([page.url, label, _snippet(page.response.text, match)])
    if not rows:
        return []
    return [
        Finding(
            test_id="debug_messages",
            title="Debug output found in responses",
            severity=Severity.LOW,
            confidence=Confidence.UNCONFIRMED,
            port=context.port,
            table=Table(columns=["URL", "Type", "Evidence"], rows=rows[:20]),
            risk_description=(
                "The risk is that debug output leaks internal state and, in the case of "
                "interactive debuggers, can allow arbitrary code execution on the server."
            ),
            recommendation=(
                "Turn debug mode off in the production configuration and remove debug "
                "statements from shipped code."
            ),
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/",
            ],
            classification=misconfig("CWE-489"),
        )
    ]


INTERESTING_COMMENT = re.compile(
    r"(?i)\b(todo|fixme|hack|bug|password|passwd|pwd|secret|api[_\-]?key|token|"
    r"username|credential|backdoor|temporary|remove this|do not commit|internal only)\b"
)


@check("code_comments", "Scanned for code comments", order=73)
def code_comments(context: ScanContext) -> list[Finding]:
    rows: list[list[str]] = []
    for page in context.html_pages:
        for comment in re.findall(r"<!--(.*?)-->", page.response.text, re.S):
            text = " ".join(comment.split())
            if not text or text.startswith("["):  # conditional comments / build markers
                continue
            if INTERESTING_COMMENT.search(text):
                rows.append([page.url, text[:200]])
    if not rows:
        return []
    return [
        Finding(
            test_id="code_comments",
            title="Interesting HTML comments found",
            severity=Severity.INFO,
            confidence=Confidence.UNCONFIRMED,
            port=context.port,
            table=Table(columns=["URL", "Comment"], rows=rows[:20]),
            risk_description=(
                "The risk is that developer comments left in the delivered HTML can disclose "
                "internal endpoints, credentials, or known weaknesses in the application."
            ),
            recommendation=(
                "Strip comments from production templates as part of the build process and "
                "review the ones that must remain."
            ),
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage",
            ],
            classification=misconfig("CWE-615"),
        )
    ]


SENSITIVE_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID"),
    (re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}"), "AWS secret key"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "GitHub token"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "Google API key"),
    (re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "Stripe live secret key"),
    (re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), "Slack token"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), "JSON Web Token"),
    (re.compile(r"(?i)\b(mysql|postgres(?:ql)?|mongodb(?:\+srv)?)://[^\s:@/]+:[^\s:@/]+@"), "Database connection string with credentials"),
    (re.compile(r"(?i)\b(?:api[_\-]?key|secret|passwd|password)['\"]?\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"), "Hard-coded credential"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "US Social Security Number pattern"),
]


@check("sensitive_data", "Scanned for sensitive data", order=74)
def sensitive_data(context: ScanContext) -> list[Finding]:
    rows: list[list[str]] = []
    for page in context.crawl.pages:
        for pattern, label in SENSITIVE_PATTERNS:
            match = pattern.search(page.response.text)
            if match:
                rows.append([page.url, label, _redact(match.group(0))])
    if not rows:
        return []
    return [
        Finding(
            test_id="sensitive_data",
            title="Sensitive data exposed in responses",
            severity=Severity.HIGH,
            confidence=Confidence.UNCONFIRMED,
            port=context.port,
            table=Table(columns=["URL", "Type", "Evidence"], rows=rows[:20]),
            risk_description=(
                "The risk is that credentials or personal data served to any visitor can be "
                "collected and used directly — an exposed API key or connection string often "
                "grants immediate access to back-end systems."
            ),
            recommendation=(
                "Remove the secret from the client-side code, rotate it immediately since it "
                "must be considered compromised, and keep secrets in server-side configuration."
            ),
            references=[
                "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            ],
            classification=Classification(
                cwe=["CWE-200", "CWE-798"],
                owasp_2017=["A3 - Sensitive Data Exposure"],
                owasp_2021=["A2 - Cryptographic Failures"],
                owasp_2025=["A03 - Cryptographic Failures"],
                cisa_kev=False,
            ),
        )
    ]


PEM_FULL = re.compile(
    r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"
    r"[\s\S]{40,}?-----END (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"
)
PEM_HEADER = re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")


@check("pem_private_key", "Scanned for PEM-encoded private key material", order=75)
def pem_private_key(context: ScanContext) -> list[Finding]:
    rows = [
        [page.url, "Complete PEM private key block found in the response body"]
        for page in context.crawl.pages
        if PEM_FULL.search(page.response.text)
    ]
    if not rows:
        return []
    return [
        Finding(
            test_id="pem_private_key",
            title="PEM-encoded private key exposed",
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(columns=["URL", "Evidence"], rows=rows),
            risk_description=(
                "The risk is total: anyone who downloads the private key can decrypt "
                "intercepted traffic, impersonate the server, or authenticate as the key's "
                "owner."
            ),
            recommendation=(
                "Remove the key from the web root immediately, treat it as compromised, "
                "generate a new key pair and revoke the old certificate."
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/312.html",
            ],
            classification=Classification(
                cwe=["CWE-312"],
                owasp_2017=["A3 - Sensitive Data Exposure"],
                owasp_2021=["A2 - Cryptographic Failures"],
                owasp_2025=["A03 - Cryptographic Failures"],
                cisa_kev=False,
            ),
        )
    ]


@check("pem_partial_key", "Scanned for partial PEM-encoded private key material", order=76)
def pem_partial_key(context: ScanContext) -> list[Finding]:
    rows = [
        [page.url, "A PEM private key header was found without a complete key block"]
        for page in context.crawl.pages
        if PEM_HEADER.search(page.response.text) and not PEM_FULL.search(page.response.text)
    ]
    if not rows:
        return []
    return [
        Finding(
            test_id="pem_partial_key",
            title="Partial PEM-encoded private key material found",
            severity=Severity.MEDIUM,
            confidence=Confidence.UNCONFIRMED,
            port=context.port,
            table=Table(columns=["URL", "Evidence"], rows=rows),
            risk_description=(
                "The risk is that a truncated key block indicates key material is handled or "
                "stored inside content served to users. Even a fragment narrows the search "
                "space for an attacker and points at where the full key lives."
            ),
            recommendation=(
                "Locate the source of the key material and remove it from anything served to "
                "clients; rotate the key if any part of it was published."
            ),
            references=["https://cwe.mitre.org/data/definitions/312.html"],
            classification=Classification(
                cwe=["CWE-312"],
                owasp_2017=["A3 - Sensitive Data Exposure"],
                owasp_2021=["A2 - Cryptographic Failures"],
                owasp_2025=["A03 - Cryptographic Failures"],
                cisa_kev=False,
            ),
        )
    ]


PATH_PATTERNS = [
    re.compile(r"[A-Za-z]:\\(?:Users|inetpub|wwwroot|xampp|www)\\[^\s\"'<>]{3,}"),
    re.compile(r"/(?:var/www|home/\w+|usr/local|opt|srv)/[^\s\"'<>:]{3,}"),
    re.compile(r"(?i)in /[^\s\"'<>]+\.(?:php|py|rb|js|java) on line \d+"),
]


@check("path_disclosure", "Scanned for Path Disclosure", order=77)
def path_disclosure(context: ScanContext) -> list[Finding]:
    rows: list[list[str]] = []
    for page in context.crawl.pages:
        for pattern in PATH_PATTERNS:
            match = pattern.search(page.response.text)
            if match:
                rows.append([page.url, match.group(0)[:160]])
                break
    if not rows:
        return []
    return [
        Finding(
            test_id="path_disclosure",
            title="Full path disclosure",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(columns=["URL", "Disclosed path"], rows=rows[:20]),
            risk_description=(
                "The risk is that knowing the absolute path of the web root helps an attacker "
                "exploit file inclusion, file upload and log poisoning issues that would "
                "otherwise require guessing."
            ),
            recommendation=(
                "Suppress the errors and messages that print server paths, and return generic "
                "error pages to users."
            ),
            references=[
                "https://owasp.org/www-community/attacks/Full_Path_Disclosure",
            ],
            classification=misconfig("CWE-200"),
        )
    ]


@check("internal_error_code", "Scanned for internal error code", order=78)
def internal_error_code(context: ScanContext) -> list[Finding]:
    rows = [
        [page.url, str(page.response.status_code),
         f"Server returned an internal error status ({page.response.status_code})"]
        for page in context.crawl.pages
        if 500 <= page.response.status_code < 600
    ]
    if not rows:
        return []
    return [
        Finding(
            test_id="internal_error_code",
            title="Internal server error returned",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(columns=["URL", "Status", "Evidence"], rows=rows[:20]),
            risk_description=(
                "The risk is that unhandled server errors indicate code paths that were not "
                "anticipated. They are frequently the visible symptom of an injection or "
                "deserialization flaw, and often leak diagnostic detail."
            ),
            recommendation=(
                "Investigate the failing requests in the server logs, fix the underlying error "
                "and return a generic error page to users."
            ),
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/",
            ],
            classification=misconfig("CWE-388"),
        )
    ]


SESSION_PARAM = re.compile(
    r"(?i)^(jsessionid|phpsessid|asp\.net_sessionid|sid|session|session_id|sessionid|"
    r"auth_token|access_token|token|api_key|apikey)$"
)


@check("session_token_in_url", "Scanned for Session Token in URL", order=79)
def session_token_in_url(context: ScanContext) -> list[Finding]:
    rows: list[list[str]] = []
    seen: set[str] = set()
    candidates = [page.url for page in context.crawl.pages]
    candidates += [link for page in context.crawl.pages for link in page.links]
    for url in candidates:
        for name, _value in parse_qsl(urlparse(url).query):
            if SESSION_PARAM.match(name) and url not in seen:
                seen.add(url)
                rows.append([url, name, "Session or authentication token passed in the URL"])
    if not rows:
        return []
    return [
        Finding(
            test_id="session_token_in_url",
            title="Session token exposed in URL",
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(columns=["URL", "Parameter", "Evidence"], rows=rows[:20]),
            risk_description=(
                "The risk is that tokens in URLs leak through browser history, proxy and "
                "server logs, and the Referer header sent to third-party sites, allowing "
                "session hijacking."
            ),
            recommendation=(
                "Carry session identifiers in cookies with the HttpOnly, Secure and SameSite "
                "attributes instead of in query parameters."
            ),
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
            ],
            classification=Classification(
                cwe=["CWE-598"],
                owasp_2017=["A2 - Broken Authentication"],
                owasp_2021=["A7 - Identification and Authentication Failures"],
                owasp_2025=["A07 - Authentication Failures"],
            ),
        )
    ]


PASSWORD_PARAM = re.compile(r"(?i)^(password|passwd|pwd|pass|user_password)$")


@check("password_in_url", "Scanned for passwords submitted in URLs", order=80)
def password_in_url(context: ScanContext) -> list[Finding]:
    rows: list[list[str]] = []
    urls = [page.url for page in context.crawl.pages]
    urls += [link for page in context.crawl.pages for link in page.links]
    for form in context.crawl.forms:
        if form.method == "GET" and form.has_password:
            rows.append([form.action, "form field",
                         "A password field is submitted via a GET form, placing it in the URL"])
    seen: set[str] = set()
    for url in urls:
        for name, _value in parse_qsl(urlparse(url).query):
            if PASSWORD_PARAM.match(name) and url not in seen:
                seen.add(url)
                rows.append([url, name, "Password value present in the query string"])
    if not rows:
        return []
    return [
        Finding(
            test_id="password_in_url",
            title="Password submitted in URL",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            port=context.port,
            table=Table(columns=["URL", "Parameter", "Evidence"], rows=rows[:20]),
            risk_description=(
                "The risk is that the password is recorded in browser history, web server "
                "access logs, and any intermediate proxy, where it can be read long after "
                "the request was made."
            ),
            recommendation=(
                "Submit credentials in the body of a POST request over HTTPS, never as URL "
                "parameters."
            ),
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            ],
            classification=Classification(
                cwe=["CWE-598"],
                owasp_2017=["A2 - Broken Authentication"],
                owasp_2021=["A7 - Identification and Authentication Failures"],
                owasp_2025=["A07 - Authentication Failures"],
            ),
        )
    ]


SQL_IN_PARAM = re.compile(
    r"(?i)\b(select\s+.+\s+from\s+|insert\s+into\s+|update\s+\w+\s+set\s+|"
    r"delete\s+from\s+|union\s+(all\s+)?select\b|drop\s+table\s+)"
)


@check("sql_in_parameter", "Scanned for SQL statement in request parameter", order=81)
def sql_in_parameter(context: ScanContext) -> list[Finding]:
    rows: list[list[str]] = []
    urls = [page.url for page in context.crawl.pages]
    urls += [link for page in context.crawl.pages for link in page.links]
    seen: set[str] = set()
    for url in urls:
        for name, value in parse_qsl(urlparse(url).query):
            if SQL_IN_PARAM.search(value) and (url, name) not in seen:
                seen.add((url, name))
                rows.append([url, name, value[:160]])
    if not rows:
        return []
    return [
        Finding(
            test_id="sql_in_parameter",
            title="SQL statement passed in a request parameter",
            severity=Severity.HIGH,
            confidence=Confidence.UNCONFIRMED,
            port=context.port,
            table=Table(columns=["URL", "Parameter", "Value"], rows=rows[:20]),
            risk_description=(
                "The risk is that the application accepts SQL fragments from the client. If "
                "any part of that value reaches the database engine, an attacker controls the "
                "query and can read or modify the entire database."
            ),
            recommendation=(
                "Never build queries from client input. Move the query server-side and use "
                "parameterized statements."
            ),
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            ],
            classification=Classification(
                cwe=["CWE-89"],
                owasp_2017=["A1 - Injection"],
                owasp_2021=["A3 - Injection"],
                owasp_2025=["A03 - Injection"],
            ),
        )
    ]


@check("password_in_response", "Scanned for password returned in later response", order=82)
def password_in_response(context: ScanContext) -> list[Finding]:
    pattern = re.compile(
        r"(?i)[\"']?(password|passwd|pwd|user_password)[\"']?\s*[:=]\s*[\"'][^\"']{4,}[\"']"
    )
    rows: list[list[str]] = []
    for page in context.crawl.pages:
        match = pattern.search(page.response.text)
        if not match:
            continue
        # Empty values and placeholders are how login forms legitimately render.
        if re.search(r"(?i)[\"'](|null|undefined|\*+|\.\.\.)[\"']\s*$", match.group(0)):
            continue
        rows.append([page.url, _redact(match.group(0))])
    if not rows:
        return []
    return [
        Finding(
            test_id="password_in_response",
            title="Password value returned in a response",
            severity=Severity.HIGH,
            confidence=Confidence.UNCONFIRMED,
            port=context.port,
            table=Table(columns=["URL", "Evidence"], rows=rows[:20]),
            risk_description=(
                "The risk is that a password echoed back in a response body can be captured "
                "from caches, logs and browser storage, and indicates the password is stored "
                "in a recoverable form rather than hashed."
            ),
            recommendation=(
                "Never return password values to the client. Store passwords only as salted "
                "hashes using a memory-hard algorithm such as Argon2id or bcrypt."
            ),
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
            ],
            classification=Classification(
                cwe=["CWE-256"],
                owasp_2017=["A3 - Sensitive Data Exposure"],
                owasp_2021=["A2 - Cryptographic Failures"],
                owasp_2025=["A03 - Cryptographic Failures"],
            ),
        )
    ]


def _snippet(text: str, match: re.Match, width: int = 80) -> str:
    start = max(0, match.start() - 20)
    return " ".join(text[start : match.end() + width].split())[:200]


def _redact(value: str, keep: int = 6) -> str:
    if len(value) <= keep * 2:
        return value
    return f"{value[:keep]}…{value[-keep:]} ({len(value)} chars)"
