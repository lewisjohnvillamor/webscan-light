"""Unified source-code security scan — point it at a folder.

Bundles four defensive, read-only passes into one report:
  1. Supply-chain / npm-poisoning heuristics (package.json + package-lock.json)
  2. Lightweight SAST (risky code patterns per language)
  3. Config / IaC checks (.env, Dockerfile, GitHub Actions, Kubernetes)
  4. Hard-coded secrets (reuses the secrets scanner's patterns)

Nothing is executed. It reads files, matches patterns and reports file:line
findings into the same report model as every other tool.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from webscan.core.models import Classification, Confidence, Finding, Severity, Table
from webscan.core.toolreport import Section, ToolReport

from .base import ToolOptions, tool
from .manifests import SKIP_DIRS
from .secrets import PATTERNS as SECRET_PATTERNS
from .secrets import PLACEHOLDER, SKIP_EXT, _redact

OWASP_INJ = dict(owasp_2021=["A03 - Injection"], owasp_2025=["A03 - Injection"])
OWASP_MISC = dict(owasp_2021=["A05 - Security Misconfiguration"],
                  owasp_2025=["A02 - Security Misconfiguration"])
OWASP_COMP = dict(owasp_2021=["A06 - Vulnerable & Outdated Components"],
                  owasp_2025=["A06 - Vulnerable & Outdated Components"])
OWASP_CRYPTO = dict(owasp_2021=["A02 - Cryptographic Failures"],
                    owasp_2025=["A04 - Cryptographic Failures"])

# ---- lightweight SAST rules: (id, label, regex, severity, cwe, recommendation, owasp) ----
SAST = [
    ("eval", "Dynamic code evaluation (eval)", re.compile(r"\beval\s*\("),
     Severity.MEDIUM, ["CWE-95"], "Avoid eval; parse/validate input or use safe alternatives.", OWASP_INJ),
    ("py_exec", "Dynamic code execution (exec)", re.compile(r"(?<![A-Za-z_])exec\s*\("),
     Severity.MEDIUM, ["CWE-95"], "Avoid exec on dynamic input.", OWASP_INJ),
    ("os_command", "Shell command execution", re.compile(
        r"os\.system\s*\(|subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True|child_process\.(?:exec|execSync)\s*\("),
     Severity.HIGH, ["CWE-78"], "Never build shell commands from untrusted input; pass argv lists, avoid shell=True.",
     OWASP_INJ),
    ("sql_fmt", "Possible SQL built from a string", re.compile(
        r"(?i)(?:execute|query|cursor\.execute)\s*\(\s*[f\"'].*(?:select|insert|update|delete|drop)\b.*(?:\{|%s|%d|\"\s*\+|'\s*\+)"),
     Severity.MEDIUM, ["CWE-89"], "Use parameterised queries / prepared statements, never string formatting.",
     OWASP_INJ),
    ("deserialize", "Unsafe deserialization", re.compile(
        r"pickle\.loads?\s*\(|cPickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Loader)|marshal\.loads\s*\(|"
        r"\bunserialize\s*\(|readObject\s*\("),
     Severity.HIGH, ["CWE-502"], "Avoid deserializing untrusted data; use safe loaders (yaml.safe_load, JSON).",
     OWASP_INJ),
    ("weak_hash", "Weak hashing algorithm", re.compile(
        r"(?:hashlib\.)?\bmd5\s*\(|(?:hashlib\.)?\bsha1\s*\(|createHash\(\s*['\"](?:md5|sha1)['\"]"),
     Severity.LOW, ["CWE-327"], "Use SHA-256+ for integrity; bcrypt/scrypt/argon2 for passwords.", OWASP_CRYPTO),
    ("tls_off", "TLS verification disabled", re.compile(
        r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|"
        r"CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:0|false)|NODE_TLS_REJECT_UNAUTHORIZED"),
     Severity.HIGH, ["CWE-295"], "Never disable certificate verification in production.", OWASP_MISC),
    ("cors_any", "Permissive CORS (wildcard origin)", re.compile(
        r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*|cors\(\s*\{\s*origin\s*:\s*['\"]\*['\"]"),
     Severity.MEDIUM, ["CWE-942"], "Reflect an allow-list of trusted origins instead of '*'.", OWASP_MISC),
    ("debug_on", "Debug mode enabled", re.compile(r"(?i)\bdebug\s*=\s*True\b|app\.run\([^)]*debug\s*=\s*True"),
     Severity.LOW, ["CWE-489"], "Disable debug mode in production builds.", OWASP_MISC),
]

CODE_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".go", ".rb", ".php",
            ".java", ".cs", ".c", ".cpp", ".sh", ".yml", ".yaml", ".tf"}

POPULAR = ["react", "lodash", "express", "chalk", "axios", "next", "vue", "webpack",
           "dotenv", "request", "commander", "debug", "async", "moment", "uuid",
           "colors", "cross-env", "node-fetch", "typescript", "eslint", "jest",
           "babel", "rimraf", "yargs", "glob", "bluebird", "underscore"]


def _lev1(a: str, b: str) -> bool:
    """True if edit distance between a and b is exactly 1 (cheap, bounded)."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        return sum(1 for x, y in zip(a, b, strict=True) if x != y) == 1
    short, lng = (a, b) if la < lb else (b, a)
    i = j = 0
    diff = 0
    while i < len(short) and j < len(lng):
        if short[i] != lng[j]:
            diff += 1
            if diff > 1:
                return False
            j += 1
        else:
            i += 1
            j += 1
    return True


def _iter_files(base: Path, max_files: int):
    if base.is_file():
        yield base
        return
    count = 0
    for p in base.rglob("*"):
        if count >= max_files:
            break
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() in SKIP_EXT:
            continue
        count += 1
        yield p


def _read(path: Path) -> str | None:
    try:
        if path.stat().st_size > 2_000_000:
            return None
        raw = path.read_bytes()
        if b"\x00" in raw[:1024]:
            return None
        return raw.decode("utf-8", "replace")
    except OSError:
        return None


def _finding(test_id, title, severity, hits, risk, rec, cwe, owasp):
    return Finding(
        test_id=test_id, title=f"{title} ({len(hits)})", severity=severity,
        confidence=Confidence.CONFIRMED,
        table=Table(["File", "Line", "Evidence"], [[h[0], h[1], h[2]] for h in hits[:50]]),
        risk_description=risk, recommendation=rec,
        classification=Classification(cwe=cwe, **owasp))


def _supply_chain(base: Path, rel):
    """npm-poisoning / supply-chain heuristics from package.json + lockfile."""
    findings = []
    # own install scripts + typosquats from package.json files
    typos, scripts = [], []
    for pj in ([base] if base.is_file() and base.name == "package.json"
               else base.rglob("package.json") if base.is_dir() else []):
        if any(part in SKIP_DIRS for part in pj.parts):
            continue
        txt = _read(pj)
        if not txt:
            continue
        try:
            data = json.loads(txt)
        except json.JSONDecodeError:
            continue
        r = rel(pj)
        for hook in ("preinstall", "install", "postinstall"):
            if isinstance(data.get("scripts"), dict) and hook in data["scripts"]:
                scripts.append([r, hook, data["scripts"][hook][:80]])
        deps = {}
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            if isinstance(data.get(key), dict):
                deps.update(data[key])
        for name in deps:
            base_name = name.split("/")[-1]
            for pop in POPULAR:
                if _lev1(base_name.lower(), pop):
                    typos.append([r, name, f"looks like '{pop}'"])
                    break
    if scripts:
        findings.append(_finding(
            "sc_install_scripts", "Install lifecycle scripts defined", Severity.LOW, scripts,
            "preinstall/install/postinstall scripts run automatically on `npm install`; they are "
            "the primary vector for malicious packages and compromised builds.",
            "Review these scripts and any dependency that ships them; prefer --ignore-scripts in CI.",
            ["CWE-829"], OWASP_COMP))
    if typos:
        findings.append(_finding(
            "sc_typosquat", "Possible typosquatted dependency", Severity.HIGH, typos,
            "A dependency name one character away from a very popular package is a classic "
            "typosquatting / package-confusion attack.",
            "Verify the package is the intended one; pin to the correct name and a known-good version.",
            ["CWE-427"], OWASP_COMP))

    # lockfile: install scripts in deps, non-registry sources, missing integrity
    installs, nonreg, nointeg = [], [], []
    locks = ([base] if base.is_file() and base.name == "package-lock.json"
             else base.rglob("package-lock.json") if base.is_dir() else [])
    for lock in locks:
        if any(part in SKIP_DIRS for part in lock.parts):
            continue
        txt = _read(lock)
        if not txt:
            continue
        try:
            data = json.loads(txt)
        except json.JSONDecodeError:
            continue
        r = rel(lock)
        for pkgpath, meta in (data.get("packages") or {}).items():
            if not pkgpath or not isinstance(meta, dict):
                continue
            nm = pkgpath.split("node_modules/")[-1]
            if meta.get("hasInstallScript"):
                installs.append([r, nm, "hasInstallScript"])
            resolved = meta.get("resolved") or ""
            if resolved and not resolved.startswith(("https://registry.npmjs.org/",
                                                     "https://registry.yarnpkg.com/")):
                nonreg.append([r, nm, resolved[:70]])
            if meta.get("version") and resolved and not meta.get("integrity"):
                nointeg.append([r, nm, meta.get("version", "")])
    if installs:
        findings.append(_finding(
            "sc_dep_install_scripts", "Dependency runs install scripts", Severity.MEDIUM, installs,
            "Third-party packages that run install scripts execute arbitrary code on your machine "
            "and CI at install time — the main delivery path for poisoned npm packages.",
            "Audit these packages; run CI installs with --ignore-scripts and an allow-list.",
            ["CWE-829"], OWASP_COMP))
    if nonreg:
        findings.append(_finding(
            "sc_nonregistry", "Dependency resolved from a non-registry source", Severity.MEDIUM, nonreg,
            "Packages pulled from git/HTTP URLs instead of the public registry bypass registry "
            "integrity and can be swapped silently.",
            "Pin to registry releases with integrity hashes; review any git/URL dependency.",
            ["CWE-829"], OWASP_COMP))
    if nointeg:
        findings.append(_finding(
            "sc_no_integrity", "Dependency without an integrity hash", Severity.LOW, nointeg,
            "A lockfile entry without an integrity hash is not tamper-evident.",
            "Regenerate the lockfile so every entry carries an integrity (SRI) hash.",
            ["CWE-353"], OWASP_COMP))
    return findings


IAC = [
    ("iac_privileged", "Privileged container", re.compile(r"privileged\s*:\s*true"),
     Severity.HIGH, ["CWE-250"], "Drop privileged; grant only the specific capabilities needed."),
    ("iac_hostnet", "Host network enabled", re.compile(r"hostNetwork\s*:\s*true"),
     Severity.MEDIUM, ["CWE-668"], "Avoid hostNetwork unless strictly required."),
    ("iac_runasroot", "Container runs as root (UID 0)", re.compile(r"runAsUser\s*:\s*0\b"),
     Severity.MEDIUM, ["CWE-250"], "Run as a non-root UID."),
    ("iac_privesc", "Privilege escalation allowed", re.compile(r"allowPrivilegeEscalation\s*:\s*true"),
     Severity.LOW, ["CWE-250"], "Set allowPrivilegeEscalation: false."),
    ("iac_ghperms", "GitHub Actions write-all permissions", re.compile(r"permissions\s*:\s*write-all"),
     Severity.MEDIUM, ["CWE-732"], "Grant least-privilege permissions per workflow/job."),
    ("iac_pr_target", "Workflow uses pull_request_target", re.compile(r"pull_request_target"),
     Severity.MEDIUM, ["CWE-269"], "pull_request_target runs with secrets; never check out & run untrusted PR code."),
    ("iac_remote_pipe", "Remote script piped to a shell", re.compile(
        r"(?:curl|wget)\s+[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh"),
     Severity.MEDIUM, ["CWE-494"], "Download, verify a checksum, then run — don't pipe the network to a shell."),
]


def _config_iac(base: Path, rel):
    findings = []
    env_hits, docker_hits, unpinned = [], [], []
    iac_hits = {r[0]: [] for r in IAC}
    for path in _iter_files(base, 20000):
        name = path.name
        low = name.lower()
        is_dockerfile = low == "dockerfile" or low.startswith("dockerfile.")
        is_workflow = ".github/workflows/" in str(path).replace("\\", "/") and path.suffix in (".yml", ".yaml")
        is_yaml = path.suffix in (".yml", ".yaml")
        # committed .env (not examples/templates)
        if (low == ".env" or low.startswith(".env.")) and "example" not in low and "sample" not in low \
                and "template" not in low and "dist" not in low:
            txt = _read(path) or ""
            if re.search(r"^[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S", txt, re.M):
                env_hits.append([rel(path), "1", "committed environment file with values"])
        if not (is_dockerfile or is_yaml):
            continue
        txt = _read(path)
        if not txt:
            continue
        has_user = False
        for i, line in enumerate(txt.splitlines(), 1):
            if is_dockerfile:
                if re.match(r"\s*USER\s+", line):
                    has_user = True
                    if re.match(r"\s*USER\s+root\b", line):
                        docker_hits.append([rel(path), str(i), "USER root"])
                if re.search(r"^\s*FROM\s+\S+(?::latest)?\s*$", line) and ":" not in line.split("FROM")[1]:
                    docker_hits.append([rel(path), str(i), "FROM without a pinned tag"])
                elif re.search(r"^\s*FROM\s+\S+:latest\b", line):
                    docker_hits.append([rel(path), str(i), "FROM ...:latest"])
            if is_workflow:
                m = re.search(r"uses\s*:\s*([A-Za-z0-9._\-]+/[A-Za-z0-9._\-]+)@([^\s#]+)", line)
                if m and not re.fullmatch(r"[0-9a-f]{40}", m.group(2)):
                    unpinned.append([rel(path), str(i), f"{m.group(1)}@{m.group(2)}"])
            for rid, _lbl, rx, _sev, _cwe, _rec in IAC:
                if rx.search(line):
                    iac_hits[rid].append([rel(path), str(i), line.strip()[:80]])
        if is_dockerfile and not has_user:
            docker_hits.append([rel(path), "1", "no USER instruction (runs as root)"])

    if env_hits:
        findings.append(_finding(
            "cfg_env_committed", "Environment file committed to the repo", Severity.MEDIUM, env_hits,
            "A committed .env typically contains real secrets and configuration.",
            "Remove it, rotate any secrets, add it to .gitignore, ship a .env.example instead.",
            ["CWE-538"], OWASP_MISC))
    if docker_hits:
        findings.append(_finding(
            "cfg_dockerfile", "Dockerfile hardening issues", Severity.LOW, docker_hits,
            "Running as root and unpinned base images weaken container isolation and reproducibility.",
            "Add a non-root USER, pin base images to a digest/tag, and minimise the image.",
            ["CWE-250"], OWASP_MISC))
    if unpinned:
        findings.append(_finding(
            "cfg_unpinned_action", "Unpinned GitHub Action", Severity.LOW, unpinned,
            "Actions referenced by tag/branch can change under you; a compromised tag runs in your CI.",
            "Pin third-party actions to a full commit SHA.",
            ["CWE-829"], OWASP_COMP))
    for rid, lbl, _rx, sev, cwe, rec in IAC:
        if iac_hits[rid]:
            findings.append(_finding(f"cfg_{rid}", lbl, sev, iac_hits[rid],
                                     f"{lbl} detected in configuration.", rec, cwe, OWASP_MISC))
    return findings


@tool(id="code", name="Code Security Scan", category="Vulnerability", glyph="COD",
      order=55, local_fs=True, target_hint="path to a project directory",
      description="Scan a local codebase: supply-chain / npm-poisoning, SAST, IaC and secrets.")
def run(target: str, options: ToolOptions) -> ToolReport:
    report = ToolReport(tool="code", tool_name="Code Security Scan", target=target)
    report.params = [("Path", target)]
    base = Path(target)
    if not base.exists():
        report.errors.append(f"Path not found: {target}")
        return report.finish("Failed")

    def rel(p: Path) -> str:
        try:
            return str(p.relative_to(base)) if base.is_dir() else p.name
        except ValueError:
            return str(p)

    max_files = options.max_items or 8000
    sast_hits = {r[0]: [] for r in SAST}
    secret_hits: dict[str, list] = {}
    scanned = 0
    for path in _iter_files(base, max_files):
        if path.suffix.lower() not in CODE_EXT and path.name not in (
                ".env",) and not path.name.lower().startswith((".env", "dockerfile")):
            # still scan generic text for secrets, but skip SAST on non-code
            code_file = False
        else:
            code_file = path.suffix.lower() in CODE_EXT
        text = _read(path)
        if text is None:
            continue
        scanned += 1
        r = rel(path)
        for lineno, line in enumerate(text.splitlines(), 1):
            if len(line) > 1000:
                continue
            if code_file:
                for rid, _lbl, rx, _sev, _cwe, _rec, _ow in SAST:
                    m = rx.search(line)
                    if m:
                        sast_hits[rid].append([r, str(lineno), line.strip()[:90]])
            for label, pattern, _sev in SECRET_PATTERNS:
                m = pattern.search(line)
                if m and not PLACEHOLDER.search(m.group(0)):
                    secret_hits.setdefault(label, []).append([r, str(lineno), _redact(m.group(0))])

    # assemble findings
    for rid, lbl, _rx, sev, cwe, rec, ow in SAST:
        if sast_hits[rid]:
            report.findings.append(_finding(
                f"sast_{rid}", lbl, sev, sast_hits[rid],
                f"{lbl}: a risky code pattern that frequently leads to vulnerabilities.", rec, cwe, ow))
    report.findings.extend(_supply_chain(base, rel))
    report.findings.extend(_config_iac(base, rel))
    for label, hits in sorted(secret_hits.items()):
        sev = next(s for (lbl, _p, s) in SECRET_PATTERNS if lbl == label)
        report.findings.append(_finding(
            f"secret_{label.lower().replace(' ', '_')[:20]}", f"Hard-coded secret: {label}", sev, hits,
            "Secrets committed to source are exposed to anyone with repo access and often leak publicly.",
            "Remove and rotate the secret; load it from env/secret-manager; purge it from git history.",
            ["CWE-798"], OWASP_MISC))

    totals = {k: 0 for k in ("sast", "supply", "iac", "secret")}
    prefix = {"sast_": "sast", "sc_": "supply", "cfg_": "iac",
              "secret_": "secret"}  # nosec B105: dict of test-id prefixes, not a password
    for f in report.findings:
        for pre, key in prefix.items():
            if f.test_id.startswith(pre):
                totals[key] += 1
                break
    report.stats = [("Files scanned", str(scanned)), ("SAST", str(totals["sast"])),
                    ("Supply-chain", str(totals["supply"])), ("Config/IaC", str(totals["iac"])),
                    ("Secrets", str(totals["secret"]))]
    if not report.findings:
        report.sections.append(Section(title="No code-level issues detected",
                                       intro="None of the SAST, supply-chain, IaC or secret checks matched."))
    return report.finish()
