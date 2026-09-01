"""Parse dependency manifests into (ecosystem, name, version) tuples for OSV."""
from __future__ import annotations

import json
import re
from pathlib import Path

MANIFEST_NAMES = {
    "requirements.txt", "requirements-dev.txt", "Pipfile.lock", "poetry.lock",
    "package-lock.json", "yarn.lock", "go.mod", "Cargo.lock", "composer.lock",
    "Gemfile.lock",
}
SKIP_DIRS = {"node_modules", ".git", "vendor", "venv", ".venv", "dist", "build", "__pycache__"}


def _pypi_req(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._+!-]+)", line)
        if m:
            out.append({"ecosystem": "PyPI", "name": m.group(1), "version": m.group(2)})
    return out


def _pipfile_lock(text: str) -> list[dict]:
    out = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return out
    for group in ("default", "develop"):
        for name, meta in (data.get(group) or {}).items():
            version = str(meta.get("version", "")).lstrip("=")
            if version:
                out.append({"ecosystem": "PyPI", "name": name, "version": version})
    return out


def _poetry_lock(text: str) -> list[dict]:
    out = []
    for block in text.split("[[package]]")[1:]:
        name = re.search(r'name\s*=\s*"([^"]+)"', block)
        version = re.search(r'version\s*=\s*"([^"]+)"', block)
        if name and version:
            out.append({"ecosystem": "PyPI", "name": name.group(1), "version": version.group(1)})
    return out


def _npm_lock(text: str) -> list[dict]:
    out = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return out
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfile v2/v3
        for path, meta in packages.items():
            if not path:
                continue
            name = path.split("node_modules/")[-1]
            version = meta.get("version")
            if name and version:
                out.append({"ecosystem": "npm", "name": name, "version": version})
    else:  # v1
        def walk(deps):
            for name, meta in (deps or {}).items():
                if meta.get("version"):
                    out.append({"ecosystem": "npm", "name": name, "version": meta["version"]})
                walk(meta.get("dependencies"))
        walk(data.get("dependencies"))
    return out


def _yarn_lock(text: str) -> list[dict]:
    out = []
    current = None
    for line in text.splitlines():
        if line and not line.startswith(" ") and line.rstrip().endswith(":"):
            spec = line.split(",")[0].strip().strip('"')
            current = spec.rsplit("@", 1)[0] if "@" in spec.lstrip("@") else spec
        elif current and line.strip().startswith("version"):
            m = re.search(r'"?([0-9][^"\s]*)"?', line.split("version", 1)[1])
            if m:
                out.append({"ecosystem": "npm", "name": current, "version": m.group(1)})
                current = None
    return out


def _go_mod(text: str) -> list[dict]:
    out = []
    for m in re.finditer(r"^\s*([\w./-]+)\s+v([0-9][\w.\-+]*)", text, re.M):
        if m.group(1) not in ("module", "go", "require", "toolchain"):
            out.append({"ecosystem": "Go", "name": m.group(1), "version": m.group(2)})
    return out


def _cargo_lock(text: str) -> list[dict]:
    out = []
    for block in text.split("[[package]]")[1:]:
        name = re.search(r'name\s*=\s*"([^"]+)"', block)
        version = re.search(r'version\s*=\s*"([^"]+)"', block)
        if name and version:
            out.append({"ecosystem": "crates.io", "name": name.group(1), "version": version.group(1)})
    return out


def _composer_lock(text: str) -> list[dict]:
    out = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return out
    for group in ("packages", "packages-dev"):
        for pkg in data.get(group) or []:
            version = str(pkg.get("version", "")).lstrip("v")
            if pkg.get("name") and version:
                out.append({"ecosystem": "Packagist", "name": pkg["name"], "version": version})
    return out


def _gemfile_lock(text: str) -> list[dict]:
    out = []
    for m in re.finditer(r"^\s{4}([a-zA-Z0-9._-]+) \(([0-9][^)]*)\)", text, re.M):
        out.append({"ecosystem": "RubyGems", "name": m.group(1), "version": m.group(2)})
    return out


_PARSERS = {
    "requirements.txt": _pypi_req, "requirements-dev.txt": _pypi_req,
    "Pipfile.lock": _pipfile_lock, "poetry.lock": _poetry_lock,
    "package-lock.json": _npm_lock, "yarn.lock": _yarn_lock,
    "go.mod": _go_mod, "Cargo.lock": _cargo_lock,
    "composer.lock": _composer_lock, "Gemfile.lock": _gemfile_lock,
}


def parse_file(path: Path) -> list[dict]:
    parser = _PARSERS.get(path.name)
    # Any *.txt that reads like pip requirements is fair game.
    if not parser and path.suffix == ".txt" and "requirement" in path.name.lower():
        parser = _pypi_req
    if not parser:
        return []
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return []
    deps = parser(text)
    for dep in deps:
        dep["source"] = path.name
    return deps


def find_and_parse(root: str, max_files: int = 50) -> list[dict]:
    """Walk ``root`` (dir or file), parse every recognised manifest."""
    base = Path(root)
    files: list[Path] = []
    if base.is_file():
        files = [base]
    else:
        for path in base.rglob("*"):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.name in MANIFEST_NAMES:
                files.append(path)
            if len(files) >= max_files:
                break
    deps: list[dict] = []
    seen: set[tuple] = set()
    for path in files:
        for dep in parse_file(path):
            key = (dep["ecosystem"], dep["name"], dep["version"])
            if key not in seen:
                seen.add(key)
                deps.append(dep)
    return deps
