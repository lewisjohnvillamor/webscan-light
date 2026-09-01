"""OSV.dev client — free, keyless vulnerability data for open-source packages."""
from __future__ import annotations

import json

import requests

from . import cache

BATCH_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns/"


class OSV:
    def __init__(self, offline: bool = False, timeout: float = 20.0) -> None:
        self.offline = offline
        self.timeout = timeout
        self.session = requests.Session()
        self.errors: list[str] = []

    def query(self, deps: list[dict]) -> dict[tuple, list[str]]:
        """Map (ecosystem,name,version) -> [vuln ids]. Cached per package."""
        result: dict[tuple, list[str]] = {}
        pending: list[dict] = []
        for dep in deps:
            key = (dep["ecosystem"], dep["name"], dep["version"])
            cached = cache.get("osv", "|".join(key), max_age=86_400)
            if cached is not None:
                result[key] = cached
            else:
                pending.append(dep)
        if pending and not self.offline:
            for start in range(0, len(pending), 100):
                batch = pending[start:start + 100]
                queries = [{"package": {"ecosystem": d["ecosystem"], "name": d["name"]},
                            "version": d["version"]} for d in batch]
                try:
                    resp = self.session.post(BATCH_URL, json={"queries": queries},
                                             timeout=self.timeout)
                    resp.raise_for_status()
                    results = resp.json().get("results", [])
                except (requests.RequestException, json.JSONDecodeError) as exc:
                    self.errors.append(f"OSV query failed: {type(exc).__name__}")
                    break
                for dep, res in zip(batch, results):
                    key = (dep["ecosystem"], dep["name"], dep["version"])
                    ids = [v["id"] for v in (res.get("vulns") or [])]
                    result[key] = ids
                    cache.put("osv", "|".join(key), ids)
        return result

    def details(self, vuln_id: str) -> dict:
        cached = cache.get("osv_detail", vuln_id, max_age=86_400 * 7)
        if cached is not None:
            return cached
        if self.offline:
            return {}
        try:
            resp = self.session.get(VULN_URL + vuln_id, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, json.JSONDecodeError):
            return {}
        summary = {
            "id": vuln_id,
            "summary": data.get("summary") or (data.get("details") or "")[:140],
            "severity": _severity(data),
            "aliases": data.get("aliases", []),
            "fixed": _fixed_version(data),
        }
        cache.put("osv_detail", vuln_id, summary)
        return summary


def _severity(data: dict) -> str:
    spec = (data.get("database_specific") or {}).get("severity")
    if spec:
        return str(spec).upper()
    for entry in data.get("affected", []):
        s = (entry.get("database_specific") or {}).get("severity")
        if s:
            return str(s).upper()
    return "UNKNOWN"


def _fixed_version(data: dict) -> str:
    for affected in data.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return ""
