"""Free vulnerability intelligence feeds: NVD, FIRST EPSS and CISA KEV.

Every lookup is cached on disk and every failure degrades to "no data" rather
than aborting the scan — the tool must stay useful offline.
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field

import requests

from . import cache
from .cpe import cpe_uri

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# NVD allows 5 requests / 30s without a key, 50 with one.
_nvd_lock = threading.Lock()
_last_nvd_call = 0.0


@dataclass
class CVE:
    id: str
    cvss: float | None = None
    summary: str = ""
    cwe: list[str] = field(default_factory=list)
    epss_score: float | None = None
    epss_percentile: float | None = None
    kev: bool = False

    def as_dict(self) -> dict:
        return {
            "id": self.id, "cvss": self.cvss, "summary": self.summary, "cwe": self.cwe,
            "epss_score": self.epss_score, "epss_percentile": self.epss_percentile,
            "kev": self.kev,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CVE":
        return cls(**data)


class Intel:
    """Vulnerability data lookups. Set ``offline`` to use only cached data."""

    def __init__(self, offline: bool = False, timeout: float = 30.0) -> None:
        self.offline = offline
        self.timeout = timeout
        self.api_key = os.environ.get("WEBSCAN_NVD_API_KEY", "").strip()
        self.session = requests.Session()
        self.errors: list[str] = []
        self._kev: set[str] | None = None

    # -- NVD ----------------------------------------------------------------
    def _throttle(self) -> None:
        global _last_nvd_call
        min_interval = 0.7 if self.api_key else 6.5
        with _nvd_lock:
            wait = min_interval - (time.monotonic() - _last_nvd_call)
            if wait > 0:
                time.sleep(wait)
            _last_nvd_call = time.monotonic()

    def cves_for(self, vendor_product: str, version: str) -> list[CVE]:
        """CVEs whose configurations cover ``vendor_product`` at ``version``."""
        key = f"{vendor_product}@{version}"
        cached = cache.get("nvd", key, max_age=86_400)
        if cached is not None:
            return [CVE.from_dict(item) for item in cached]
        if self.offline:
            return []

        params = {
            "virtualMatchString": cpe_uri(vendor_product, version),
            "resultsPerPage": "200",
        }
        headers = {"User-Agent": "webscan-light"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            self._throttle()
            response = self.session.get(
                NVD_URL, params=params, headers=headers, timeout=self.timeout
            )
            if response.status_code == 403:
                self.errors.append("NVD rate limit reached (set WEBSCAN_NVD_API_KEY for a higher quota)")
                return []
            response.raise_for_status()
            payload = response.json()
        except (requests.RequestException, json.JSONDecodeError) as exc:
            self.errors.append(f"NVD lookup failed for {key}: {type(exc).__name__}")
            return []

        cves = [self._parse_nvd_item(item) for item in payload.get("vulnerabilities", [])]
        cves = [cve for cve in cves if cve]
        cache.put("nvd", key, [cve.as_dict() for cve in cves])
        return cves

    @staticmethod
    def _parse_nvd_item(item: dict) -> CVE | None:
        data = item.get("cve") or {}
        cve_id = data.get("id")
        if not cve_id:
            return None
        summary = ""
        for description in data.get("descriptions", []):
            if description.get("lang") == "en":
                summary = " ".join(description.get("value", "").split())
                break
        score = None
        metrics = data.get("metrics") or {}
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                score = entries[0].get("cvssData", {}).get("baseScore")
                break
        cwes = []
        for weakness in data.get("weaknesses", []):
            for description in weakness.get("description", []):
                value = description.get("value", "")
                if value.startswith("CWE-") and value not in cwes:
                    cwes.append(value)
        return CVE(id=cve_id, cvss=score, summary=summary, cwe=cwes)

    # -- EPSS ---------------------------------------------------------------
    def enrich_epss(self, cves: list[CVE]) -> None:
        if not cves:
            return
        missing = []
        for cve in cves:
            cached = cache.get("epss", cve.id, max_age=86_400)
            if cached is not None:
                cve.epss_score = cached.get("epss")
                cve.epss_percentile = cached.get("percentile")
            else:
                missing.append(cve)
        if not missing or self.offline:
            return

        for batch_start in range(0, len(missing), 50):
            batch = missing[batch_start : batch_start + 50]
            try:
                response = self.session.get(
                    EPSS_URL,
                    params={"cve": ",".join(cve.id for cve in batch)},
                    timeout=self.timeout,
                )
                response.raise_for_status()
                payload = response.json()
            except (requests.RequestException, json.JSONDecodeError) as exc:
                self.errors.append(f"EPSS lookup failed: {type(exc).__name__}")
                return
            scores = {
                entry["cve"]: (float(entry["epss"]), float(entry["percentile"]))
                for entry in payload.get("data", [])
                if entry.get("cve")
            }
            for cve in batch:
                score, percentile = scores.get(cve.id, (None, None))
                cve.epss_score, cve.epss_percentile = score, percentile
                cache.put("epss", cve.id, {"epss": score, "percentile": percentile})

    # -- CISA KEV -----------------------------------------------------------
    def kev_ids(self) -> set[str]:
        if self._kev is not None:
            return self._kev
        cached = cache.get("kev", "catalog", max_age=86_400)
        if cached is None and not self.offline:
            try:
                response = self.session.get(KEV_URL, timeout=self.timeout)
                response.raise_for_status()
                cached = [item["cveID"] for item in response.json().get("vulnerabilities", [])]
                cache.put("kev", "catalog", cached)
            except (requests.RequestException, json.JSONDecodeError, KeyError) as exc:
                self.errors.append(f"CISA KEV download failed: {type(exc).__name__}")
                cached = []
        self._kev = set(cached or [])
        return self._kev

    def enrich_kev(self, cves: list[CVE]) -> None:
        known = self.kev_ids()
        for cve in cves:
            cve.kev = cve.id in known
