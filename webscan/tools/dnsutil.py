"""DNS lookups over DoH (no extra dependency) with a plain-socket fallback."""
from __future__ import annotations

import socket
from functools import lru_cache

import requests

DOH_ENDPOINTS = ("https://dns.google/resolve", "https://cloudflare-dns.com/dns-query")


@lru_cache(maxsize=2048)
def resolve(name: str, rtype: str = "A", timeout: float = 8.0) -> tuple[str, ...]:
    """Return record values for ``name`` of type ``rtype`` (A, AAAA, CNAME, TXT, MX, NS)."""
    for endpoint in DOH_ENDPOINTS:
        try:
            response = requests.get(
                endpoint,
                params={"name": name, "type": rtype},
                headers={"Accept": "application/dns-json"},
                timeout=timeout,
            )
            if response.status_code != 200:
                continue
            answers = response.json().get("Answer") or []
            values = [a["data"].strip('"') for a in answers if "data" in a]
            if values or response.json().get("Status") == 3:  # 3 = NXDOMAIN
                return tuple(values)
        except (requests.RequestException, ValueError):
            continue
    # Fallback for A records only.
    if rtype == "A":
        try:
            return tuple({info[4][0] for info in socket.getaddrinfo(name, None, socket.AF_INET)})
        except OSError:
            return ()
    return ()


def resolves(name: str, timeout: float = 8.0) -> bool:
    return bool(resolve(name, "A", timeout) or resolve(name, "AAAA", timeout)
                or resolve(name, "CNAME", timeout))
