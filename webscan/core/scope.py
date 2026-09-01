"""Target scope policy — the SSRF guard for the exposed web layer.

The web UI lets a caller name any target, so on a reachable server it is an
SSRF primitive: it could be pointed at cloud metadata (169.254.169.254) or
internal hosts. This module resolves a target and decides whether it is in
scope. Private/loopback/link-local/reserved addresses are blocked unless the
operator explicitly opts in (WEBSCAN_ALLOW_PRIVATE=1), because scanning an
internal range is a legitimate self-hosted use — but it must be a deliberate
choice, not the default.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

METADATA_IPS = {"169.254.169.254", "fd00:ec2::254", "100.100.100.200"}


def allow_private_default() -> bool:
    return os.environ.get("WEBSCAN_ALLOW_PRIVATE", "").lower() in ("1", "true", "yes", "on")


def _extract_host(target: str) -> str:
    target = target.strip()
    if "://" in target:
        return urlparse(target).hostname or ""
    # bare host, host:port, CIDR or range
    return target.split("/")[0].split(":")[0].split("-")[0].strip()


def _classify(ip: str) -> str | None:
    """Return a reason string if the IP is out of the public-scope policy."""
    if ip in METADATA_IPS:
        return "cloud metadata endpoint"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_loopback:
        return "loopback address"
    if addr.is_link_local:
        return "link-local address"
    if addr.is_private:
        return "private address"
    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return "reserved address"
    return None


def check(target: str, allow_private: bool | None = None) -> tuple[bool, str]:
    """Return (allowed, reason). ``reason`` is empty when allowed."""
    if allow_private is None:
        allow_private = allow_private_default()
    if allow_private:
        return True, ""

    host = _extract_host(target)
    if not host:
        return False, "could not parse a host from the target"

    # A literal IP is checked directly.
    try:
        ipaddress.ip_address(host)
        reason = _classify(host)
        return (False, f"target is a {reason}") if reason else (True, "")
    except ValueError:
        pass

    # Resolve the hostname; block if any resolved address is out of scope
    # (defends against DNS rebinding to an internal IP).
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False, f"could not resolve host '{host}'"
    for info in infos:
        ip = info[4][0]
        reason = _classify(ip)
        if reason:
            return False, f"target resolves to a {reason} ({ip})"
    return True, ""
