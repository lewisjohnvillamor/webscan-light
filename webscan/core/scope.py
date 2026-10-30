"""Target scope policy — the SSRF guard for the exposed web layer.

The web UI lets a caller name any target, so on a reachable server it is an
SSRF primitive: it could be pointed at cloud metadata (169.254.169.254) or
internal hosts. Private/loopback/link-local/reserved addresses are blocked
unless the operator explicitly opts in (WEBSCAN_ALLOW_PRIVATE=1), because
scanning an internal range is a legitimate self-hosted use — but it must be a
deliberate choice, not the default.

Two layers:

* ``check()`` validates a submitted target before a job starts. It parses the
  target the same way the tools do and checks every address it can expand to.
* The connect guard (``activate_connect_guard()``, switched on by the web app)
  re-applies the policy to every outbound TCP connection the process makes:
  redirect hops, hosts the tools discover themselves (subdomains, look-alike
  domains, nameservers, crawled form actions) and scheduled re-runs. It
  resolves once, refuses if any address is out of scope, and connects to the
  vetted address, so DNS rebinding between check and connect cannot slip
  through. The CLI never activates it: a local operator is trusted.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import threading
from contextlib import contextmanager
from urllib.parse import urlparse

METADATA_IPS = {"169.254.169.254", "fd00:ec2::254", "100.100.100.200"}
MAX_ADDRESSES = 65536  # widest CIDR/range accepted (an IPv4 /16, an IPv6 /112)

_RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$")
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class ScopeError(OSError):
    """Raised when a connection would leave the permitted scope."""


def allow_private_default() -> bool:
    return os.environ.get("WEBSCAN_ALLOW_PRIVATE", "").lower() in ("1", "true", "yes", "on")


def _classify(ip: str) -> str | None:
    """Return a reason string if the IP is out of the public-scope policy."""
    if ip in METADATA_IPS:
        return "cloud metadata endpoint"
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped:
        return _classify(str(addr.ipv4_mapped))
    if str(addr) in METADATA_IPS:
        return "cloud metadata endpoint"
    if addr.is_loopback:
        return "loopback address"
    if addr.is_link_local:
        return "link-local address"
    if addr.is_private:
        return "private address"
    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return "reserved address"
    if not addr.is_global:
        return "non-public address"
    return None


def expand_addresses(target: str) -> tuple[list[str], str]:
    """Literal addresses a CIDR, last-octet range or IP target expands to.

    Returns (addresses, error). An empty list with no error means the target
    is a hostname that needs resolving.
    """
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return [], ""
        if net.num_addresses > MAX_ADDRESSES:
            return [], f"network is too large (max {MAX_ADDRESSES} addresses)"
        return [str(a) for a in net], ""
    match = _RANGE_RE.match(target)
    if match:
        base, lo, hi = match.group(1), int(match.group(2)), int(match.group(3))
        if not 0 <= lo <= hi <= 255:
            return [], "invalid address range"
        try:
            return [str(ipaddress.ip_address(f"{base}.{i}")) for i in range(lo, hi + 1)], ""
        except ValueError:
            return [], "invalid address range"
    try:
        return [str(ipaddress.ip_address(target.strip("[]")))], ""
    except ValueError:
        return [], ""


def _hostname(target: str) -> tuple[str, str]:
    """Extract and validate the hostname of a URL or bare host[:port][/path]."""
    if any(ch.isspace() for ch in target) or "," in target or "*" in target:
        return "", "target contains characters that are not allowed"
    parsed = urlparse(target if "://" in target else "//" + target)
    if "@" in parsed.netloc:
        return "", "credentials in the target are not allowed"
    try:
        host = (parsed.hostname or "").rstrip(".")
        parsed.port  # noqa: B018  (raises ValueError on a malformed port)
    except ValueError:
        return "", "invalid port in target"
    if not host:
        return "", "could not parse a host from the target"
    try:
        return str(ipaddress.ip_address(host)), ""
    except ValueError:
        pass
    labels = host.lower().split(".")
    if all(re.fullmatch(r"[0-9x-]+", label) for label in labels):
        # Short or ranged numeric forms ("169.253", "10.0-1.0.1") are parsed
        # differently by resolvers and tools such as nmap.
        return "", "numeric host forms other than a plain IP are not allowed"
    if not all(_LABEL_RE.match(label) for label in labels):
        return "", "invalid hostname"
    return host.lower(), ""


def check(target: str, allow_private: bool | None = None) -> tuple[bool, str]:
    """Return (allowed, reason). ``reason`` is empty when allowed."""
    if allow_private is None:
        allow_private = allow_private_default()
    if allow_private:
        return True, ""
    target = (target or "").strip()
    if not target:
        return False, "empty target"

    if "://" not in target:
        literal, error = expand_addresses(target)
        if error:
            return False, error
        if literal:
            for ip in literal:
                reason = _classify(ip)
                if reason:
                    return False, f"target includes a {reason} ({ip})"
            return True, ""

    host, error = _hostname(target)
    if error:
        return False, error
    if expand_addresses(host)[0]:
        reason = _classify(host)
        return (False, f"target is a {reason}") if reason else (True, "")
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False, f"could not resolve host '{host}'"
    for info in infos:
        reason = _classify(info[4][0])
        if reason:
            return False, f"target resolves to a {reason} ({info[4][0]})"
    return True, ""


# --------------------------------------------------------------------------- connect guard

_state = {"installed": False, "active": False}
_local = threading.local()
_orig_socket_create_connection = socket.create_connection


def unguarded_engines_allowed() -> bool:
    """Opt-in for engines that make their own connections (Chromium, nuclei)."""
    return os.environ.get("WEBSCAN_ALLOW_UNGUARDED_ENGINES", "").lower() in ("1", "true", "yes", "on")


def connect_guard_active() -> bool:
    """True when outbound connections from this process are scope-checked."""
    return _state["active"] and not allow_private_default() and not getattr(_local, "trusted", False)


@contextmanager
def trusted():
    """Bypass the guard for an operator-configured destination (alert webhook, SMTP)."""
    previous = getattr(_local, "trusted", False)
    _local.trusted = True
    try:
        yield
    finally:
        _local.trusted = previous


def _proxy_endpoints() -> set[tuple[str, int]]:
    """(host, port) of each configured HTTP proxy; only those exact endpoints are exempt."""
    endpoints = set()
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        value = os.environ.get(name)
        if not value:
            continue
        parsed = urlparse(value if "://" in value else "//" + value)
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            continue
        if parsed.hostname:
            endpoints.add((parsed.hostname.lower(), port))
    return endpoints


def vetted_addresses(host: str, port: int) -> list[str]:
    """Resolve ``host`` once and return its addresses, or raise ScopeError."""
    host = host.strip("[]")
    addresses = []
    for info in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        ip = info[4][0]
        reason = _classify(ip)
        if reason:
            raise ScopeError(f"blocked by scope policy: {host} resolves to a {reason} ({ip})")
        if ip not in addresses:
            addresses.append(ip)
    return addresses


def _guarded(original):
    def create_connection(address, *args, **kwargs):
        host, port = address[0], address[1]
        if not connect_guard_active() or (str(host).strip("[]").lower(), int(port)) in _proxy_endpoints():
            return original(address, *args, **kwargs)
        last: OSError | None = None
        for ip in vetted_addresses(str(host), port):
            try:
                return original((ip, port), *args, **kwargs)
            except OSError as exc:
                last = exc
        raise last or OSError(f"could not connect to {host}:{port}")
    create_connection.__wrapped__ = original
    return create_connection


def activate_connect_guard() -> None:
    """Scope-check every outbound connection this process makes (idempotent)."""
    if not _state["installed"]:
        import urllib3.util.connection as u3conn

        u3conn.create_connection = _guarded(u3conn.create_connection)
        socket.create_connection = _guarded(_orig_socket_create_connection)
        _state["installed"] = True
    _state["active"] = True
