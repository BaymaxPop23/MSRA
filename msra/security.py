"""Shared input-validation and hardening helpers.

Everything that touches attacker-influenced strings (scan ids from URLs,
package names from APK manifests, URLs from users / feeds) should go through
these helpers rather than ad-hoc checks.
"""
from __future__ import annotations

import ipaddress
import re
import shlex
import socket
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

# New scans use 12 hex chars, but legacy/migrated scans are named after the package
# (e.g. "atws.app"), so dots are allowed - never leading, trailing or doubled.
SCAN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
PACKAGE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
_FILENAME_BAD = re.compile(r"[^A-Za-z0-9._-]")


def is_valid_scan_id(scan_id: object) -> bool:
    return (isinstance(scan_id, str) and bool(SCAN_ID_RE.match(scan_id))
            and ".." not in scan_id and not scan_id.endswith("."))


def is_valid_package(pkg: object) -> bool:
    return isinstance(pkg, str) and len(pkg) <= 255 and bool(PACKAGE_RE.match(pkg))


def safe_join(base: Path, name: str) -> Path:
    """Join *name* under *base*, refusing anything that escapes it."""
    base_r = base.resolve()
    target = (base / name).resolve()
    if target != base_r and base_r not in target.parents:
        raise ValueError("path escapes base directory")
    return target


def safe_filename(name: str, default: str = "file") -> str:
    """Reduce an arbitrary string to a safe single path component."""
    name = Path(str(name or "")).name
    name = _FILENAME_BAD.sub("_", name).lstrip(".")
    return name[:120] or default


def header_filename(name: str) -> str:
    """Filename safe to embed in a Content-Disposition header."""
    return safe_filename(name, "download")


def sh_quote(value: object) -> str:
    """Quote a value for the on-device (Android) POSIX shell."""
    return shlex.quote(str(value))


_CSV_DANGEROUS = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: object) -> str:
    """Neutralise spreadsheet formula injection in a CSV cell."""
    s = "" if value is None else str(value)
    if s and s.startswith(_CSV_DANGEROUS):
        return "'" + s
    return s


# ── SSRF-safe fetching ────────────────────────────────────────────────────

class UnsafeURLError(ValueError):
    pass


def _ip_is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def check_public_url(url: str) -> str:
    """Raise UnsafeURLError unless *url* is http(s) and resolves only to public IPs."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeURLError("only http/https URLs are allowed")
    host = parsed.hostname
    if not host:
        raise UnsafeURLError("URL has no host")
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeURLError(f"cannot resolve host: {exc}") from exc
    for info in infos:
        if not _ip_is_public(info[4][0]):
            raise UnsafeURLError("URL resolves to a non-public address")
    return url


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_public_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SafeRedirect)


def safe_fetch(url: str, *, timeout: float = 15, max_bytes: int = 500_000,
               headers: Optional[dict] = None) -> tuple[bytes, str]:
    """Fetch *url* with SSRF protection. Returns (body, content_type).

    Validates the initial URL and every redirect target. Note: a determined
    DNS-rebinding attacker can still race the resolve/connect gap; for hostile
    networks, also egress-filter the host.
    """
    check_public_url(url)
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "MSRA/2.0"})
    with _OPENER.open(req, timeout=timeout) as resp:
        body = resp.read(max_bytes)
        return body, resp.headers.get("Content-Type", "")
