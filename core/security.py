"""Safety primitives: SSRF guards, rate limiting, redaction, safe filenames."""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import socket
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence


class UnsafeTargetError(ValueError):
    """Raised when a target resolves to a non-public address."""


class RateLimitExceeded(RuntimeError):
    """Raised when the configured request budget is exhausted."""


_BLOCKED_NETWORKS = [
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
        "2001:db8::/32",
    )
]


def _normalise_ip(value: str) -> Optional[ipaddress._BaseAddress]:
    try:
        ip = ipaddress.ip_address(str(value).strip().strip("[]"))
    except ValueError:
        return None
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        return mapped
    return ip


def is_private_ip(value: str) -> bool:
    """True when the value is an IP literal in loopback/private/reserved space.

    A hostname (non-literal) returns False here: it must be resolved first and
    checked address-by-address. Use assert_public_target() for that guard.
    """
    ip = _normalise_ip(value)
    if ip is None:
        return False
    for network in _BLOCKED_NETWORKS:
        try:
            if ip.version == network.version and ip in network:
                return True
        except TypeError:
            continue
    return bool(
        getattr(ip, "is_private", False)
        or getattr(ip, "is_loopback", False)
        or getattr(ip, "is_link_local", False)
        or getattr(ip, "is_reserved", False)
        or getattr(ip, "is_multicast", False)
        or getattr(ip, "is_unspecified", False)
    )


def resolve_host(host: str, port: int = 443, timeout: float = 4.0) -> List[str]:
    """Resolve a hostname to a de-duplicated list of IP strings."""
    if not host:
        raise UnsafeTargetError("empty host")
    literal = _normalise_ip(host)
    if literal is not None:
        return [str(literal)]
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeTargetError("cannot resolve {}: {}".format(host, exc))
    except OSError as exc:
        raise UnsafeTargetError("cannot resolve {}: {}".format(host, exc))
    addresses: List[str] = []
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise UnsafeTargetError("no addresses for {}".format(host))
    return addresses


def assert_public_target(
    host: str, port: int = 443, allow_private: bool = False
) -> List[str]:
    """SSRF guard: refuse hosts that resolve to internal address space."""
    addresses = resolve_host(host, port)
    blocked = [address for address in addresses if is_private_ip(address)]
    if blocked and not allow_private:
        raise UnsafeTargetError(
            "refusing to contact {!r}: it resolves to non-public address {} "
            "(private/loopback/link-local targets are blocked)".format(
                host, ", ".join(blocked)
            )
        )
    return addresses


class RateLimiter:
    """Thread-safe token bucket with a hard per-run request budget."""

    def __init__(self, rate: float = 3.0, burst: Optional[int] = None, max_requests: int = 0):
        self.rate = max(0.1, float(rate))
        self.capacity = max(1, int(burst if burst is not None else max(1, round(self.rate))))
        self.tokens = float(self.capacity)
        self.max_requests = int(max_requests or 0)
        self.used = 0
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last
        if elapsed > 0:
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self._last = now

    def acquire(self, tokens: int = 1, blocking: bool = True) -> None:
        need = max(1, int(tokens))
        deadline = time.monotonic() + 30.0
        while True:
            with self._lock:
                if self.max_requests and self.used + need > self.max_requests:
                    raise RateLimitExceeded(
                        "request budget exhausted ({} requests per run)".format(
                            self.max_requests
                        )
                    )
                self._refill()
                if self.tokens >= need:
                    self.tokens -= need
                    self.used += need
                    return
                deficit = need - self.tokens
            if not blocking:
                raise RateLimitExceeded("rate limit reached, try again shortly")
            if time.monotonic() > deadline:
                raise RateLimitExceeded("rate limit wait timed out")
            time.sleep(min(0.5, max(0.02, deficit / self.rate)))

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "rate_per_second": self.rate,
                "capacity": self.capacity,
                "tokens": round(self.tokens, 2),
                "used": self.used,
                "max_requests": self.max_requests,
            }


SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "api-key",
}

_SECRET_PATTERNS: Sequence = (
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-+/=]{8,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(basic\s+)[A-Za-z0-9+/=]{8,}"), r"\1[REDACTED]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"), "gh*_[REDACTED]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), "xox*-[REDACTED]"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "sk-[REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AKIA[REDACTED]"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\b\s*[=:]\s*\S+"), r"\1=[REDACTED]"),
    (re.compile(r"(?i)(eyJ[A-Za-z0-9_\-]{8,})\.([A-Za-z0-9_\-]{8,})\.([A-Za-z0-9_\-]{8,})"), "[REDACTED-JWT]"),
)


def redact_text(value: Any) -> Any:
    """Strip obvious credentials from free text."""
    if not isinstance(value, str):
        return value
    text = value
    for pattern, replacement in _SECRET_PATTERNS:
        try:
            text = pattern.sub(replacement, text)
        except Exception:
            continue
    return text


def redact_headers(headers: Any) -> Dict[str, str]:
    """Copy a header mapping with secret-bearing values replaced."""
    cleaned: Dict[str, str] = {}
    items: Iterable = []
    if isinstance(headers, dict):
        items = headers.items()
    elif isinstance(headers, (list, tuple)):
        items = headers
    for key, value in items:
        name = str(key)
        if name.lower() in SENSITIVE_HEADERS:
            cleaned[name] = "[REDACTED]"
        else:
            cleaned[name] = redact_text(str(value))
    return cleaned


def redact_structure(value: Any) -> Any:
    """Recursively redact a JSON-like structure before it is written to disk."""
    if isinstance(value, dict):
        result: Dict[str, Any] = {}
        for key, item in value.items():
            if str(key).lower() in SENSITIVE_HEADERS:
                result[key] = "[REDACTED]"
            else:
                result[key] = redact_structure(item)
        return result
    if isinstance(value, (list, tuple)):
        return [redact_structure(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


_FILENAME_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename(value: str, fallback: str = "report", max_length: int = 80) -> str:
    """Produce a filesystem-safe slug with no path traversal potential."""
    text = str(value or "").strip()
    text = text.replace(os.sep, "-").replace("/", "-").replace("\\", "-")
    text = _FILENAME_SAFE.sub("-", text).strip(".-")
    text = re.sub(r"-{2,}", "-", text)
    if not text or text in (".", ".."):
        text = fallback
    return text[:max_length].strip(".-") or fallback


def truncate(value: str, limit: int = 2000) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[:limit] + "... [truncated {} chars]".format(len(text) - limit)


def sha256_text(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()


def ensure_within(base: Path, candidate: Path) -> Path:
    """Resolve a path and refuse to escape its base directory."""
    base_resolved = Path(base).resolve()
    target = (base_resolved / candidate).resolve() if not Path(candidate).is_absolute() else Path(candidate).resolve()
    if base_resolved != target and base_resolved not in target.parents:
        raise UnsafeTargetError("path escapes the permitted directory: {}".format(candidate))
    return target
