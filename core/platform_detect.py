"""Cross-platform detection and capability mapping for SHADOW-X ULTIMATE.

The rest of the application asks this module what it may do instead of
assuming that Termux and a desktop Linux distribution behave the same way.
Everything here is read-only and safe to call on every start-up.
"""
from __future__ import annotations

import importlib.util
import os
import platform
import shutil
import socket
import sys
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

TERMUX_MARKERS = ("com.termux",)
TERMUX_DATA_DIR = "/data/data/com.termux/files/usr"

OPTIONAL_BINARIES = {
    "ping": "ICMP ping diagnostics",
    "traceroute": "traceroute diagnostics",
    "dig": "DNS lookups via dig",
    "whois": "WHOIS lookups via the system client",
    "openssl": "local certificate inspection",
    "curl": "HTTP transfers via the system client",
    "ip": "interface enumeration",
}


@dataclass
class PlatformInfo:
    """Snapshot of the host platform and what it is able to do."""

    system: str = "unknown"
    pretty_name: str = "Unknown"
    is_android: bool = False
    is_termux: bool = False
    is_kali: bool = False
    is_root: bool = False
    distro_id: str = ""
    kernel: str = ""
    machine: str = ""
    python_version: str = ""
    termux_version: str = ""
    capabilities: Dict[str, bool] = field(default_factory=dict)
    missing: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)

    @property
    def display(self) -> str:
        return self.pretty_name or self.system

    def supports(self, capability: str) -> bool:
        return bool(self.capabilities.get(capability))


_CACHE: Optional[PlatformInfo] = None


def have_command(name: str) -> bool:
    """Return True when an executable is present on PATH."""
    try:
        return shutil.which(name) is not None
    except Exception:
        return False


def module_available(name: str) -> bool:
    """Return True when an importable module exists (without importing it)."""
    try:
        return importlib.util.find_spec(name) is not None
    except Exception:
        return False


def _read_os_release() -> Dict[str, str]:
    values: Dict[str, str] = {}
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, raw = line.partition("=")
                    values[key.strip()] = raw.strip().strip('"').strip("'")
            if values:
                return values
        except OSError:
            continue
    return values


def is_root() -> bool:
    """True when running with uid 0. Never used to demand elevation."""
    try:
        return hasattr(os, "geteuid") and os.geteuid() == 0
    except Exception:
        return False


def _raw_socket_available() -> bool:
    """Raw sockets are what ICMP ping and traceroute truly need."""
    if not hasattr(socket, "SOCK_RAW"):
        return False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.close()
        return True
    except OSError:
        return False
    except Exception:
        return False


def detect(force: bool = False) -> PlatformInfo:
    """Detect the platform once and cache the result."""
    global _CACHE
    if _CACHE is not None and not force:
        return _CACHE

    info = PlatformInfo()
    info.kernel = platform.release()
    info.machine = platform.machine()
    info.python_version = platform.python_version()
    info.is_root = is_root()

    osrel = _read_os_release()
    distro_id = osrel.get("ID", "").lower()
    pretty = osrel.get("PRETTY_NAME") or osrel.get("NAME") or ""
    info.distro_id = distro_id

    prefix = os.environ.get("PREFIX", "")
    looks_termux = any(marker in prefix for marker in TERMUX_MARKERS)
    info.is_termux = bool(
        looks_termux
        or os.path.isdir(TERMUX_DATA_DIR)
        or "TERMUX_VERSION" in os.environ
        or "termux" in pretty.lower()
    )
    info.termux_version = os.environ.get("TERMUX_VERSION", "")
    info.is_android = bool(
        info.is_termux
        or "android" in pretty.lower()
        or (os.path.isdir("/system/app") and os.path.isdir("/data"))
    )
    info.is_kali = (not info.is_termux) and ("kali" in distro_id or "kali" in pretty.lower())

    sysname = platform.system().lower()
    if info.is_termux:
        info.system = "termux"
        info.pretty_name = "Termux on Android{}".format(
            " " + info.termux_version if info.termux_version else ""
        )
    elif info.is_kali:
        info.system = "kali"
        info.pretty_name = pretty or "Kali Linux"
    elif sysname == "linux":
        info.system = "linux"
        info.pretty_name = pretty or "Linux"
    elif sysname == "darwin":
        info.system = "macos"
        info.pretty_name = pretty or "macOS"
    elif sysname.startswith("win"):
        info.system = "windows"
        info.pretty_name = pretty or "Windows"
    else:
        info.system = "unknown"
        info.pretty_name = pretty or sysname or "Unknown"

    caps: Dict[str, bool] = {}
    for binary in OPTIONAL_BINARIES:
        caps[binary] = have_command(binary)
    caps["curl"] = caps.get("curl", False)
    caps["rich"] = module_available("rich")
    caps["colorama"] = module_available("colorama")
    caps["raw_socket"] = _raw_socket_available()
    caps["dns_resolver"] = True  # bundled pure-python resolver
    info.capabilities = caps

    info.missing = [
        binary for binary, purpose in OPTIONAL_BINARIES.items() if not caps.get(binary)
    ]

    info.notes = limitations(info)
    _CACHE = info
    return info


def limitations(info: Optional[PlatformInfo] = None) -> List[str]:
    """Human-readable platform caveats, honest about what is not possible."""
    info = info or detect()
    caps = info.capabilities
    notes: List[str] = []

    if info.is_termux:
        notes.append(
            "Termux: running as an app sandbox - no root, no packet capture."
        )
        notes.append(
            "ICMP ping and binary traceroute normally need root or raw sockets; "
            "SHADOW-X falls back to TCP latency probes and labels them as TCP, not ICMP."
        )
    elif info.is_kali:
        notes.append(
            "Kali Linux: full TCP/UDP diagnostics available; raw-socket tools still "
            "need CAP_NET_RAW (often via sudo) and SHADOW-X never demands elevation."
        )
    elif info.is_android:
        notes.append("Android shell without Termux prefix: expect limited tooling.")
    else:
        notes.append(
            "Generic Linux: some binaries ({}) may be missing.".format(
                ", ".join(info.missing) if info.missing else "none"
            )
        )

    if not caps.get("traceroute"):
        notes.append("traceroute binary not found - traceroute will report as unsupported.")
    if not caps.get("raw_socket"):
        notes.append("No raw-socket permission - ICMP-based probes are unavailable.")
    if not caps.get("rich"):
        notes.append("Rich is not installed - falling back to plain ANSI rendering.")
    if not caps.get("whois"):
        notes.append("No whois binary - SHADOW-X uses its own port-43 client and RDAP.")
    return notes


def probe_network(host: str = "1.1.1.1", port: int = 443, timeout: float = 2.5) -> bool:
    """Quick TCP reachability probe used by the dashboard. Never raises."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def summary_line() -> str:
    """One-line platform summary, e.g. 'Termux on Android 0.118 (aarch64)'."""
    info = detect()
    return "{} ({})".format(info.display, info.machine or "unknown arch")


def python_executable() -> str:
    return sys.executable or "python3"
