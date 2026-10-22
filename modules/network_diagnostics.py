"""Network and IP diagnostics with honest platform limits.

Termux cannot open raw sockets without root, so ICMP ping and binary
traceroute may be unavailable. When that happens this module falls back to TCP
connect latency and *labels it as TCP*, never pretending it was ICMP.
"""
from __future__ import annotations

import http.client
import json
import platform
import socket
import ssl
import struct
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from core import net_dns, platform_detect
from core.models import Report, RiskLevel
from core.security import is_private_ip, redact_headers


def local_interfaces() -> List[Dict[str, Any]]:
    """Enumerate interfaces without external dependencies."""
    interfaces: List[Dict[str, Any]] = []
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None)
    except Exception:
        infos = []
    seen = set()
    for family, _type, _proto, _canon, sockaddr in infos:
        address = sockaddr[0]
        if address in seen:
            continue
        seen.add(address)
        interfaces.append(
            {
                "address": address,
                "family": "inet6" if family == socket.AF_INET6 else "inet",
                "scope": "loopback" if is_private_ip(address) else "public",
            }
        )
    for name in ("wlan0", "eth0", "rmnet_data0"):
        if platform_detect.have_command("ip"):
            break
    return interfaces


def public_ip(timeout: float = 6.0) -> Dict[str, Any]:
    """Ask a public echo service for our egress address. Requires consent in the UI."""
    endpoints = [
        ("https://api.ipify.org?format=json", "ipify"),
        ("https://ifconfig.co/json", "ifconfig.co"),
    ]
    errors: List[str] = []
    for url, provider in endpoints:
        parts = urlsplit(url)
        try:
            context = ssl.create_default_context()
            connection = http.client.HTTPSConnection(
                parts.hostname, 443, timeout=timeout, context=context
            )
            path = parts.path + ("?" + parts.query if parts.query else "")
            connection.request(
                "GET",
                path,
                headers={"User-Agent": "SHADOW-X-Ultimate/1.0", "Accept": "application/json"},
            )
            response = connection.getresponse()
            raw = response.read(8192).decode("utf-8", "replace")
            connection.close()
            if response.status != 200:
                errors.append("{}: HTTP {}".format(provider, response.status))
                continue
            data = json.loads(raw)
            address = data.get("ip") or data.get("IP") or data.get("address")
            if not address:
                errors.append("{}: no address field".format(provider))
                continue
            return {
                "ip": address,
                "provider": provider,
                "country": data.get("country") or data.get("country_iso") or "",
                "city": data.get("city") or "",
                "asn": data.get("asn") or "",
                "error": None,
            }
        except Exception as exc:
            errors.append("{}: {}".format(provider, exc))
    return {"ip": None, "provider": None, "error": "; ".join(errors) or "no provider reachable"}


def ping_host(
    host: str, count: int = 4, timeout: float = 3.0
) -> Dict[str, Any]:
    """ICMP ping when permitted, otherwise TCP latency probes (clearly labelled)."""
    count = max(1, min(int(count), 10))
    result: Dict[str, Any] = {
        "host": host,
        "method": None,
        "sent": count,
        "received": 0,
        "loss_percent": 100.0,
        "min_ms": None,
        "avg_ms": None,
        "max_ms": None,
        "samples": [],
        "note": "",
    }

    if platform_detect.have_command("ping"):
        try:
            completed = subprocess.run(
                ["ping", "-c", str(count), "-W", str(max(1, int(timeout))), host],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout * count + 5,
            )
            text = completed.stdout.decode("utf-8", "replace")
            timings = []
            for token in text.replace("=", " ").split():
                if token.endswith("ms") and token[:-2].replace(".", "", 1).isdigit():
                    timings.append(float(token[:-2]))
            if "time=" in text:
                samples = []
                for line in text.splitlines():
                    if "time=" in line:
                        fragment = line.split("time=", 1)[1].split()[0].rstrip("ms")
                        try:
                            samples.append(float(fragment))
                        except ValueError:
                            continue
                if samples:
                    result.update(
                        {
                            "method": "icmp",
                            "received": len(samples),
                            "loss_percent": round(100.0 * (count - len(samples)) / count, 1),
                            "min_ms": round(min(samples), 2),
                            "avg_ms": round(sum(samples) / len(samples), 2),
                            "max_ms": round(max(samples), 2),
                            "samples": [round(value, 2) for value in samples],
                            "note": "ICMP echo via the ping binary",
                        }
                    )
                    return result
            result["note"] = "ping binary present but produced no replies (ICMP may be filtered)"
        except (subprocess.SubprocessError, OSError) as exc:
            result["note"] = "ping binary failed: {}".format(exc)

    samples: List[float] = []
    for _ in range(count):
        started = time.perf_counter()
        try:
            with socket.create_connection((host, 443), timeout=timeout):
                samples.append((time.perf_counter() - started) * 1000.0)
        except OSError:
            try:
                started = time.perf_counter()
                with socket.create_connection((host, 80), timeout=timeout):
                    samples.append((time.perf_counter() - started) * 1000.0)
            except OSError:
                continue
    result.update(
        {
            "method": "tcp",
            "received": len(samples),
            "loss_percent": round(100.0 * (count - len(samples)) / count, 1),
            "samples": [round(value, 2) for value in samples],
            "note": "TCP connect latency to ports 443/80 - this is NOT ICMP echo",
        }
    )
    if samples:
        result.update(
            {
                "min_ms": round(min(samples), 2),
                "avg_ms": round(sum(samples) / len(samples), 2),
                "max_ms": round(max(samples), 2),
            }
        )
    else:
        result["note"] = (
            "No ICMP binary usable and TCP connect failed; the host may be offline "
            "or blocking both ports."
        )
    return result


def tcp_check(host: str, port: int, timeout: float = 4.0) -> Dict[str, Any]:
    """Single TCP connect test with a measured handshake time."""
    port = int(port)
    started = time.perf_counter()
    record: Dict[str, Any] = {
        "host": host,
        "port": port,
        "open": False,
        "elapsed_ms": None,
        "banner": "",
        "error": None,
    }
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            record["open"] = True
            record["elapsed_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
            try:
                sock.settimeout(1.2)
                banner = sock.recv(128)
                record["banner"] = banner.decode("latin-1", "replace").strip()[:120]
            except (socket.timeout, OSError):
                pass
    except socket.timeout:
        record["error"] = "timeout"
    except ConnectionRefusedError:
        record["error"] = "refused"
    except OSError as exc:
        record["error"] = str(exc)
    return record


def http_check(url: str, timeout: float = 8.0, method: str = "HEAD") -> Dict[str, Any]:
    """HTTP reachability check. Only http/https, no redirects followed."""
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return {"url": url, "ok": False, "error": "unsupported scheme"}
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    started = time.perf_counter()
    record: Dict[str, Any] = {
        "url": url,
        "ok": False,
        "status": None,
        "elapsed_ms": None,
        "headers": {},
        "tls_protocol": None,
        "error": None,
    }
    connection = None
    try:
        if parts.scheme == "https":
            connection = http.client.HTTPSConnection(
                host, port, timeout=timeout, context=ssl.create_default_context()
            )
        else:
            connection = http.client.HTTPConnection(host, port, timeout=timeout)
        connection.request(
            method,
            path,
            headers={"User-Agent": "SHADOW-X-Ultimate/1.0", "Connection": "close"},
        )
        response = connection.getresponse()
        record["status"] = response.status
        record["headers"] = redact_headers(response.getheaders())
        record["ok"] = True
        record["elapsed_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
        sock = getattr(connection, "sock", None)
        if sock is not None and hasattr(sock, "version"):
            record["tls_protocol"] = sock.version()
    except Exception as exc:
        record["error"] = "{}: {}".format(type(exc).__name__, exc)
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
    return record


def traceroute(
    host: str, max_hops: int = 12, timeout: float = 2.0
) -> Dict[str, Any]:
    """Real traceroute when the binary exists; otherwise report unsupported.

    Termux usually has no traceroute binary and no raw-socket permission, so the
    honest answer is 'unsupported on this platform' rather than a fabricated path.
    """
    max_hops = max(1, min(int(max_hops), 30))
    if not platform_detect.have_command("traceroute"):
        return {
            "supported": False,
            "host": host,
            "hops": [],
            "reason": (
                "traceroute binary not installed; install it with 'pkg install traceroute' "
                "on Termux or 'sudo apt install traceroute' on Kali. Raw ICMP/UDP probes "
                "also need CAP_NET_RAW, which the app sandbox does not grant."
            ),
        }
    try:
        completed = subprocess.run(
            ["traceroute", "-m", str(max_hops), "-w", str(max(1, int(timeout))), host],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=max_hops * (timeout + 1) + 10,
        )
        text = completed.stdout.decode("utf-8", "replace")
        hops: List[Dict[str, Any]] = []
        for line in text.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            hops.append({"raw": line[:160]})
        return {
            "supported": completed.returncode == 0,
            "host": host,
            "hops": hops,
            "reason": "" if completed.returncode == 0 else text.strip()[:300],
        }
    except (subprocess.SubprocessError, OSError) as exc:
        return {"supported": False, "host": host, "hops": [], "reason": str(exc)}


def diagnose(target: str, timeout: float = 6.0, do_ping: bool = True) -> Report:
    """Run the standard diagnostic suite against one host or URL."""
    report = Report(module="network_diagnostics", target=target)
    info = platform_detect.detect()
    report.metadata["platform"] = info.display

    host = target
    port = 443
    if "://" in target:
        parts = urlsplit(target)
        host = parts.hostname or target
        port = parts.port or (443 if parts.scheme == "https" else 80)

    report.limitations = [
        "Latency depends on the current mobile or Wi-Fi connection and is indicative only.",
        "An IP address identifies a network endpoint, never a person's exact home address.",
        "A closed TCP port may be filtered by a firewall rather than genuinely closed.",
    ]
    if info.is_termux:
        report.limitations.append(
            "Termux cannot use raw sockets; ICMP-based results fall back to TCP and are labelled accordingly."
        )
    if not info.capabilities.get("traceroute"):
        report.limitations.append("Traceroute is unavailable on this device (binary missing).")

    addresses: List[str] = []
    try:
        addresses = net_dns.get_records(host, "A", timeout=min(timeout, 5.0))
    except Exception as exc:
        report.add_finding(
            "Resolution",
            "DNS resolution failed",
            severity=RiskLevel.MEDIUM,
            detail=str(exc),
            recommendation="Check the hostname spelling and your DNS connectivity.",
        )

    dns_data: Dict[str, Any] = {"a": addresses, "ptr": {}, "interfaces": local_interfaces()}
    for address in addresses[:5]:
        try:
            dns_data["ptr"][address] = net_dns.reverse_lookup(address, timeout=min(timeout, 4.0))
        except Exception:
            dns_data["ptr"][address] = []
    report.add_section("Resolution", dns_data)

    if do_ping:
        ping_result = ping_host(host, count=4, timeout=min(timeout, 3.0))
        ping_section = report.add_section("Latency", ping_result)
        if ping_result["received"] == 0:
            ping_section.add(
                title="Host did not respond",
                severity=RiskLevel.LOW,
                detail=ping_result.get("note") or "No replies received.",
                recommendation="Confirm the host is online; many networks block probes.",
            )
        elif ping_result.get("loss_percent", 0) > 25:
            ping_section.add(
                title="Packet loss above 25%",
                severity=RiskLevel.LOW,
                detail="{}% loss over {} probes.".format(ping_result["loss_percent"], ping_result["sent"]),
                recommendation="Retest on a stable Wi-Fi connection before drawing conclusions.",
            )

    if addresses:
        check_host = addresses[0]
    else:
        check_host = host
    tcp_result = tcp_check(check_host, port, timeout=min(timeout, 4.0))
    tcp_result["port_label"] = port
    tcp_section = report.add_section("TCP Connectivity", tcp_result)
    if not tcp_result["open"]:
        tcp_section.add(
            title="TCP port {} not reachable".format(port),
            severity=RiskLevel.LOW,
            detail=tcp_result.get("error") or "no connection established",
            recommendation="Confirm the service is running and the port is not firewalled.",
        )

    trace = traceroute(host, max_hops=12, timeout=2.0)
    report.add_section("Traceroute", trace)
    if not trace["supported"]:
        report.add_finding(
            "Traceroute",
            "Traceroute unsupported on this platform",
            severity=RiskLevel.INFO,
            detail=trace.get("reason", ""),
            recommendation="Use the TCP latency measurements above instead.",
        )

    report.risk_score = 0 if addresses else 30
    return report


def port_scan(
    host: str,
    ports: List[int],
    timeout: float = 2.0,
    authorized: bool = False,
) -> Report:
    """Small, rate-limited TCP connect scan for hosts you own."""
    report = Report(module="network_diagnostics", target="{} ({} ports)".format(host, len(ports)))
    if not authorized:
        report.add_finding(
            "Authorization",
            "Scan not performed",
            severity=RiskLevel.INFO,
            detail="Port scanning requires explicit confirmation that you own or are authorized to test the host.",
            recommendation="Only scan systems you own or have written permission to test.",
        )
        report.metadata["scan_performed"] = False
        return report
    results = []
    for port in ports[:200]:
        results.append(tcp_check(host, int(port), timeout=timeout))
    open_ports = [item for item in results if item["open"]]
    report.add_section(
        "Scan Results",
        {
            "host": host,
            "checked": len(results),
            "open": len(open_ports),
            "results": results,
        },
    )
    report.add_finding(
        "Summary",
        "{} open port(s) found".format(len(open_ports)),
        severity=RiskLevel.INFO,
        detail=", ".join(str(item["port"]) for item in open_ports) or "none",
        recommendation="Close any service you do not need and keep the rest patched.",
    )
    report.metadata["scan_performed"] = True
    return report
