"""Authorized security testing: strictly non-intrusive, scope-limited checks.

WHAT THIS MODULE DOES: availability checks, TCP connectivity diagnostics, TLS
configuration inspection, HTTP security-header analysis and a rate-controlled
port sweep on hosts you are authorised to test.

WHAT THIS MODULE DOES NOT DO (by design, with no code path for it): credential
capture, covert surveillance, exploitation, unauthorized access, persistence,
or evasion of detection.
"""
from __future__ import annotations

import socket
import ssl
import time
from typing import Any, Dict, List, Optional, Sequence

from core.models import Report, RiskLevel
from core.security import is_private_ip
from modules import domain_intelligence, network_diagnostics, url_analyzer

SCOPE_NOTICE = (
    "AUTHORIZATION REQUIRED: only test systems you own or have explicit written "
    "permission to assess. SHADOW-X records that you confirmed authorization in "
    "the report metadata. Unauthorized testing is illegal in most jurisdictions."
)

TEST_MODES = ("availability", "connectivity", "tls", "headers", "full")


def tls_configuration(host: str, port: int = 443, timeout: float = 6.0) -> Dict[str, Any]:
    """Probe which TLS versions and ciphers a host accepts."""
    versions = [
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", ssl.TLSVersion.TLSv1_2)),
    ]
    supported: List[str] = []
    rejected: List[str] = []
    details: Dict[str, Any] = {}
    for label, version in versions:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = version
            context.maximum_version = version
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    supported.append(label)
                    details[label] = {
                        "cipher": tls.cipher()[0] if tls.cipher() else None,
                        "protocol": tls.version(),
                    }
        except Exception as exc:
            rejected.append(label)
            details[label] = {"error": str(exc)[:120]}
    return {"supported": supported, "rejected": rejected, "details": details}


def check_availability(host: str, port: int, timeout: float = 5.0) -> Dict[str, Any]:
    """One connectivity sample with an explicit response-time measurement."""
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {
                "host": host,
                "port": port,
                "available": True,
                "response_ms": round((time.perf_counter() - started) * 1000.0, 2),
            }
    except Exception as exc:
        return {
            "host": host,
            "port": port,
            "available": False,
            "response_ms": None,
            "error": str(exc)[:120],
        }


def port_sweep(
    host: str,
    ports: Sequence[int],
    timeout: float = 1.5,
    delay: float = 0.2,
) -> List[Dict[str, Any]]:
    """Rate-controlled sequential sweep - deliberately slow and non-aggressive."""
    results: List[Dict[str, Any]] = []
    for port in ports:
        results.append(network_diagnostics.tcp_check(host, int(port), timeout=timeout))
        if delay:
            time.sleep(delay)
    return results


def run(
    target: str,
    mode: str = "full",
    ports: Optional[Sequence[int]] = None,
    authorized: bool = False,
    timeout: float = 6.0,
) -> Report:
    """Run one authorized test mode against a single target."""
    mode = str(mode or "full").lower()
    report = Report(module="authorized_testing", target=target)
    report.metadata["authorization_confirmed"] = bool(authorized)
    report.metadata["mode"] = mode
    report.metadata["scope_notice"] = SCOPE_NOTICE
    report.limitations = [
        SCOPE_NOTICE,
        "Only non-intrusive checks are performed: no exploitation, no credential attacks, "
        "no persistence and no detection evasion.",
        "A reachable port is not proof of a vulnerability, and a filtered port is not proof of safety.",
        "Results reflect this network vantage point at this moment only.",
    ]
    if not authorized:
        report.add_finding(
            "Authorization",
            "Testing not performed",
            severity=RiskLevel.INFO,
            detail="Authorization was not confirmed, so no active check was run.",
            recommendation="Confirm in writing that you may test this target, then re-run.",
        )
        return report
    if mode not in TEST_MODES:
        report.add_finding(
            "Input",
            "Unknown test mode",
            severity=RiskLevel.INFO,
            detail="Mode must be one of: {}".format(", ".join(TEST_MODES)),
            recommendation="Pick a supported mode.",
        )
        return report

    host = target
    port = 443
    if "://" in target:
        from urllib.parse import urlsplit

        parts = urlsplit(target)
        host = parts.hostname or target
        port = parts.port or (443 if parts.scheme == "https" else 80)

    if is_private_ip(host):
        report.add_finding(
            "Scope",
            "Target is a private address",
            severity=RiskLevel.MEDIUM,
            detail="Testing internal address space from this sandbox is blocked by default.",
            recommendation="Test from inside the network with explicit authorization instead.",
        )
        return report

    if mode in ("availability", "connectivity", "full"):
        samples = [check_availability(host, port, timeout=timeout) for _ in range(3)]
        available = [item for item in samples if item["available"]]
        latencies = [item["response_ms"] for item in available if item["response_ms"]]
        section = report.add_section(
            "Availability",
            {
                "host": host,
                "port": port,
                "samples": len(samples),
                "successful": len(available),
                "min_ms": min(latencies) if latencies else None,
                "avg_ms": round(sum(latencies) / len(latencies), 2) if latencies else None,
                "max_ms": max(latencies) if latencies else None,
            },
        )
        if len(available) < len(samples):
            section.add(
                title="Intermittent availability",
                severity=RiskLevel.LOW,
                detail="{}/{} connection attempts succeeded.".format(len(available), len(samples)),
                recommendation="Check the service and any upstream firewall for instability.",
            )

    if mode in ("connectivity", "full"):
        checks = port_sweep(host, list(ports or [80, 443, 22, 8443]), delay=0.15)
        open_ports = [item for item in checks if item["open"]]
        section = report.add_section(
            "TCP Connectivity",
            {
                "checked": len(checks),
                "open": [item["port"] for item in open_ports],
                "results": checks,
            },
        )
        exposed = [
            item["port"] for item in open_ports
            if item["port"] in (21, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5432, 6379, 27017)
        ]
        if exposed:
            section.add(
                title="Management/database ports reachable from the internet",
                severity=RiskLevel.HIGH,
                detail="Ports {} accepted a connection from this network.".format(exposed),
                recommendation="Restrict these ports to trusted networks or a VPN immediately.",
                evidence={"ports": exposed},
            )

    if mode in ("tls", "full"):
        config = tls_configuration(host, port=port, timeout=timeout)
        section = report.add_section("TLS Configuration", config)
        if "TLSv1.3" not in config["supported"]:
            section.add(
                title="TLS 1.3 not offered",
                severity=RiskLevel.LOW,
                detail="Supported: {}".format(config["supported"] or "none"),
                recommendation="Enable TLS 1.3 alongside 1.2 for forward secrecy and speed.",
            )
        if not config["supported"]:
            section.add(
                title="No supported TLS version negotiated",
                severity=RiskLevel.HIGH,
                detail="The host did not complete a TLS 1.2 or 1.3 handshake.",
                recommendation="Fix the TLS stack before serving traffic.",
            )
        cert = domain_intelligence.tls_info(host, port=port, timeout=timeout)
        if cert.get("available"):
            report.add_section("Certificate Chain", {k: v for k, v in cert.items() if k != "available"})

    if mode in ("headers", "full"):
        scheme = "https" if port in (443, 8443) else "http"
        response = network_diagnostics.http_check(
            "{}://{}:{}".format(scheme, host, port), timeout=timeout
        )
        findings, data = url_analyzer.analyze_security_headers(response.get("headers") or {})
        section = report.add_section("HTTP Security Headers", data)
        for item in findings:
            section.add(**item)
        if response.get("error"):
            section.add(
                title="HTTP request failed",
                severity=RiskLevel.LOW,
                detail=str(response["error"]),
                recommendation="Confirm the service speaks HTTP on this port.",
            )

    score = 0
    for finding in report.findings:
        score += {"critical": 30, "high": 20, "medium": 10, "low": 4, "info": 0}[
            finding.severity.value
        ]
    report.risk_score = min(100, score)
    return report
