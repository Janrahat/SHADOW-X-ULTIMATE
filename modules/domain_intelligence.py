"""Domain intelligence: records, WHOIS/RDAP, TLS, SPF/DMARC, reputation hints."""
from __future__ import annotations

import datetime
import json
import re
import socket
import ssl
import time
from typing import Any, Dict, List, Optional, Tuple

from core import net_dns
from core.models import Report, RiskLevel
from core.security import is_private_ip, redact_text
from modules.url_analyzer import registrable_domain, SUSPICIOUS_TLDS

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV")

WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io": "whois.nic.io",
    "dev": "whois.nic.google",
    "app": "whois.nic.google",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "pk": "whois.pknic.net.pk",
    "info": "whois.afilias.net",
    "xyz": "whois.nic.xyz",
    "co": "whois.nic.co",
}

WHOIS_QUERY = "whois.iana.org"


class WhoisError(Exception):
    """Raised when no WHOIS server answers."""


def _tcp_text(server: str, query: str, port: int = 43, timeout: float = 8.0) -> str:
    with socket.create_connection((server, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((query.strip() + "\r\n").encode("utf-8"))
        chunks: List[bytes] = []
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
            if sum(len(chunk) for chunk in chunks) > 200_000:
                break
    return b"".join(chunks).decode("utf-8", "replace")


def whois_lookup(domain: str, timeout: float = 8.0) -> Dict[str, Any]:
    """Port-43 WHOIS with IANA referral fallback. Returns parsed key fields."""
    domain = domain.strip().lower().strip(".")
    if not domain or " " in domain:
        raise WhoisError("invalid domain")
    tld = domain.rsplit(".", 1)[-1]
    errors: List[str] = []
    server = WHOIS_SERVERS.get(tld)
    raw = ""
    used = ""
    if server:
        try:
            raw = _tcp_text(server, domain, timeout=timeout)
            used = server
        except OSError as exc:
            errors.append("{}: {}".format(server, exc))
    if not raw:
        try:
            referral = _tcp_text(WHOIS_QUERY, tld, timeout=timeout)
            for line in referral.splitlines():
                if line.lower().startswith("refer:"):
                    candidate = line.split(":", 1)[1].strip()
                    if candidate:
                        raw = _tcp_text(candidate, domain, timeout=timeout)
                        used = candidate
                        break
        except OSError as exc:
            errors.append("iana: {}".format(exc))
    if not raw:
        raise WhoisError("WHOIS unavailable ({})".format("; ".join(errors) or "no referral"))

    parsed = parse_whois(raw)
    parsed["server"] = used
    parsed["raw_length"] = len(raw)
    return parsed


FIELD_ALIASES = {
    "registrar": ("registrar", "sponsoring registrar", "registrar name"),
    "created": ("creation date", "created", "created on", "registered on", "registration date"),
    "updated": ("updated date", "last updated", "last modified", "changed"),
    "expires": ("registry expiry date", "expiry date", "expiration date", "expires", "paid-till"),
    "status": ("domain status", "status"),
    "nameservers": ("name server", "nserver", "nameserver"),
    "registrant_country": ("registrant country", "country"),
    "dnssec": ("dnssec",),
}


def parse_whois(raw: str) -> Dict[str, Any]:
    """Extract the fields we care about; keep unknown lines out of the report."""
    buckets: Dict[str, List[str]] = {key: [] for key in FIELD_ALIASES}
    for line in raw.splitlines():
        if ":" not in line or line.strip().startswith("%") or line.strip().startswith("#"):
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = redact_text(value.strip())
        if not value:
            continue
        for field, aliases in FIELD_ALIASES.items():
            if key in aliases:
                if value not in buckets[field]:
                    buckets[field].append(value)
                break
    result: Dict[str, Any] = {}
    for field, values in buckets.items():
        if not values:
            continue
        if field in ("status", "nameservers"):
            result[field] = values[:8]
        else:
            result[field] = values[0]
    return result


def rdap_lookup(domain: str, timeout: float = 8.0) -> Dict[str, Any]:
    """RDAP over HTTPS; works when port 43 is blocked on mobile networks."""
    import http.client

    result: Dict[str, Any] = {"available": False, "error": None}
    try:
        connection = http.client.HTTPSConnection(
            "rdap.org", 443, timeout=timeout, context=ssl.create_default_context()
        )
        connection.request(
            "GET",
            "/domain/{}".format(domain),
            headers={"Accept": "application/rdap+json", "User-Agent": "SHADOW-X-Ultimate/1.0"},
        )
        response = connection.getresponse()
        raw = response.read(100_000).decode("utf-8", "replace")
        connection.close()
        if response.status != 200:
            result["error"] = "HTTP {}".format(response.status)
            return result
        data = json.loads(raw)
        events = {}
        for event in data.get("events", []) or []:
            action = str(event.get("eventAction", "")).lower()
            if event.get("eventDate"):
                events[action] = event["eventDate"]
        nameservers = [
            item.get("ldhName") for item in (data.get("nameservers") or []) if item.get("ldhName")
        ]
        status = data.get("status") or []
        result.update(
            {
                "available": True,
                "handle": data.get("handle"),
                "status": status,
                "events": events,
                "nameservers": nameservers[:8],
                "secure_dns": bool(data.get("secureDNS", {}).get("delegationSigned")),
            }
        )
    except Exception as exc:
        result["error"] = "{}: {}".format(type(exc).__name__, exc)
    return result


def parse_date(value: Any) -> Optional[datetime.datetime]:
    if not value:
        return None
    text = str(value).strip()
    candidates = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d",
        "%d-%b-%Y",
        "%Y.%m.%d",
        "%Y%m%d",
    ]
    for fmt in candidates:
        try:
            parsed = datetime.datetime.strptime(text[:len(fmt) + 10], fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=datetime.timezone.utc)
            return parsed
        except ValueError:
            continue
    match = re.search(r"(\d{4}-\d{2}-\d{2})", text)
    if match:
        try:
            return datetime.datetime.fromisoformat(match.group(1)).replace(
                tzinfo=datetime.timezone.utc
            )
        except ValueError:
            return None
    return None


def tls_info(domain: str, port: int = 443, timeout: float = 8.0) -> Dict[str, Any]:
    """Certificate subject/issuer/SAN plus negotiated protocol and cipher."""
    result: Dict[str, Any] = {"available": False, "error": None}
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert() or {}
                san = [value for key, value in (cert.get("subjectAltName") or []) if key == "DNS"]
                not_after = cert.get("notAfter")
                days_left = None
                if not_after:
                    try:
                        expiry = datetime.datetime.strptime(
                            not_after, "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=datetime.timezone.utc)
                        days_left = (expiry - datetime.datetime.now(datetime.timezone.utc)).days
                    except ValueError:
                        days_left = None
                result.update(
                    {
                        "available": True,
                        "subject": dict(item[0] for item in cert.get("subject", []) if item),
                        "issuer": dict(item[0] for item in cert.get("issuer", []) if item),
                        "not_before": cert.get("notBefore"),
                        "not_after": not_after,
                        "days_remaining": days_left,
                        "san": san[:40],
                        "san_count": len(san),
                        "protocol": tls.version(),
                        "cipher": tls.cipher()[0] if tls.cipher() else None,
                        "expired": bool(days_left is not None and days_left < 0),
                    }
                )
    except ssl.SSLCertVerificationError as exc:
        result["error"] = "certificate verification failed: {}".format(exc)
    except Exception as exc:
        result["error"] = "{}: {}".format(type(exc).__name__, exc)
    return result


def spf_record(txt_records: List[str]) -> Optional[str]:
    for record in txt_records or []:
        if str(record).lower().startswith("v=spf1"):
            return str(record)
    return None


def analyze_spf(record: Optional[str]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    data: Dict[str, Any] = {"record": record, "all_qualifier": None, "dns_lookups_estimate": None}
    if not record:
        findings.append({
            "title": "No SPF record",
            "severity": "medium",
            "detail": "Without SPF, anyone can send mail claiming to be from this domain.",
            "recommendation": "Publish a single v=spf1 record ending in -all or ~all.",
        })
        return findings, data
    tokens = record.split()
    qualifier = None
    for token in tokens[1:]:
        if token.endswith("all") and token[0] in "+-~?":
            qualifier = token[0]
            break
    data["all_qualifier"] = qualifier
    data["dns_lookups_estimate"] = sum(
        1 for token in tokens if any(marker in token for marker in ("include:", "a:", "mx", "ptr", "exists:"))
    )
    if qualifier == "+":
        findings.append({
            "title": "SPF ends with +all",
            "severity": "critical",
            "detail": "+all authorises every server on the internet to send mail as this domain.",
            "recommendation": "Change +all to -all (or ~all while you validate the record).",
        })
    elif qualifier is None:
        findings.append({
            "title": "SPF has no 'all' mechanism",
            "severity": "medium",
            "detail": "The default result for unlisted senders is neutral, so spoofing is not blocked.",
            "recommendation": "Terminate the record with -all.",
        })
    elif qualifier == "?":
        findings.append({
            "title": "SPF ends with ?all (neutral)",
            "severity": "low",
            "detail": "?all explicitly declines to state a policy for other senders.",
            "recommendation": "Use -all once you have confirmed all legitimate senders.",
        })
    if (data["dns_lookups_estimate"] or 0) > 10:
        findings.append({
            "title": "SPF exceeds the 10 DNS lookup limit",
            "severity": "medium",
            "detail": "{} lookup mechanisms found; receivers may return permerror.".format(
                data["dns_lookups_estimate"]),
            "recommendation": "Flatten includes so the record stays within 10 lookups.",
        })
    return findings, data


def analyze_dmarc(records: List[str]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    record = None
    for item in records or []:
        if str(item).lower().startswith("v=dmarc1"):
            record = str(item)
            break
    data: Dict[str, Any] = {"record": record, "policy": None, "pct": 100, "rua": None}
    if not record:
        findings.append({
            "title": "No DMARC record",
            "severity": "medium",
            "detail": "Without DMARC, receivers have no instruction for failing mail and you get no reports.",
            "recommendation": "Publish v=DMARC1; p=none; rua=mailto:dmarc@yourdomain and tighten to p=reject.",
        })
        return findings, data
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, _, value = part.partition("=")
            tags[key.strip().lower()] = value.strip()
    policy = (tags.get("p") or "none").lower()
    data.update(
        {
            "policy": policy,
            "subdomain_policy": tags.get("sp"),
            "pct": tags.get("pct", "100"),
            "rua": tags.get("rua"),
            "ruf": tags.get("ruf"),
        }
    )
    if policy == "none":
        findings.append({
            "title": "DMARC policy is p=none (monitor only)",
            "severity": "low",
            "detail": "Failing mail is still delivered; the domain remains spoofable.",
            "recommendation": "Move to p=quarantine then p=reject once reports look clean.",
        })
    if not tags.get("rua"):
        findings.append({
            "title": "DMARC has no aggregate report address",
            "severity": "low",
            "detail": "Without rua you will not see who is sending as your domain.",
            "recommendation": "Add rua=mailto:dmarc@yourdomain.",
        })
    return findings, data


def analyze(domain: str, timeout: float = 8.0, include_whois: bool = True) -> Report:
    """Full domain intelligence pass."""
    target = str(domain or "").strip().lower()
    if "://" in target:
        from urllib.parse import urlsplit

        target = urlsplit(target).hostname or target
    target = target.strip(".")
    report = Report(module="domain_intelligence", target=target)
    report.limitations = [
        "WHOIS and RDAP data is self-reported by registrars and can be redacted.",
        "Reputation indicators here are heuristic; no third-party blocklist is queried by default.",
        "DNS answers may be geo-steered or CDN-specific and differ from other vantage points.",
    ]
    if not target:
        report.add_finding("Input", "Empty domain", severity=RiskLevel.HIGH, detail="No domain supplied.")
        return report

    records: Dict[str, Any] = {}
    for rdtype in RECORD_TYPES:
        try:
            result = net_dns.query(target, rdtype, timeout=min(timeout, 5.0))
            values = [
                item["value"] for item in result.get("answers", [])
                if item.get("type") == rdtype
            ]
            records[rdtype] = values
            if result.get("rcode") not in (0, 3):
                records[rdtype] = {"rcode": result.get("rcode_text")}
        except Exception as exc:
            records[rdtype] = {"error": str(exc)[:120]}
    report.add_section("DNS Records", {key: value for key, value in records.items() if value})

    a_values = records.get("A") or []
    if not a_values or isinstance(a_values, dict):
        report.add_finding(
            "DNS Records",
            "Domain does not resolve",
            severity=RiskLevel.MEDIUM,
            detail="No A record returned for this name.",
            recommendation="Confirm the domain is registered and its DNS is live.",
        )

    txt_values = [item for item in (records.get("TXT") or []) if isinstance(item, str)]
    spf_findings, spf_data = analyze_spf(spf_record(txt_values))
    spf_section = report.add_section("Email Authentication (SPF)", spf_data)
    for item in spf_findings:
        spf_section.add(**item)

    dmarc_records: List[str] = []
    dmarc_name = "_dmarc.{}".format(target)
    try:
        dmarc_result = net_dns.query(dmarc_name, "TXT", timeout=min(timeout, 5.0))
        dmarc_records = [
            item["value"] for item in dmarc_result.get("answers", [])
            if item.get("type") == "TXT" and isinstance(item.get("value"), str)
        ]
    except Exception:
        dmarc_records = []
    dmarc_findings, dmarc_data = analyze_dmarc(dmarc_records)
    dmarc_section = report.add_section("Email Authentication (DMARC)", dmarc_data)
    for item in dmarc_findings:
        dmarc_section.add(**item)

    if include_whois:
        whois_data: Dict[str, Any] = {}
        whois_section = report.add_section("WHOIS", {})
        try:
            whois_data = whois_lookup(target, timeout=timeout)
            whois_section.data.update(whois_data)
            expires = parse_date(whois_data.get("expires"))
            if expires:
                days = (expires - datetime.datetime.now(datetime.timezone.utc)).days
                whois_section.data["days_until_expiry"] = days
                if days < 0:
                    whois_section.add(
                        title="Registration has expired",
                        severity=RiskLevel.HIGH,
                        detail="The registry expiry date is in the past.",
                        recommendation="Renew immediately; expired domains are quickly taken over.",
                    )
                elif days < 30:
                    whois_section.add(
                        title="Registration expires in {} days".format(days),
                        severity=RiskLevel.MEDIUM,
                        detail="An expired domain can be re-registered by someone else.",
                        recommendation="Renew the registration and enable auto-renew.",
                    )
        except WhoisError as exc:
            report.add_finding(
                "WHOIS",
                "WHOIS unavailable",
                severity=RiskLevel.INFO,
                detail=str(exc),
                recommendation="Try again later or from another network; RDAP results below still apply.",
            )
        rdap = rdap_lookup(target, timeout=timeout)
        if rdap.get("available"):
            rdap_section = report.add_section("RDAP", {k: v for k, v in rdap.items() if k != "available"})
            events = rdap.get("events") or {}
            expiry = parse_date(events.get("expiration"))
            if expiry and "days_until_expiry" not in whois_section.data:
                days = (expiry - datetime.datetime.now(datetime.timezone.utc)).days
                rdap_section.data["days_until_expiry"] = days
        else:
            report.add_finding(
                "RDAP",
                "RDAP lookup failed",
                severity=RiskLevel.INFO,
                detail=rdap.get("error") or "no data",
                recommendation="No action needed; WHOIS results remain authoritative where present.",
            )

    certificate = tls_info(target, timeout=timeout)
    tls_section = report.add_section("TLS Certificate", {k: v for k, v in certificate.items() if k != "available"})
    if not certificate.get("available"):
        tls_section.add(
            title="TLS handshake failed",
            severity=RiskLevel.MEDIUM,
            detail=certificate.get("error") or "no certificate returned",
            recommendation="Serve a valid certificate from a trusted CA over TLS 1.2+.",
        )
    else:
        days = certificate.get("days_remaining")
        if certificate.get("expired"):
            tls_section.add(
                title="Certificate expired",
                severity=RiskLevel.HIGH,
                detail="Expired {}.".format(certificate.get("not_after")),
                recommendation="Renew the certificate and automate renewal.",
            )
        elif isinstance(days, int) and days < 21:
            tls_section.add(
                title="Certificate expires in {} days".format(days),
                severity=RiskLevel.MEDIUM,
                detail="Expiry: {}".format(certificate.get("not_after")),
                recommendation="Renew before expiry; automate it.",
            )
        san = certificate.get("san") or []
        if san and target not in san and not any(
            name.startswith("*.") and target.endswith(name[1:]) for name in san
        ):
            tls_section.add(
                title="Certificate does not list this hostname",
                severity=RiskLevel.HIGH,
                detail="SAN entries: {}".format(", ".join(san[:6])),
                recommendation="Reissue the certificate with the correct SANs.",
            )
        if certificate.get("protocol") in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            tls_section.add(
                title="Obsolete TLS version negotiated",
                severity=RiskLevel.HIGH,
                detail="Negotiated {}.".format(certificate.get("protocol")),
                recommendation="Disable TLS 1.0/1.1 and allow only TLS 1.2 and 1.3.",
            )

    registered = registrable_domain(target)
    tld = target.rsplit(".", 1)[-1] if "." in target else ""
    reputation_findings: List[Dict[str, Any]] = []
    if tld in SUSPICIOUS_TLDS:
        reputation_findings.append({
            "title": "High-abuse TLD .{}".format(tld),
            "severity": "medium",
            "detail": ".{} registrations are cheap and frequently abused for phishing.".format(tld),
            "recommendation": "Increase scrutiny of mail and links from this TLD.",
        })
    if len(registered.split(".")[0]) <= 4 and tld in SUSPICIOUS_TLDS:
        reputation_findings.append({
            "title": "Very short registered name on an abused TLD",
            "severity": "medium",
            "detail": "Short throwaway names are typical of campaign infrastructure.",
            "recommendation": "Block or quarantine this domain at the mail gateway until reviewed.",
        })
    if re.search(r"\d{4,}", registered):
        reputation_findings.append({
            "title": "Long digit run in the domain name",
            "severity": "low",
            "detail": "Random-looking digits often indicate automated registration.",
            "recommendation": "Confirm the domain with the organisation it claims to represent.",
        })
    rep_section = report.add_section(
        "Reputation Indicators",
        {
            "registered_domain": registered,
            "notes": "heuristic only - no blocklist or reputation API was queried",
        },
    )
    for item in reputation_findings:
        rep_section.add(**item)
    if not reputation_findings:
        rep_section.add(
            title="No heuristic red flags",
            severity=RiskLevel.INFO,
            detail="No suspicious naming patterns were detected.",
            recommendation="Absence of heuristics is not a reputation guarantee.",
        )

    score = 0
    for finding in report.findings:
        score += {"critical": 30, "high": 18, "medium": 8, "low": 3, "info": 0}[
            finding.severity.value
        ]
    report.risk_score = min(100, score)
    report.metadata["records_checked"] = list(RECORD_TYPES)
    report.metadata["resolved_addresses"] = a_values if isinstance(a_values, list) else []
    return report
