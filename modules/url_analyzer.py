"""URL analysis: structure, redirects, TLS, phishing indicators, risk score.

All network access is guarded: private/loopback/link-local destinations are
refused (SSRF protection), redirects are capped, timeouts are enforced and no
credential is ever attached to an outbound request.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit, urlunsplit

from core import net_dns
from core.models import Report, RiskLevel
from core.security import (
    assert_public_target,
    is_private_ip,
    redact_headers,
    truncate,
    UnsafeTargetError,
)

SUSPICIOUS_TLDS = {
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "work", "click",
    "link", "loan", "review", "country", "kim", "cricket", "science", "party",
    "gdn", "stream", "download", "racing", "win", "bid", "date", "faith",
}

BRAND_KEYWORDS = (
    "paypal", "apple", "icloud", "microsoft", "office365", "outlook", "google",
    "gmail", "amazon", "netflix", "facebook", "instagram", "whatsapp", "binance",
    "coinbase", "metamask", "dhl", "fedex", "ups", "hsbc", "chase", "wellsfargo",
)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "tr.im",
}

IP_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
PUNYCODE_RE = re.compile(r"^xn--", re.IGNORECASE)
MANY_DASHES_RE = re.compile(r"-")
SENSITIVE_PATH_TOKENS = (
    "login", "signin", "verify", "account", "update", "secure", "password",
    "wallet", "recover", "confirm", "billing", "invoice", "unlock", "suspend",
    "webscr", "auth", "token",
)


class URLAnalysisError(ValueError):
    """Raised when a URL cannot be parsed or is blocked for safety."""


@dataclass
class ParsedURL:
    raw: str
    scheme: str = ""
    hostname: str = ""
    port: Optional[int] = None
    path: str = "/"
    query: str = ""
    fragment: str = ""
    username: Optional[str] = None
    password: Optional[str] = None
    query_params: Dict[str, str] = field(default_factory=dict)

    @property
    def effective_port(self) -> int:
        if self.port:
            return self.port
        return 443 if self.scheme == "https" else 80

    @property
    def origin(self) -> str:
        host = self.hostname
        if ":" in host and not host.startswith("["):
            host = "[{}]".format(host)
        default = 443 if self.scheme == "https" else 80
        if self.port and self.port != default:
            return "{}://{}:{}".format(self.scheme, host, self.port)
        return "{}://{}".format(self.scheme, host)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scheme": self.scheme,
            "hostname": self.hostname,
            "port": self.effective_port,
            "path": self.path,
            "query": truncate(self.query, 300),
            "fragment": self.fragment,
            "has_userinfo": bool(self.username or self.password),
            "query_params": dict(list(self.query_params.items())[:12]),
        }


def normalize_url(raw: str) -> str:
    """Add a scheme when missing and strip surrounding whitespace/control chars."""
    text = str(raw or "").strip().strip('"\'')
    text = "".join(ch for ch in text if ch.isprintable())
    if not text:
        raise URLAnalysisError("empty URL")
    if "://" not in text:
        text = "http://" + text.lstrip("/")
    return text


def parse_url(raw: str) -> ParsedURL:
    """Validate and decompose a URL into its parts."""
    text = normalize_url(raw)
    parts = urlsplit(text)
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise URLAnalysisError(
            "unsupported scheme {!r} - only http and https are analysed".format(scheme)
        )
    hostname = (parts.hostname or "").strip().strip(".")
    if not hostname:
        raise URLAnalysisError("URL has no hostname: {!r}".format(raw))
    if len(hostname) > 253:
        raise URLAnalysisError("hostname is too long")
    if " " in hostname or "\x00" in hostname:
        raise URLAnalysisError("hostname contains illegal characters")
    try:
        port: Optional[int] = parts.port
    except ValueError as exc:
        # urlsplit raises ValueError for a non-numeric or out-of-range port.
        raise URLAnalysisError("invalid port in {!r}: {}".format(raw, exc))
    if port is not None and not (1 <= port <= 65535):
        raise URLAnalysisError("port out of range: {}".format(port))
    parsed = ParsedURL(
        raw=text,
        scheme=scheme,
        hostname=hostname.lower(),
        port=port,
        path=parts.path or "/",
        query=parts.query,
        fragment=parts.fragment,
        username=parts.username,
        password=parts.password,
    )
    try:
        parsed.query_params = dict(parse_qsl(parts.query, keep_blank_values=True))
    except Exception:
        parsed.query_params = {}
    return parsed


def registrable_domain(hostname: str) -> str:
    """Best-effort eTLD+1 without a public-suffix dependency."""
    host = (hostname or "").lower().strip(".")
    if not host or IP_HOST_RE.match(host) or ":" in host:
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    # Handle common two-level public suffixes (co.uk, com.au, ...)
    two_level = {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "net.in", "co.jp",
        "co.kr", "com.au", "net.au", "org.au", "com.br", "com.pk", "com.tr",
        "com.sa", "co.za", "com.mx", "com.ar", "co.nz",
    }
    tail = ".".join(labels[-2:])
    if tail in two_level and len(labels) >= 3:
        return ".".join(labels[-3:])
    return tail


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            cost = 0 if char_a == char_b else 1
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost))
        previous = current
    return previous[-1]


def _similar_brand(host: str) -> Optional[str]:
    """Return a brand name the host is typosquatting, if any."""
    labels = [label for label in host.lower().split(".") if label]
    if not labels:
        return None
    for label in labels[:-1]:
        for brand in BRAND_KEYWORDS:
            if label == brand:
                continue
            if len(label) >= 4 and _levenshtein(label, brand) in (1, 2):
                return brand
    return None


def analyze_structure(parsed: ParsedURL) -> Tuple[List[Dict[str, Any]], int]:
    """Determine whether a URL was typed by a human. Returns (findings, weight)."""
    findings: List[Dict[str, Any]] = []
    weight = 0
    host = parsed.hostname
    labels = host.split(".")
    tld = labels[-1] if labels else ""
    registered = registrable_domain(host)

    if parsed.username or parsed.password:
        findings.append({
            "title": "Credentials embedded in the URL",
            "severity": "high",
            "detail": "The URL carries user:password@ before the host. Browsers may ignore it, "
                      "but it is a classic way to disguise the real destination.",
            "recommendation": "Never trust a link that embeds credentials. Open the site by typing its domain.",
        })
        weight += 25

    if IP_HOST_RE.match(host) or ":" in host:
        findings.append({
            "title": "Destination is a raw IP address",
            "severity": "medium" if is_private_ip(host) else "low",
            "detail": "Legitimate public services normally use a domain name, not a bare address.",
            "recommendation": "Verify the owner of the address before entering any data.",
        })
        weight += 12

    if is_private_ip(host):
        findings.append({
            "title": "Target is not a public address",
            "severity": "medium",
            "detail": "The host resolves to loopback, private or reserved address space, so the "
                      "analysis is limited and network checks are blocked.",
            "recommendation": "Analyse public URLs only; internal addresses are out of scope.",
        })

    if tld in SUSPICIOUS_TLDS:
        findings.append({
            "title": "High-abuse top level domain .{}".format(tld),
            "severity": "medium",
            "detail": ".{} is frequently used in throwaway phishing campaigns because registration is free or very cheap.".format(tld),
            "recommendation": "Treat unexpected .{} links as hostile until independently verified.".format(tld),
        })
        weight += 15

    if PUNYCODE_RE.match(labels[0] if labels else "") or "xn--" in host:
        findings.append({
            "title": "Punycode / internationalised hostname",
            "severity": "medium",
            "detail": "The hostname uses xn-- encoding, which can render as visually identical "
                      "characters from another alphabet (homograph attack).",
            "recommendation": "Decode the hostname with a trusted tool before clicking.",
        })
        weight += 20

    brand = _similar_brand(host)
    if brand:
        findings.append({
            "title": "Possible typosquat of '{}'".format(brand),
            "severity": "high",
            "detail": "The registered name '{}' is one or two edits away from the brand '{}'.".format(registered, brand),
            "recommendation": "Reach the brand through its official domain instead of this link.",
        })
        weight += 30

    # A brand name parked inside a *different* registered domain is the single
    # strongest cheap phishing signal: paypal-secure-verify.tk is not paypal.com.
    name_part = (registered.split(".")[0] if registered else "").lower()
    embedded = [
        word for word in BRAND_KEYWORDS
        if len(word) >= 4 and word in name_part and name_part not in (word,)
    ]
    if embedded:
        findings.append({
            "title": "Brand name '{}' used inside an unrelated domain".format(embedded[0]),
            "severity": "high",
            "detail": (
                "The registered domain '{}' merely contains the word '{}'; it is not "
                "operated by that brand. Legitimate brands use their own domain."
            ).format(registered, embedded[0]),
            "recommendation": "Contact the organisation through its official site, never through this link.",
            "evidence": {"registered_domain": registered, "brand": embedded[0]},
        })
        weight += 35

    dash_count = len(MANY_DASHES_RE.findall(registered.split(".")[0] if registered else ""))
    if dash_count >= 3:
        findings.append({
            "title": "Heavily hyphenated domain",
            "severity": "low",
            "detail": "{} hyphens in the registered name - a common pattern in lookalike domains.".format(dash_count),
            "recommendation": "Confirm the exact domain with the organisation directly.",
        })
        weight += 8

    if len(host) > 60:
        findings.append({
            "title": "Unusually long hostname",
            "severity": "low",
            "detail": "{} characters - long names can push the real domain out of a mobile address bar.".format(len(host)),
            "recommendation": "Scroll the address bar to read the actual registered domain.",
        })
        weight += 6

    # Hyphenation matters even at two dashes when a brand word is present.
    if dash_count == 2 and embedded:
        findings.append({
            "title": "Hyphenated brand-substring domain",
            "severity": "medium",
            "detail": "Two hyphens plus a brand word is the classic throwaway phishing shape.",
            "recommendation": "Treat this domain as hostile until the brand confirms otherwise.",
        })
        weight += 10

    if len(labels) >= 5:
        findings.append({
            "title": "Deep subdomain chain",
            "severity": "low",
            "detail": "{} labels deep; a familiar brand name in a subdomain says nothing about the owner.".format(len(labels)),
            "recommendation": "Judge the registered domain, not the subdomains in front of it.",
        })
        weight += 6

    if registered in SHORTENERS:
        findings.append({
            "title": "URL shortener hides the destination",
            "severity": "medium",
            "detail": "{} is a link shortener; the real target only appears after a redirect.".format(registered),
            "recommendation": "Expand the short link first and check the final destination.",
        })
        weight += 15

    path_lower = unquote(parsed.path).lower()
    hits = [token for token in SENSITIVE_PATH_TOKENS if token in path_lower]
    if len(hits) >= 2:
        findings.append({
            "title": "Credential-harvesting path pattern",
            "severity": "high",
            "detail": "The path combines {} - typical of fake login pages.".format(", ".join(hits[:4])),
            "recommendation": "Never sign in from a link; navigate to the service yourself.",
        })
        weight += 20

    if re.search(r"\.(php|asp|aspx|cgi)$", path_lower) and len(parsed.query_params) >= 3:
        findings.append({
            "title": "Script endpoint with many parameters",
            "severity": "low",
            "detail": "Path ends in a server script and carries {} query parameters.".format(len(parsed.query_params)),
            "recommendation": "Treat parameter-heavy script URLs with suspicion in unsolicited messages.",
        })
        weight += 5

    if "@" in parsed.raw.split("?")[0].replace("://", "", 1):
        if parsed.username or parsed.password:
            pass  # already reported
        else:
            findings.append({
                "title": "Ambiguous @ in the authority section",
                "severity": "medium",
                "detail": "An @ appears before the path; some parsers read everything before it as credentials.",
                "recommendation": "Do not click; the displayed and actual hosts may differ.",
            })
            weight += 15

    return findings, min(weight, 60)


def _http_request(
    parsed: ParsedURL, timeout: float = 8.0
) -> Dict[str, Any]:
    """Single HTTP(S) request with no automatic redirects and no credentials."""
    host = parsed.hostname
    port = parsed.effective_port
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query

    headers = {
        "Host": host if port in (80, 443) else "{}:{}".format(host, port),
        "User-Agent": "SHADOW-X-Ultimate/1.0 (+authorized-security-check)",
        "Accept": "*/*",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    context = ssl.create_default_context()
    result: Dict[str, Any] = {
        "url": parsed.raw,
        "status": None,
        "reason": "",
        "headers": {},
        "elapsed_ms": None,
        "error": None,
        "tls": None,
    }
    started = time.time()
    connection = None
    try:
        if parsed.scheme == "https":
            connection = http.client.HTTPSConnection(
                host, port, timeout=timeout, context=context
            )
        else:
            connection = http.client.HTTPConnection(host, port, timeout=timeout)
        connection.request("GET", target, headers=headers)
        response = connection.getresponse()
        body = b""
        try:
            body = response.read(4096)
        except Exception:
            body = b""
        result["status"] = response.status
        result["reason"] = response.reason
        result["headers"] = redact_headers(response.getheaders())
        result["elapsed_ms"] = int((time.time() - started) * 1000)
        result["body_bytes"] = len(body)
        if parsed.scheme == "https":
            sock = getattr(connection, "sock", None)
            if sock is not None:
                try:
                    result["tls"] = summarize_certificate(sock.getpeercert())
                except Exception:
                    result["tls"] = None
    except ssl.SSLError as exc:
        result["error"] = "TLS error: {}".format(exc)
    except socket.timeout:
        result["error"] = "timed out after {}s".format(timeout)
    except (socket.gaierror, OSError, http.client.HTTPException) as exc:
        result["error"] = "{}: {}".format(type(exc).__name__, exc)
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
    return result


def summarize_certificate(cert: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not cert:
        return None
    def flatten(items: Any) -> List[str]:
        out: List[str] = []
        for entry in items or []:
            for pair in entry:
                if isinstance(pair, tuple) and len(pair) == 2:
                    out.append("{}={}".format(pair[0], pair[1]))
        return out

    dns_names = [value for key, value in (cert.get("subjectAltName") or []) if key == "DNS"]
    return {
        "subject": flatten(cert.get("subject")),
        "issuer": flatten(cert.get("issuer")),
        "version": cert.get("version"),
        "serial": cert.get("serialNumber"),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "san_dns": dns_names[:30],
        "san_count": len(dns_names),
    }


def follow_redirects(
    parsed: ParsedURL,
    max_redirects: int = 5,
    timeout: float = 8.0,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Walk the redirect chain, refusing to hop onto a private address."""
    chain: List[Dict[str, Any]] = []
    current = parsed
    seen = {parsed.raw}
    final: Dict[str, Any] = {}
    for _hop in range(max(0, max_redirects) + 1):
        hop = _http_request(current, timeout=timeout)
        hop["url"] = current.raw
        chain.append(hop)
        final = hop
        location = None
        for key, value in (hop.get("headers") or {}).items():
            if key.lower() == "location":
                location = value
                break
        if not location or hop.get("status") is None:
            break
        if hop["status"] not in (301, 302, 303, 307, 308):
            break
        absolute = urljoin(current.raw, location)
        if absolute in seen:
            chain.append({"error": "redirect loop detected", "url": absolute})
            break
        seen.add(absolute)
        try:
            next_parsed = parse_url(absolute)
            assert_public_target(next_parsed.hostname, next_parsed.effective_port)
        except (URLAnalysisError, UnsafeTargetError) as exc:
            chain.append({"error": "blocked redirect: {}".format(exc), "url": absolute})
            break
        current = next_parsed
    return chain, final


def dns_footprint(hostname: str, timeout: float = 5.0) -> Dict[str, Any]:
    """Address records plus reverse DNS for a hostname."""
    result: Dict[str, Any] = {"a": [], "aaaa": [], "ptr": {}, "error": None}
    for rdtype, key in (("A", "a"), ("AAAA", "aaaa")):
        try:
            records = net_dns.get_records(hostname, rdtype, timeout=timeout)
            result[key] = records
        except Exception as exc:
            if key == "a":
                result["error"] = str(exc)
    for address in (result["a"] + result["aaaa"])[:6]:
        try:
            result["ptr"][address] = net_dns.reverse_lookup(address, timeout=timeout)
        except Exception:
            result["ptr"][address] = []
    return result


SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", "high"),
    "content-security-policy": ("CSP", "high"),
    "x-content-type-options": ("X-Content-Type-Options", "medium"),
    "x-frame-options": ("X-Frame-Options", "medium"),
    "referrer-policy": ("Referrer-Policy", "low"),
    "permissions-policy": ("Permissions-Policy", "low"),
}


def analyze_security_headers(headers: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    lower = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
    findings: List[Dict[str, Any]] = []
    present: Dict[str, str] = {}
    missing: List[str] = []
    for header, (label, severity) in SECURITY_HEADERS.items():
        if header in lower:
            present[label] = lower[header]
        else:
            missing.append(label)
    if missing:
        findings.append({
            "title": "Missing security headers",
            "severity": "medium" if len(missing) >= 3 else "low",
            "detail": "Not set: {}".format(", ".join(missing)),
            "recommendation": "Add the missing headers at the web server or CDN layer.",
        })
    if "server" in lower:
        findings.append({
            "title": "Server banner exposed",
            "severity": "low",
            "detail": "Server: {}".format(lower["server"][:120]),
            "recommendation": "Reduce version disclosure in the Server header.",
        })
    if lower.get("x-powered-by"):
        findings.append({
            "title": "Technology disclosed via X-Powered-By",
            "severity": "low",
            "detail": "X-Powered-By: {}".format(lower["x-powered-by"][:120]),
            "recommendation": "Remove the X-Powered-By header.",
        })
    return findings, {"present": present, "missing": missing}


def analyze(
    url: str,
    timeout: float = 8.0,
    max_redirects: int = 5,
    follow: bool = True,
    allow_private: bool = False,
) -> Report:
    """Full URL analysis returning a populated Report."""
    report = Report(module="url_analyzer", target=url)
    report.limitations = [
        "A URL analysis inspects the link itself; it cannot prove the site's intentions.",
        "No page content is executed or downloaded beyond the first 4 KB of the response.",
        "Reputation lookups require an optional API key and are skipped when unset.",
        "Private, loopback and link-local destinations are deliberately refused (SSRF guard).",
    ]
    try:
        parsed = parse_url(url)
    except URLAnalysisError as exc:
        report.risk_score = 0
        report.add_finding(
            "Input",
            "URL rejected",
            severity=RiskLevel.HIGH,
            detail=str(exc),
            recommendation="Provide a full http:// or https:// URL with a valid hostname.",
        )
        return report

    report.target = parsed.raw
    structure_findings, structure_weight = analyze_structure(parsed)
    input_section = report.add_section("URL Structure", parsed.to_dict())
    for item in structure_findings:
        input_section.add(**item)

    resolved: List[str] = []
    try:
        resolved = assert_public_target(
            parsed.hostname, parsed.effective_port, allow_private=allow_private
        )
    except UnsafeTargetError as exc:
        report.add_finding(
            "Safety",
            "Target blocked by SSRF guard",
            severity=RiskLevel.MEDIUM,
            detail=str(exc),
            recommendation="Analyse publicly routable URLs only.",
        )
        report.risk_score = min(100, structure_weight + 10)
        return report

    dns_info = dns_footprint(parsed.hostname, timeout=min(timeout, 5.0))
    dns_info["resolved"] = resolved
    dns_section = report.add_section("DNS Resolution", dns_info)
    if not dns_info.get("a") and not dns_info.get("aaaa"):
        dns_section.add(
            title="No address records returned",
            severity=RiskLevel.MEDIUM,
            detail=dns_info.get("error") or "The resolver returned no A/AAAA records.",
            recommendation="A live site should publish at least one address record.",
        )

    chain_weight = 0
    if follow:
        chain, final = follow_redirects(parsed, max_redirects=max_redirects, timeout=timeout)
        redirect_data = {
            "hops": len(chain),
            "chain": [
                {
                    "url": hop.get("url"),
                    "status": hop.get("status"),
                    "elapsed_ms": hop.get("elapsed_ms"),
                    "error": hop.get("error"),
                }
                for hop in chain
            ],
        }
        redirect_section = report.add_section("Redirect Chain", redirect_data)
        if len(chain) > 1:
            redirect_section.add(
                title="Multiple redirects",
                severity=RiskLevel.LOW if len(chain) <= 3 else RiskLevel.MEDIUM,
                detail="{} hops before the final response.".format(len(chain)),
                recommendation="Confirm every hop belongs to the expected organisation.",
            )
            chain_weight += 5 * min(len(chain) - 1, 4)
        cross_domain = [
            hop for hop in chain
            if hop.get("url") and registrable_domain(urlsplit(hop["url"]).hostname or "") != registrable_domain(parsed.hostname)
        ]
        if cross_domain:
            redirect_section.add(
                title="Redirect leaves the original domain",
                severity=RiskLevel.HIGH,
                detail="Final destination differs from {}.".format(registrable_domain(parsed.hostname)),
                recommendation="Verify the final destination before entering any data.",
            )
            chain_weight += 20

        response = final or chain[0] if chain else {}
    else:
        response = _http_request(parsed, timeout=timeout)

    http_data = {
        "status": response.get("status"),
        "reason": response.get("reason"),
        "elapsed_ms": response.get("elapsed_ms"),
        "headers": response.get("headers") or {},
        "error": response.get("error"),
    }
    http_section = report.add_section("HTTP Response", http_data)
    status = response.get("status")
    if response.get("error"):
        http_section.add(
            title="Request failed",
            severity=RiskLevel.LOW,
            detail=str(response["error"]),
            recommendation="Confirm the host is online and reachable from this network.",
        )
    elif isinstance(status, int) and status >= 400:
        http_section.add(
            title="Error status {}".format(status),
            severity=RiskLevel.LOW,
            detail="The server answered with {}. {}.".format(status, response.get("reason") or ""),
            recommendation="A dead link in an unsolicited message is itself a warning sign.",
            evidence={"status": status},
        )

    header_findings, header_data = analyze_security_headers(response.get("headers") or {})
    header_section = report.add_section("Security Headers", header_data)
    for item in header_findings:
        header_section.add(**item)

    tls_info = response.get("tls") or _tls_from_host(parsed, timeout=timeout)
    if tls_info:
        report.add_section("TLS Certificate", tls_info)
    elif parsed.scheme == "https":
        report.add_finding(
            "TLS Certificate",
            "Certificate could not be inspected",
            severity=RiskLevel.MEDIUM,
            detail="The TLS handshake did not complete with a valid certificate chain.",
            recommendation="Treat the connection as untrusted until the certificate is valid.",
        )

    base = structure_weight + chain_weight
    if not tls_info and parsed.scheme == "https":
        base += 25
    if parsed.scheme == "http":
        report.add_finding(
            "Transport",
            "Plain HTTP - no transport encryption",
            severity=RiskLevel.HIGH,
            detail="Credentials and content travel in clear text over http://.",
            recommendation="Use https:// and enable HSTS on the server.",
        )
        base += 20
    report.risk_score = min(100, base)

    if report.risk_score >= 70:
        report.add_finding(
            "Verdict",
            "Likely phishing or malicious",
            severity=RiskLevel.CRITICAL,
            detail="Multiple independent indicators combine into a high risk score.",
            recommendation="Do not open this link or enter any information on it.",
        )
    elif report.risk_score >= 40:
        report.add_finding(
            "Verdict",
            "Suspicious - verify independently",
            severity=RiskLevel.MEDIUM,
            detail="Some indicators are present but the evidence is not conclusive.",
            recommendation="Reach the organisation through an address you already trust.",
        )
    else:
        report.add_finding(
            "Verdict",
            "No strong indicators detected",
            severity=RiskLevel.INFO,
            detail="The URL shows no significant structural warning signs in this check.",
            recommendation="Absence of indicators is not proof of safety; stay cautious.",
        )
    return report


def _tls_from_host(parsed: ParsedURL, timeout: float = 8.0) -> Optional[Dict[str, Any]]:
    """Explicit TLS handshake for the case where the HTTP layer failed."""
    if parsed.scheme != "https":
        return None
    context = ssl.create_default_context()
    try:
        with socket.create_connection(
            (parsed.hostname, parsed.effective_port), timeout=timeout
        ) as sock:
            with context.wrap_socket(sock, server_hostname=parsed.hostname) as tls:
                cert = tls.getpeercert()
                info = summarize_certificate(cert) or {}
                info["cipher"] = tls.cipher()[0] if tls.cipher() else None
                info["protocol"] = tls.version()
                return info
    except Exception:
        return None


def quick_verdict(url: str, timeout: float = 5.0) -> Dict[str, Any]:
    """Offline structural verdict - no network access. Used by batch links."""
    try:
        parsed = parse_url(url)
    except URLAnalysisError as exc:
        return {"url": url, "risk": "invalid", "score": 0, "error": str(exc), "findings": []}
    findings, weight = analyze_structure(parsed)
    return {
        "url": parsed.raw,
        "host": parsed.hostname,
        "registered_domain": registrable_domain(parsed.hostname),
        "score": min(100, weight),
        "risk": RiskLevel.from_score(min(100, weight)).value,
        "findings": findings,
    }
