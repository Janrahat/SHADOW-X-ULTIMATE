"""Defensive utilities: passwords, hashing, integrity, encoding, JWT, logs."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import string
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, unquote

from core.models import Report, RiskLevel
from modules.url_analyzer import analyze_security_headers

AMBIGUOUS = "Il1O0o"
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"

COMMON_WEAK = {
    "password", "123456", "12345678", "qwerty", "abc123", "letmein",
    "welcome", "admin", "monkey", "dragon", "iloveyou", "sunshine",
    "princess", "football", "charlie", "aa123456", "password1", "qwerty123",
}

KEYBOARD_RUNS = ("qwerty", "asdf", "zxcv", "1234", "abcd", "1111", "0000")


# ---------------------------------------------------------------------------
# Passwords
def generate_password(
    length: int = 20,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = True,
) -> str:
    """Cryptographically secure password via secrets.choice."""
    length = max(8, min(int(length), 128))
    pools: List[str] = []
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append(SYMBOLS)
    if not pools:
        pools.append(string.ascii_letters + string.digits)
    if avoid_ambiguous:
        pools = ["".join(ch for ch in pool if ch not in AMBIGUOUS) for pool in pools]
        pools = [pool for pool in pools if pool]

    # Guarantee at least one character from every requested pool.
    chars = [secrets.choice(pool) for pool in pools]
    combined = "".join(pools)
    while len(chars) < length:
        chars.append(secrets.choice(combined))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars[:length])


def estimate_strength(password: str) -> Dict[str, Any]:
    """Entropy-based strength estimate with a human explanation."""
    text = str(password or "")
    flags: List[str] = []
    score = 0
    if len(text) >= 8:
        score += 10
    if len(text) >= 12:
        score += 15
    if len(text) >= 16:
        score += 15
    if len(text) >= 24:
        score += 10
    classes = sum(
        [
            bool(re.search(r"[a-z]", text)),
            bool(re.search(r"[A-Z]", text)),
            bool(re.search(r"[0-9]", text)),
            bool(re.search(r"[^A-Za-z0-9]", text)),
        ]
    )
    score += classes * 8

    alphabet = 0
    if re.search(r"[a-z]", text):
        alphabet += 26
    if re.search(r"[A-Z]", text):
        alphabet += 26
    if re.search(r"[0-9]", text):
        alphabet += 10
    if re.search(r"[^A-Za-z0-9]", text):
        alphabet += 32
    entropy = len(text) * (math.log2(alphabet) if alphabet else 0)

    if text.lower() in COMMON_WEAK:
        flags.append("Appears in common password lists")
        score = min(score, 10)
    if re.search(r"(.)\1{2,}", text):
        flags.append("Contains a repeated character run")
        score -= 8
    if any(run in text.lower() for run in KEYBOARD_RUNS):
        flags.append("Contains a keyboard sequence")
        score -= 10
    if re.match(r"^[A-Z][a-z]+\d{1,4}!?$", text):
        flags.append("Classic capitalised-word-plus-digits pattern")
        score -= 12
    if len(text) < 8:
        flags.append("Shorter than 8 characters")

    score = max(0, min(100, score))
    if score >= 80:
        label = "excellent"
    elif score >= 60:
        label = "strong"
    elif score >= 40:
        label = "moderate"
    elif score >= 20:
        label = "weak"
    else:
        label = "very weak"

    # Offline crack time at 10 billion guesses/second (GPU attack).
    guesses = (2 ** entropy) / 2 if entropy else 1
    seconds = guesses / 1e10
    return {
        "score": score,
        "label": label,
        "length": len(text),
        "character_classes": classes,
        "entropy_bits": round(entropy, 1),
        "offline_crack_seconds": seconds,
        "crack_time_human": humanize_seconds(seconds),
        "flags": flags,
        "recommendation": (
            "Use a password manager and a unique password per site; prefer a long passphrase."
            if score < 60
            else "Good. Store it in a password manager and enable MFA."
        ),
    }


def humanize_seconds(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    units = (
        (60, "seconds", 1),
        (3600, "minutes", 60),
        (86400, "hours", 3600),
        (2592000, "days", 86400),
        (31536000, "months", 2592000),
        (31536000 * 100, "years", 31536000),
    )
    for limit, label, divisor in units:
        if seconds < limit:
            value = seconds / divisor
            return "{:.1f} {}".format(value, label if value >= 1.5 else label.rstrip("s"))
    years = seconds / 31536000
    if years > 1e6:
        return "more than a million years"
    return "{:,.0f} years".format(years)


# ---------------------------------------------------------------------------
# Hashing and integrity
HASH_ALGORITHMS = ("md5", "sha1", "sha256", "sha512", "blake2b")


def hash_text(value: str, algorithm: str = "sha256") -> str:
    algo = str(algorithm).lower()
    if algo not in HASH_ALGORITHMS:
        raise ValueError("unsupported algorithm {!r}".format(algorithm))
    digest = hashlib.new(algo)
    digest.update(str(value).encode("utf-8"))
    return digest.hexdigest()


def hash_file(path: Path, algorithm: str = "sha256", chunk_size: int = 65536) -> Dict[str, Any]:
    algo = str(algorithm).lower()
    if algo not in HASH_ALGORITHMS:
        raise ValueError("unsupported algorithm {!r}".format(algorithm))
    target = Path(path)
    digest = hashlib.new(algo)
    size = 0
    with target.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return {"path": str(target), "algorithm": algo, "digest": digest.hexdigest(), "bytes": size}


def compare_integrity(path: Path, expected: str, algorithm: str = "sha256") -> Dict[str, Any]:
    actual = hash_file(path, algorithm)
    match = hmac.compare_digest(actual["digest"].lower(), str(expected).strip().lower())
    return {
        "path": str(path),
        "algorithm": actual["algorithm"],
        "expected": str(expected).strip().lower(),
        "actual": actual["digest"],
        "match": match,
    }


# ---------------------------------------------------------------------------
# Encoding
_MAX_DECODE_BYTES = 1_000_000


def base64_encode(value: str) -> str:
    return base64.b64encode(str(value).encode("utf-8")).decode("ascii")


def base64_decode(value: str) -> str:
    text = str(value or "").strip()
    if len(text) > _MAX_DECODE_BYTES:
        raise ValueError("input too large to decode safely")
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.b64decode(padded, validate=False).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise ValueError("not valid base64/UTF-8: {}".format(exc))


def url_encode(value: str, safe: str = "") -> str:
    return quote(str(value), safe=safe)


def url_decode(value: str) -> str:
    return unquote(str(value))


def json_format(value: str, indent: int = 2) -> Tuple[Optional[str], Optional[str]]:
    """Return (pretty_json, error)."""
    try:
        data = json.loads(value)
    except ValueError as exc:
        return None, "invalid JSON: {}".format(exc)
    return json.dumps(data, indent=indent, ensure_ascii=False, sort_keys=True), None


# ---------------------------------------------------------------------------
# JWT
def inspect_jwt(token: str) -> Dict[str, Any]:
    """Structural inspection only - no signature verification, no secret guessing."""
    text = str(token or "").strip()
    parts = text.split(".")
    result: Dict[str, Any] = {
        "valid_structure": len(parts) == 3,
        "segments": len(parts),
        "header": None,
        "payload": None,
        "notes": [],
        "findings": [],
    }
    if len(parts) != 3:
        result["notes"].append("A JWT must have three dot-separated segments.")
        return result

    def decode(segment: str) -> Any:
        padded = segment + "=" * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))

    try:
        result["header"] = decode(parts[0])
    except Exception:
        result["notes"].append("Header segment is not valid base64url JSON.")
    try:
        result["payload"] = decode(parts[1])
    except Exception:
        result["notes"].append("Payload segment is not valid base64url JSON.")

    header = result["header"] or {}
    payload = result["payload"] or {}
    algorithm = str(header.get("alg", "")).lower()
    if algorithm == "none":
        result["findings"].append({
            "title": "alg=none - signature is not enforced",
            "severity": "critical",
            "detail": "A token declaring alg=none is accepted unsigned by broken validators.",
            "recommendation": "Reject alg=none server side and pin the expected algorithm.",
        })
    if algorithm.startswith("hs") and not header.get("kid"):
        result["findings"].append({
            "title": "HMAC token without a key id",
            "severity": "low",
            "detail": "Without kid, key rotation is harder and shared secrets are more likely.",
            "recommendation": "Use asymmetric signing (RS256/ES256) with a kid, or rotate HMAC secrets.",
        })
    if "exp" not in payload:
        result["findings"].append({
            "title": "No expiry claim",
            "severity": "medium",
            "detail": "A token without exp never expires, so a leak is permanent.",
            "recommendation": "Always set exp and keep it short; use refresh tokens for longevity.",
        })
    if "aud" not in payload:
        result["findings"].append({
            "title": "No audience claim",
            "severity": "low",
            "detail": "Without aud, a token issued for one service may be replayed at another.",
            "recommendation": "Set and verify aud on every service.",
        })
    if payload.get("exp"):
        import datetime

        try:
            expiry = datetime.datetime.fromtimestamp(
                int(payload["exp"]), datetime.timezone.utc
            )
            result["expires_at"] = expiry.isoformat()
            result["expired"] = expiry < datetime.datetime.now(datetime.timezone.utc)
        except (ValueError, OSError, TypeError):
            result["notes"].append("exp claim is not a valid timestamp.")
    return result


# ---------------------------------------------------------------------------
# Local log analysis
LOG_PATTERNS = {
    "failed_login": re.compile(r"(?i)(failed|invalid|denied).{0,24}(login|password|auth)"),
    "privilege_escalation": re.compile(r"(?i)\b(sudo|su)\b.{0,30}(failed|denied|incorrect)"),
    "port_scan": re.compile(r"(?i)(multiple|repeated).{0,20}(connection|refused)"),
    "malware_hint": re.compile(r"(?i)(reverse shell|base64 -d|/dev/tcp/|curl .{0,40}\| ?sh)"),
    "error_spike": re.compile(r"(?i)\b(critical|fatal|segfault|panic)\b"),
}


def analyze_log(path: Path, max_lines: int = 50_000, tail: int = 500) -> Report:
    target = Path(path)
    report = Report(module="defensive_security", target=str(target))
    report.limitations = [
        "Log analysis is pattern based and will miss novel attacks and produce some false positives.",
        "Only the file you point at is read; nothing is uploaded or transmitted.",
    ]
    if not target.is_file():
        report.add_finding("Input", "Log file not found", severity=RiskLevel.MEDIUM,
                          detail=str(target), recommendation="Pass an absolute path to an existing log file.")
        return report
    counters = {key: 0 for key in LOG_PATTERNS}
    examples: Dict[str, List[str]] = {key: [] for key in LOG_PATTERNS}
    lines_read = 0
    try:
        with target.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                lines_read += 1
                if lines_read > max_lines:
                    break
                for key, pattern in LOG_PATTERNS.items():
                    if pattern.search(line):
                        counters[key] += 1
                        if len(examples[key]) < 3:
                            examples[key].append(line.strip()[:180])
    except OSError as exc:
        report.add_finding("Input", "Log file unreadable", severity=RiskLevel.MEDIUM, detail=str(exc))
        return report

    report.add_section(
        "Log Summary",
        {"lines_scanned": min(lines_read, max_lines), "patterns": counters, "examples": examples},
    )
    labels = {
        "failed_login": ("Repeated failed logins", RiskLevel.MEDIUM,
                         "Enable rate limiting and MFA for the affected accounts."),
        "privilege_escalation": ("Failed privilege escalation attempts", RiskLevel.HIGH,
                                 "Review sudoers rules and restrict who can elevate."),
        "port_scan": ("Scanning-like connection patterns", RiskLevel.LOW,
                      "Rate limit the service and add an IDS/IPS signature."),
        "malware_hint": ("Possible malware or reverse-shell activity", RiskLevel.CRITICAL,
                         "Isolate the host and investigate the matching process immediately."),
        "error_spike": ("Critical/fatal application errors", RiskLevel.LOW,
                        "Investigate the underlying failures; attackers use them to hide activity."),
    }
    for key, count in counters.items():
        if not count:
            continue
        title, severity, recommendation = labels[key]
        if key == "failed_login" and count < 5:
            severity = RiskLevel.LOW
        report.add_finding(
            "Detections",
            "{} ({} matches)".format(title, count),
            severity=severity,
            detail="Examples: " + " | ".join(examples[key][:2]) if examples[key] else "",
            recommendation=recommendation,
            evidence={"count": count},
        )
    if not any(counters.values()):
        report.add_finding("Detections", "No suspicious patterns matched", severity=RiskLevel.INFO,
                          detail="None of the built-in patterns fired on this file.",
                          recommendation="Keep log rotation and centralised collection enabled.")
    report.risk_score = min(100, sum(20 if counters[key] else 0 for key in counters))
    return report


def file_metadata(path: Path) -> Dict[str, Any]:
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(str(target))
    stat = target.stat()
    import datetime

    return {
        "path": str(target),
        "name": target.name,
        "is_file": target.is_file(),
        "is_dir": target.is_dir(),
        "size_bytes": stat.st_size,
        "permissions": oct(stat.st_mode)[-4:],
        "modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "suffix": target.suffix,
    }


CHECKLIST = (
    ("Disk encryption enabled", "Protects data if the device is lost or stolen."),
    ("Screen lock with a 6+ digit PIN or biometrics", "Stops casual physical access."),
    ("OS and apps fully updated", "Closes publicly known vulnerabilities."),
    ("Play Protect / app scanning enabled", "Blocks known malicious APKs."),
    ("No apps with accessibility access you do not recognise", "Accessibility access is abused to read screens and tap for you."),
    ("2FA enabled on the accounts holding your data", "A stolen password alone then stops being enough."),
    ("Unique password per account in a manager", "Limits the blast radius of any single breach."),
    ("Termux packages installed only from the official repo", "Third-party repos can ship trojanised binaries."),
    ("No unknown sideloaded APKs", "Sideloaded apps bypass store scanning."),
    ("Backups tested, not just configured", "A backup you have never restored is a guess."),
)


def checklist() -> List[Dict[str, Any]]:
    return [{"item": item, "why": why, "done": False} for item, why in CHECKLIST]


def header_check(headers: Dict[str, str]) -> Report:
    report = Report(module="defensive_security", target="http security headers")
    findings, data = analyze_security_headers(headers or {})
    section = report.add_section("Security Headers", data)
    for item in findings:
        section.add(**item)
    if not findings:
        section.add(title="All checked headers present", severity=RiskLevel.INFO,
                    detail="No missing header was detected in the supplied set.",
                    recommendation="Keep the policy under review as the site evolves.")
    return report
