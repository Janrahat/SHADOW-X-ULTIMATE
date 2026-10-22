"""Transparent, consent-based shareable report links.

DESIGN BOUNDARY: this module produces links to *your own* reports and nothing
else. It has no ability to create deceptive tracking links, and it never
collects a visitor's IP, location, device, camera, microphone, files or
credentials. Access logging is limited to a timestamp plus an optional
self-declared note and can be turned off entirely.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.security import safe_filename, sha256_text

PRIVACY_NOTICE = (
    "This link points to a security report you chose to share. It does not "
    "track the recipient: no IP address, location, device fingerprint, camera, "
    "microphone, contact list or file is collected. Anyone holding the URL and "
    "the password (when set) can read the report until it expires or is revoked."
)

LINK_TTL_PRESETS = {
    "15m": 900,
    "1h": 3600,
    "24h": 86400,
    "7d": 604800,
    "30d": 2592000,
}


class LinkError(ValueError):
    """Raised for invalid TTL, password or missing report file."""


@dataclass
class ShareLink:
    link_id: str
    report_id: str
    report_name: str
    created_at: float
    expires_at: Optional[float] = None
    password_hash: Optional[str] = None
    password_salt: Optional[str] = None
    revoked: bool = False
    access_log: List[Dict[str, Any]] = field(default_factory=list)
    views: int = 0
    base_url: str = ""

    @property
    def url(self) -> str:
        base = (self.base_url or "").rstrip("/")
        if base:
            return "{}/reports/{}.html".format(base, self.report_id)
        return "local://reports/{}.html".format(self.report_id)

    @property
    def is_expired(self) -> bool:
        return bool(self.expires_at and time.time() >= self.expires_at)

    @property
    def is_active(self) -> bool:
        return not self.revoked and not self.is_expired

    def remaining_seconds(self) -> Optional[int]:
        if not self.expires_at:
            return None
        return max(0, int(self.expires_at - time.time()))

    def to_dict(self, include_log: bool = True) -> Dict[str, Any]:
        payload = {
            "link_id": self.link_id,
            "report_id": self.report_id,
            "report_name": self.report_name,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "protected": bool(self.password_hash),
            "revoked": self.revoked,
            "views": self.views,
            "url": self.url,
            "active": self.is_active,
            "remaining_seconds": self.remaining_seconds(),
        }
        if include_log:
            payload["access_log"] = self.access_log
        return payload


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000
    ).hex()


def parse_ttl(value: Any) -> Optional[int]:
    """Accept '15m', '1h', '7d', plain seconds, or 'never'."""
    if value in (None, "", "never", "none"):
        return None
    text = str(value).strip().lower()
    if text in LINK_TTL_PRESETS:
        return LINK_TTL_PRESETS[text]
    if text.isdigit():
        seconds = int(text)
        if seconds <= 0:
            raise LinkError("TTL must be positive")
        return seconds
    # Generic <number><unit>, e.g. 1d, 3h, 45m - any value the user asks for.
    match = re.match(r"^(\d+)\s*([mhd])$", text)
    if match:
        amount = int(match.group(1))
        unit = match.group(2)
        multiplier = {"m": 60, "h": 3600, "d": 86400}[unit]
        if amount <= 0:
            raise LinkError("TTL must be positive")
        return amount * multiplier
    raise LinkError(
        "unrecognised TTL {!r} (use e.g. 15m, 1h, 24h, 7d, 30d, 1d, or seconds)".format(value)
    )


class LinkStore:
    """File-backed store for share links. JSON on disk, no database needed."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._links: Dict[str, ShareLink] = {}
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        for item in raw.get("links", []):
            try:
                link = ShareLink(**item)
                self._links[link.link_id] = link
            except TypeError:
                continue

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"links": [asdict(link) for link in self._links.values()]}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    # -- mutations -----------------------------------------------------------
    def create(
        self,
        report_id: str,
        report_name: str = "",
        ttl: Any = "24h",
        password: Optional[str] = None,
        base_url: str = "",
    ) -> ShareLink:
        seconds = parse_ttl(ttl)
        now = time.time()
        link = ShareLink(
            link_id=secrets.token_hex(8),
            report_id=safe_filename(report_id, fallback="report"),
            report_name=report_name or report_id,
            created_at=now,
            expires_at=(now + seconds) if seconds else None,
            base_url=base_url,
        )
        if password:
            if len(str(password)) < 4:
                raise LinkError("password must be at least 4 characters")
            salt = secrets.token_hex(8)
            link.password_salt = salt
            link.password_hash = _hash_password(str(password), salt)
        self._links[link.link_id] = link
        self.save()
        return link

    def get(self, link_id: str) -> Optional[ShareLink]:
        return self._links.get(link_id)

    def revoke(self, link_id: str) -> bool:
        link = self._links.get(link_id)
        if not link:
            return False
        link.revoked = True
        self.save()
        return True

    def verify_password(self, link_id: str, password: str) -> bool:
        link = self._links.get(link_id)
        if not link or not link.is_active:
            return False
        if not link.password_hash or not link.password_salt:
            return True
        candidate = _hash_password(str(password), link.password_salt)
        return hmac.compare_digest(candidate, link.password_hash)

    def record_access(
        self, link_id: str, note: str = "", store_logs: bool = True
    ) -> Optional[Dict[str, Any]]:
        """Log a view. Deliberately records no address, agent or fingerprint."""
        link = self._links.get(link_id)
        if not link:
            return None
        link.views += 1
        entry = None
        if store_logs:
            entry = {
                "at": int(time.time()),
                "note": (note or "")[:120],
                "collected": "timestamp and self-declared note only",
            }
            link.access_log.append(entry)
            del link.access_log[:-200]
        self.save()
        return entry

    def prune(self, retention_days: int = 30) -> int:
        cutoff = time.time() - max(0, retention_days) * 86400
        removed = 0
        for link_id in list(self._links):
            link = self._links[link_id]
            if link.expires_at and link.expires_at < cutoff:
                del self._links[link_id]
                removed += 1
                continue
            if link.access_log:
                link.access_log = [item for item in link.access_log if item.get("at", 0) >= cutoff]
        if removed:
            self.save()
        return removed

    def list_links(self, include_inactive: bool = False) -> List[ShareLink]:
        links = list(self._links.values())
        if not include_inactive:
            links = [link for link in links if link.is_active]
        return sorted(links, key=lambda item: item.created_at, reverse=True)


def build_credentials_gate(report_id: str, password_required: bool) -> str:
    """Minimal, honest HTML gate for a password-protected report."""
    label = (
        '<label>Password <input type="password" name="password" required></label>'
        if password_required
        else "<p>No password is set for this link.</p>"
    )
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>Protected report</title></head><body>"
        "<h1>Protected security report</h1>"
        "<p>{}</p>"
        "<form method='post'>{}<button type='submit'>Open report</button></form>"
        "<p><small>Report reference: {}</small></p>"
        "</body></html>".format(PRIVACY_NOTICE, label, report_id)
    )


def summarize_store(store: LinkStore) -> Dict[str, Any]:
    links = store.list_links(include_inactive=True)
    return {
        "total": len(links),
        "active": sum(1 for link in links if link.is_active),
        "protected": sum(1 for link in links if link.password_hash),
        "views": sum(link.views for link in links),
        "privacy": "no visitor IP, geolocation or device data is ever recorded",
    }
