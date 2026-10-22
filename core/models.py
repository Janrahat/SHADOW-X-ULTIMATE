"""Shared data models: risk levels, findings, sections and reports."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

TOOL_NAME = "SHADOW-X ULTIMATE"
TOOL_VERSION = "1.0.0"


class RiskLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> int:
        return {
            RiskLevel.INFO: 0,
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
        }[self]

    @classmethod
    def from_score(cls, score: float) -> "RiskLevel":
        try:
            value = float(score)
        except (TypeError, ValueError):
            return cls.INFO
        if value >= 80:
            return cls.CRITICAL
        if value >= 60:
            return cls.HIGH
        if value >= 35:
            return cls.MEDIUM
        if value > 0:
            return cls.LOW
        return cls.INFO

    @classmethod
    def parse(cls, value: Any) -> "RiskLevel":
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().lower())
        except Exception:
            return cls.INFO

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


@dataclass
class Finding:
    """A single observation with evidence and a defensive recommendation."""

    title: str
    severity: RiskLevel = RiskLevel.INFO
    detail: str = ""
    recommendation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    category: str = "general"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "category": self.category,
        }


@dataclass
class Section:
    """A named group of findings plus the raw data behind them."""

    title: str
    findings: List[Finding] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)

    def add(
        self,
        title: str,
        severity: RiskLevel = RiskLevel.INFO,
        detail: str = "",
        recommendation: str = "",
        evidence: Optional[Dict[str, Any]] = None,
        category: str = "general",
    ) -> Finding:
        finding = Finding(
            title=title,
            severity=RiskLevel.parse(severity),
            detail=detail,
            recommendation=recommendation,
            evidence=evidence or {},
            category=category,
        )
        self.findings.append(finding)
        return finding

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "findings": [finding.to_dict() for finding in self.findings],
            "data": self.data,
        }


@dataclass
class Report:
    """The single object every module hands to the reporting engine."""

    module: str
    target: str = ""
    report_id: str = ""
    created_at: str = ""
    tool: str = TOOL_NAME
    version: str = TOOL_VERSION
    sections: List[Section] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)
    risk_score: float = 0.0

    def __post_init__(self) -> None:
        if not self.report_id:
            self.report_id = new_report_id()
        if not self.created_at:
            self.created_at = utc_now()

    # -- construction helpers ------------------------------------------------
    def add_section(self, title: str, data: Optional[Dict[str, Any]] = None) -> Section:
        for section in self.sections:
            if section.title == title:
                if data:
                    section.data.update(data)
                return section
        section = Section(title=title, data=data or {})
        self.sections.append(section)
        return section

    def add_finding(
        self,
        section_title: str,
        title: str,
        severity: RiskLevel = RiskLevel.INFO,
        detail: str = "",
        recommendation: str = "",
        evidence: Optional[Dict[str, Any]] = None,
        category: str = "general",
    ) -> Finding:
        section = self.add_section(section_title)
        return section.add(
            title=title,
            severity=severity,
            detail=detail,
            recommendation=recommendation,
            evidence=evidence,
            category=category,
        )

    # -- derived values ------------------------------------------------------
    @property
    def findings(self) -> List[Finding]:
        return [finding for section in self.sections for finding in section.findings]

    def count_by_severity(self) -> Dict[str, int]:
        counts = {level.value: 0 for level in RiskLevel}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    @property
    def max_severity(self) -> RiskLevel:
        findings = self.findings
        if not findings:
            return RiskLevel.INFO
        return max(findings, key=lambda item: item.severity.score).severity

    @property
    def overall_risk(self) -> RiskLevel:
        if self.risk_score:
            return RiskLevel.from_score(self.risk_score)
        return self.max_severity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "tool": self.tool,
            "version": self.version,
            "module": self.module,
            "target": self.target,
            "created_at": self.created_at,
            "risk_score": self.risk_score,
            "overall_risk": self.overall_risk.value,
            "counts": self.count_by_severity(),
            "sections": [section.to_dict() for section in self.sections],
            "metadata": self.metadata,
            "limitations": self.limitations,
        }


@dataclass
class PlatformStatus:
    """Small view-model used by the dashboard."""

    platform: str = ""
    python: str = ""
    network: bool = False
    disk_free: str = "n/a"
    memory: str = "n/a"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def new_report_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return "SX-{}-{}".format(stamp, uuid.uuid4().hex[:6].upper())


def parse_timestamp(value: str) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except Exception:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
