"""Batch processing for URL lists: offline scoring plus optional deep checks."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.models import Report, RiskLevel
from modules import url_analyzer

MAX_BATCH_ITEMS = 500


def load_targets(path: Path, limit: int = MAX_BATCH_ITEMS) -> List[str]:
    """Read one target per line, skipping blanks and # comments."""
    target = Path(path)
    if not target.is_file():
        raise FileNotFoundError(str(target))
    items: List[str] = []
    with target.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            items.append(text)
            if len(items) >= limit:
                break
    return items


def analyze_urls(
    targets: List[str], deep: bool = False, timeout: float = 6.0
) -> Report:
    """Score a list of URLs. Offline by default so a 500-line list is instant."""
    report = Report(module="url_batch", target="{} target(s)".format(len(targets)))
    report.limitations = [
        "Batch mode runs the structural analysis only unless deep checks are requested.",
        "Deep mode performs one HTTP request per target and honours the configured timeout.",
    ]
    rows: List[Dict[str, Any]] = []
    for item in targets[:MAX_BATCH_ITEMS]:
        if deep:
            deep_report = url_analyzer.analyze(item, timeout=timeout, follow=False)
            rows.append(
                {
                    "url": deep_report.target or item,
                    "score": deep_report.risk_score,
                    "risk": deep_report.overall_risk.value,
                    "findings": len(deep_report.findings),
                }
            )
        else:
            rows.append(url_analyzer.quick_verdict(item))
    rows.sort(key=lambda row: row.get("score", 0), reverse=True)
    report.add_section("Batch Results", {"count": len(rows), "deep": deep, "rows": rows})

    high_risk = [row for row in rows if row.get("score", 0) >= 60]
    if high_risk:
        report.add_finding(
            "Summary",
            "{} target(s) scored high risk".format(len(high_risk)),
            severity=RiskLevel.HIGH,
            detail=", ".join(row["url"][:60] for row in high_risk[:5]),
            recommendation="Investigate the listed targets before anyone clicks them.",
        )
    else:
        report.add_finding(
            "Summary",
            "No high-risk targets",
            severity=RiskLevel.INFO,
            detail="Every target stayed below the high-risk threshold.",
            recommendation="Structural scoring cannot prove a link is safe.",
        )
    report.risk_score = max((row.get("score", 0) for row in rows), default=0)
    return report
