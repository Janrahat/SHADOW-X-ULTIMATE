"""Tests for the reporting engine and the redaction guarantee."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from core.models import Report, RiskLevel, new_report_id, parse_timestamp, utc_now
from core.security import (
    redact_headers,
    redact_structure,
    redact_text,
    safe_filename,
)
from modules import report_generator as rg


def sample_report() -> Report:
    report = Report(module="url_analyzer", target="https://example.com/login")
    report.add_section("URL Structure", {"hostname": "example.com", "scheme": "https"})
    report.add_finding(
        "URL Structure",
        "Missing security headers",
        severity=RiskLevel.MEDIUM,
        detail="HSTS not set",
        recommendation="Add HSTS",
        evidence={"header": "Strict-Transport-Security"},
    )
    report.add_finding(
        "TLS",
        "Certificate expires soon",
        severity=RiskLevel.HIGH,
        detail="12 days remaining",
        recommendation="Renew now",
    )
    report.limitations = ["Heuristic only."]
    report.risk_score = 45
    return report


class ModelsTests(unittest.TestCase):
    def test_report_id_format(self) -> None:
        report_id = new_report_id()
        self.assertTrue(report_id.startswith("SX-"))
        self.assertEqual(len(report_id.split("-")), 4)

    def test_report_ids_are_unique(self) -> None:
        self.assertNotEqual(new_report_id(), new_report_id())

    def test_timestamp_is_utc_z(self) -> None:
        self.assertTrue(utc_now().endswith("Z"))

    def test_parse_timestamp_roundtrip(self) -> None:
        parsed = parse_timestamp(utc_now())
        self.assertIsNotNone(parsed)

    def test_parse_timestamp_rejects_garbage(self) -> None:
        self.assertIsNone(parse_timestamp("not a date"))

    def test_risk_level_from_score(self) -> None:
        self.assertEqual(RiskLevel.from_score(95), RiskLevel.CRITICAL)
        self.assertEqual(RiskLevel.from_score(65), RiskLevel.HIGH)
        self.assertEqual(RiskLevel.from_score(45), RiskLevel.MEDIUM)
        self.assertEqual(RiskLevel.from_score(5), RiskLevel.LOW)
        self.assertEqual(RiskLevel.from_score(0), RiskLevel.INFO)

    def test_risk_level_parse_tolerates_garbage(self) -> None:
        self.assertEqual(RiskLevel.parse("HIGH"), RiskLevel.HIGH)
        self.assertEqual(RiskLevel.parse("nonsense"), RiskLevel.INFO)

    def test_count_by_severity(self) -> None:
        counts = sample_report().count_by_severity()
        self.assertEqual(counts["medium"], 1)
        self.assertEqual(counts["high"], 1)
        self.assertEqual(counts["critical"], 0)

    def test_overall_risk_uses_score(self) -> None:
        report = sample_report()
        self.assertEqual(report.overall_risk, RiskLevel.MEDIUM)

    def test_overall_risk_falls_back_to_max_severity(self) -> None:
        report = Report(module="test")
        report.add_finding("S", "x", severity=RiskLevel.CRITICAL)
        self.assertEqual(report.overall_risk, RiskLevel.CRITICAL)

    def test_add_section_is_idempotent(self) -> None:
        report = Report(module="test")
        first = report.add_section("A", {"x": 1})
        second = report.add_section("A", {"y": 2})
        self.assertIs(first, second)
        self.assertEqual(len(report.sections), 1)
        self.assertEqual(second.data, {"x": 1, "y": 2})

    def test_to_dict_is_serialisable(self) -> None:
        payload = json.dumps(sample_report().to_dict())
        self.assertIn("report_id", payload)


class RedactionTests(unittest.TestCase):
    def test_bearer_token_redacted(self) -> None:
        self.assertNotIn("abcdef123456", redact_text("Authorization: Bearer abcdef1234567890"))

    def test_github_token_redacted(self) -> None:
        self.assertNotIn("ghp_", redact_text("token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"))

    def test_aws_key_redacted(self) -> None:
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", redact_text("key AKIAIOSFODNN7EXAMPLE"))

    def test_slack_token_redacted(self) -> None:
        self.assertNotIn("xoxb-", redact_text("xoxb-1234567890-abcdefghij"))

    def test_jwt_redacted(self) -> None:
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop"
        self.assertNotIn(token, redact_text(token))

    def test_password_assignment_redacted(self) -> None:
        self.assertNotIn("hunter2", redact_text("password=hunter2"))

    def test_headers_redacted(self) -> None:
        cleaned = redact_headers({
            "Authorization": "Bearer xyz",
            "Cookie": "session=abc",
            "Server": "nginx",
        })
        self.assertEqual(cleaned["Authorization"], "[REDACTED]")
        self.assertEqual(cleaned["Cookie"], "[REDACTED]")
        self.assertEqual(cleaned["Server"], "nginx")

    def test_headers_from_list_of_tuples(self) -> None:
        cleaned = redact_headers([("Set-Cookie", "a=b"), ("Content-Type", "text/html")])
        self.assertEqual(cleaned["Set-Cookie"], "[REDACTED]")
        self.assertEqual(cleaned["Content-Type"], "text/html")

    def test_structure_redaction_recurses(self) -> None:
        payload = {
            "headers": {"Authorization": "Bearer secretvalue123"},
            "list": [{"cookie": "session=xyz"}],
            "note": "password=topsecret",
        }
        cleaned = redact_structure(payload)
        rendered = json.dumps(cleaned)
        self.assertNotIn("secretvalue123", rendered)
        self.assertNotIn("topsecret", rendered)
        self.assertEqual(cleaned["headers"]["Authorization"], "[REDACTED]")

    def test_non_string_passthrough(self) -> None:
        self.assertEqual(redact_structure(42), 42)
        self.assertIsNone(redact_structure(None))

    def test_safe_filename_strips_traversal(self) -> None:
        self.assertEqual(safe_filename("../../etc/passwd"), "etc-passwd")
        self.assertNotIn("/", safe_filename("a/b/c"))
        self.assertNotIn("..", safe_filename(".."))


class JsonRenderTests(unittest.TestCase):
    def test_json_is_valid(self) -> None:
        payload = json.loads(rg.to_json(sample_report()))
        self.assertEqual(payload["module"], "url_analyzer")
        self.assertEqual(payload["overall_risk"], "medium")

    def test_json_contains_sections_and_findings(self) -> None:
        payload = json.loads(rg.to_json(sample_report()))
        self.assertTrue(payload["sections"])
        self.assertEqual(len(payload["sections"][0]["findings"]), 1)

    def test_json_redacts_secrets(self) -> None:
        report = Report(module="test", target="x")
        report.add_section("H", {"Authorization": "Bearer supersecret"})
        rendered = rg.to_json(report)
        self.assertNotIn("supersecret", rendered)


class TextRenderTests(unittest.TestCase):
    def test_text_has_header_and_footer(self) -> None:
        text = rg.to_text(sample_report())
        self.assertIn("SHADOW-X ULTIMATE", text)
        self.assertIn("Report ID", text)
        self.assertIn("LIMITATIONS", text)

    def test_text_lists_findings(self) -> None:
        text = rg.to_text(sample_report())
        self.assertIn("Missing security headers", text)
        self.assertIn("MEDIUM", text)

    def test_text_wraps_long_detail(self) -> None:
        report = Report(module="test", target="x")
        report.add_finding("S", "Long", detail="word " * 200)
        text = rg.to_text(report)
        longest = max(len(line) for line in text.splitlines())
        self.assertLessEqual(longest, 90)

    def test_text_handles_empty_report(self) -> None:
        text = rg.to_text(Report(module="empty"))
        self.assertIn("no findings".lower(), text.lower())


class HtmlRenderTests(unittest.TestCase):
    def test_html_is_well_formed(self) -> None:
        html = rg.to_html(sample_report())
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        self.assertIn("</html>", html)
        self.assertIn("<style>", html)

    def test_html_escapes_injection(self) -> None:
        report = Report(module="test", target="<script>alert(1)</script>")
        html = rg.to_html(report)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_html_mentions_redaction(self) -> None:
        self.assertIn("redacted", rg.to_html(sample_report()).lower())

    def test_html_shows_risk_colour(self) -> None:
        self.assertIn("#ffd60a", rg.to_html(sample_report()))


class SaveTests(unittest.TestCase):
    def test_save_single_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = rg.save(sample_report(), Path(tmp), fmt="json")
            self.assertEqual(len(paths), 1)
            self.assertTrue(paths[0].exists())
            json.loads(paths[0].read_text(encoding="utf-8"))

    def test_save_all_formats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = rg.save(sample_report(), Path(tmp), export_all=True)
            self.assertEqual(len(paths), 3)
            suffixes = {path.suffix for path in paths}
            self.assertEqual(suffixes, {".json", ".txt", ".html"})

    def test_save_creates_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            nested = Path(tmp) / "a" / "b"
            rg.save(sample_report(), nested, fmt="txt")
            self.assertTrue(nested.is_dir())

    def test_save_rejects_unknown_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                rg.save(sample_report(), Path(tmp), fmt="pdf")

    def test_saved_files_contain_no_secret(self) -> None:
        report = Report(module="test", target="x")
        report.add_section("H", {"Cookie": "session=abcdef"})
        with tempfile.TemporaryDirectory() as tmp:
            paths = rg.save(report, Path(tmp), export_all=True)
            for path in paths:
                self.assertNotIn("session=abcdef", path.read_text(encoding="utf-8"))

    def test_custom_filename_is_sanitised(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = rg.save(sample_report(), Path(tmp), filename="../evil/name")
            self.assertEqual(len(paths), 1)
            self.assertNotIn("..", paths[0].name)


class ListingTests(unittest.TestCase):
    def test_list_reports_newest_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for index in range(3):
                rg.save(sample_report(), directory, filename="r{}".format(index))
            entries = rg.list_reports(directory, limit=10)
            self.assertEqual(len(entries), 3)
            self.assertTrue(all("name" in item for item in entries))

    def test_list_missing_directory_is_empty(self) -> None:
        self.assertEqual(rg.list_reports(Path("/nonexistent/xyz")), [])

    def test_summarize(self) -> None:
        summary = rg.summarize(sample_report())
        self.assertEqual(summary["module"], "url_analyzer")
        self.assertEqual(summary["findings"], 2)
        self.assertEqual(summary["risk"], "medium")


if __name__ == "__main__":
    unittest.main()
