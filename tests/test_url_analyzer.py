"""Tests for URL parsing, phishing heuristics and safety guards."""
from __future__ import annotations

import unittest

from core.security import UnsafeTargetError, assert_public_target, is_private_ip
from modules import url_analyzer as ua


class ParsingTests(unittest.TestCase):
    def test_normalize_adds_scheme(self) -> None:
        self.assertEqual(ua.normalize_url("example.com"), "http://example.com")

    def test_normalize_strips_whitespace(self) -> None:
        self.assertEqual(ua.normalize_url("  https://a.test  "), "https://a.test")

    def test_empty_url_rejected(self) -> None:
        with self.assertRaises(ua.URLAnalysisError):
            ua.normalize_url("   ")

    def test_ftp_scheme_rejected(self) -> None:
        with self.assertRaises(ua.URLAnalysisError):
            ua.parse_url("ftp://example.com/file")

    def test_javascript_scheme_rejected(self) -> None:
        with self.assertRaises(ua.URLAnalysisError):
            ua.parse_url("javascript:alert(1)")

    def test_missing_hostname_rejected(self) -> None:
        with self.assertRaises(ua.URLAnalysisError):
            ua.parse_url("http:///path")

    def test_port_range_enforced(self) -> None:
        with self.assertRaises(ua.URLAnalysisError):
            ua.parse_url("http://example.com:99999/")

    def test_components_split(self) -> None:
        parsed = ua.parse_url("https://user:pw@example.com:8443/a/b?x=1&y=2#frag")
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.hostname, "example.com")
        self.assertEqual(parsed.port, 8443)
        self.assertEqual(parsed.path, "/a/b")
        self.assertEqual(parsed.query_params, {"x": "1", "y": "2"})
        self.assertEqual(parsed.fragment, "frag")
        self.assertTrue(parsed.username)

    def test_effective_port_defaults(self) -> None:
        self.assertEqual(ua.parse_url("https://a.test").effective_port, 443)
        self.assertEqual(ua.parse_url("http://a.test").effective_port, 80)

    def test_origin_omits_default_port(self) -> None:
        self.assertEqual(ua.parse_url("https://a.test").origin, "https://a.test")
        self.assertEqual(ua.parse_url("https://a.test:8443").origin, "https://a.test:8443")

    def test_to_dict_hides_credentials(self) -> None:
        payload = ua.parse_url("https://user:secret@a.test/").to_dict()
        self.assertTrue(payload["has_userinfo"])
        self.assertNotIn("secret", str(payload))


class RegistrableDomainTests(unittest.TestCase):
    def test_simple(self) -> None:
        self.assertEqual(ua.registrable_domain("www.example.com"), "example.com")

    def test_two_level_suffix(self) -> None:
        self.assertEqual(ua.registrable_domain("shop.example.co.uk"), "example.co.uk")

    def test_short_returns_itself(self) -> None:
        self.assertEqual(ua.registrable_domain("example"), "example")

    def test_ip_returned_unchanged(self) -> None:
        self.assertEqual(ua.registrable_domain("192.0.2.10"), "192.0.2.10")


class PrivateAddressTests(unittest.TestCase):
    def test_loopback(self) -> None:
        self.assertTrue(is_private_ip("127.0.0.1"))

    def test_rfc1918(self) -> None:
        self.assertTrue(is_private_ip("10.1.2.3"))
        self.assertTrue(is_private_ip("172.16.0.5"))
        self.assertTrue(is_private_ip("192.168.1.1"))

    def test_link_local(self) -> None:
        self.assertTrue(is_private_ip("169.254.169.254"))

    def test_ipv6_loopback(self) -> None:
        self.assertTrue(is_private_ip("::1"))

    def test_public(self) -> None:
        self.assertFalse(is_private_ip("1.1.1.1"))
        self.assertFalse(is_private_ip("2606:4700:4700::1111"))

    def test_hostname_is_not_private(self) -> None:
        # A name must be resolved before the guard applies.
        self.assertFalse(is_private_ip("example.com"))

    def test_guard_blocks_loopback_literal(self) -> None:
        with self.assertRaises(UnsafeTargetError):
            assert_public_target("127.0.0.1")

    def test_guard_blocks_private_literal(self) -> None:
        with self.assertRaises(UnsafeTargetError):
            assert_public_target("192.168.0.10")

    def test_guard_blocks_metadata_address(self) -> None:
        with self.assertRaises(UnsafeTargetError):
            assert_public_target("169.254.169.254")


class StructureHeuristicTests(unittest.TestCase):
    def _titles(self, url: str):
        findings, weight = ua.analyze_structure(ua.parse_url(url))
        return [item["title"] for item in findings], weight

    def test_clean_url_low_weight(self) -> None:
        titles, weight = self._titles("https://example.com/about")
        self.assertEqual(weight, 0)
        self.assertFalse(any("Brand name" in title for title in titles))

    def test_embedded_brand_flagged(self) -> None:
        titles, weight = self._titles("http://paypal-secure-verify.tk/login/account")
        self.assertTrue(any("Brand name" in title for title in titles))
        self.assertGreaterEqual(weight, 40)

    def test_suspicious_tld(self) -> None:
        titles, _ = self._titles("http://cheap-deal.tk/")
        self.assertTrue(any(".tk" in title for title in titles))

    def test_typosquat_detected(self) -> None:
        titles, weight = self._titles("http://paypa1.com/login")
        self.assertGreater(weight, 0)
        self.assertTrue(titles)

    def test_punycode_flagged(self) -> None:
        titles, _ = self._titles("http://xn--pypal-4ve.com/")
        self.assertTrue(any("Punycode" in title for title in titles))

    def test_shortener_flagged(self) -> None:
        titles, _ = self._titles("https://bit.ly/abc123")
        self.assertTrue(any("shortener" in title for title in titles))

    def test_userinfo_flagged_high(self) -> None:
        findings, weight = ua.analyze_structure(ua.parse_url("https://a.test@evil.test/"))
        severities = {item["severity"] for item in findings}
        self.assertIn("high", severities)
        self.assertGreater(weight, 0)

    def test_raw_ip_flagged(self) -> None:
        titles, _ = self._titles("http://203.0.113.7/admin")
        self.assertTrue(any("raw IP" in title for title in titles))

    def test_deep_subdomain_flagged(self) -> None:
        titles, _ = self._titles("https://a.b.c.d.evil.test/")
        self.assertTrue(any("subdomain" in title.lower() for title in titles))

    def test_weight_capped(self) -> None:
        _, weight = ua.analyze_structure(
            ua.parse_url("http://user:pw@paypal-verify-login-account-secure-update.tk/a?b=1&c=2&d=3")
        )
        self.assertLessEqual(weight, 60)


class QuickVerdictTests(unittest.TestCase):
    def test_valid_url_returns_fields(self) -> None:
        verdict = ua.quick_verdict("https://example.com")
        self.assertEqual(verdict["risk"], "info")
        self.assertEqual(verdict["score"], 0)
        self.assertIn("registered_domain", verdict)

    def test_invalid_url_reports_error(self) -> None:
        verdict = ua.quick_verdict("not a url at all")
        self.assertIn(verdict["risk"], ("invalid", "info", "low"))

    def test_phishing_url_scores_high(self) -> None:
        verdict = ua.quick_verdict("http://paypal-secure-verify.tk/login/account/update")
        self.assertGreaterEqual(verdict["score"], 50)
        self.assertIn(verdict["risk"], ("medium", "high", "critical"))


class AnalyzeSafetyTests(unittest.TestCase):
    """No network is contacted here: these paths return before any request."""

    def test_invalid_url_gives_report(self) -> None:
        report = ua.analyze("not-a-url")
        self.assertEqual(report.module, "url_analyzer")
        self.assertTrue(report.findings)

    def test_ssrf_guard_blocks_loopback(self) -> None:
        report = ua.analyze("http://127.0.0.1:8080/admin", timeout=1)
        titles = [item.title for item in report.findings]
        self.assertTrue(any("SSRF" in title or "blocked" in title.lower() for title in titles))

    def test_ssrf_guard_blocks_private_range(self) -> None:
        report = ua.analyze("http://10.0.0.5/", timeout=1)
        self.assertTrue(report.findings)

    def test_report_has_limitations(self) -> None:
        report = ua.analyze("https://example.com", timeout=1, follow=False)
        self.assertTrue(report.limitations)

    def test_analyze_never_raises_on_garbage(self) -> None:
        for payload in ("", "   ", "http://", "://", "\\x00"):
            report = ua.analyze(payload, timeout=1)
            self.assertIsNotNone(report)


class SecurityHeaderTests(unittest.TestCase):
    def test_missing_headers_reported(self) -> None:
        findings, data = ua.analyze_security_headers({})
        self.assertTrue(findings)
        self.assertEqual(len(data["missing"]), 6)

    def test_all_present_no_findings(self) -> None:
        headers = {
            "strict-transport-security": "max-age=63072000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
        }
        findings, data = ua.analyze_security_headers(headers)
        self.assertEqual(data["missing"], [])
        self.assertFalse(any("Missing" in item["title"] for item in findings))

    def test_server_banner_flagged(self) -> None:
        findings, _ = ua.analyze_security_headers({"Server": "nginx/1.18"})
        self.assertTrue(any("Server banner" in item["title"] for item in findings))

    def test_header_lookup_is_case_insensitive(self) -> None:
        _, data = ua.analyze_security_headers({"STRICT-TRANSPORT-SECURITY": "max-age=1"})
        self.assertIn("HSTS", data["present"])


class RedirectSafetyTests(unittest.TestCase):
    def test_redirect_onto_private_host_is_blocked(self) -> None:
        # follow_redirects is exercised against a real request only when the
        # first hop succeeds; here we assert parse+guard behaviour directly.
        parsed = ua.parse_url("http://169.254.169.254/latest/meta-data/")
        with self.assertRaises(UnsafeTargetError):
            assert_public_target(parsed.hostname, 80)


if __name__ == "__main__":
    unittest.main()
