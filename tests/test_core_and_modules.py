"""Tests for config, DNS wire format, defensive tools, links and batch mode."""
from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

from core import config as cfgmod
from core import net_dns
from core.security import RateLimiter, RateLimitExceeded
from modules import batch, defensive_security as ds, link_generator as lg


class ConfigTests(unittest.TestCase):
    def test_defaults_are_complete(self) -> None:
        defaults = cfgmod.defaults()
        for key in ("theme", "timeout", "max_redirects", "report_dir", "log_level"):
            self.assertIn(key, defaults)

    def test_defaults_are_a_copy(self) -> None:
        first = cfgmod.defaults()
        first["theme"] = "minimal"
        self.assertNotEqual(cfgmod.defaults()["theme"], "minimal")

    def test_validate_accepts_defaults(self) -> None:
        ok, errors = cfgmod.validate(cfgmod.defaults())
        self.assertTrue(ok, errors)

    def test_validate_rejects_bad_theme(self) -> None:
        bad = cfgmod.defaults()
        bad["theme"] = "neon-vomit"
        ok, errors = cfgmod.validate(bad)
        self.assertFalse(ok)
        self.assertTrue(any("theme" in item for item in errors))

    def test_validate_rejects_timeout_out_of_range(self) -> None:
        bad = cfgmod.defaults()
        bad["timeout"] = 500
        ok, errors = cfgmod.validate(bad)
        self.assertFalse(ok)

    def test_coerce_bool_variants(self) -> None:
        for value in ("true", "YES", "1", "on", True):
            self.assertTrue(cfgmod.coerce("color", value))
        for value in ("false", "no", "0", "off", False):
            self.assertFalse(cfgmod.coerce("color", value))

    def test_coerce_bool_rejects_garbage(self) -> None:
        with self.assertRaises(cfgmod.ConfigError):
            cfgmod.coerce("color", "maybe")

    def test_coerce_path_rejects_traversal(self) -> None:
        with self.assertRaises(cfgmod.ConfigError):
            cfgmod.coerce("report_dir", "../elsewhere")

    def test_coerce_rejects_unknown_key(self) -> None:
        with self.assertRaises(cfgmod.ConfigError):
            cfgmod.coerce("nonexistent", 1)

    def test_save_and_load_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            settings = cfgmod.defaults()
            settings["theme"] = "matrix"
            cfgmod.save(settings, path)
            loaded = cfgmod.load(path)
            self.assertEqual(loaded["theme"], "matrix")

    def test_load_missing_returns_defaults(self) -> None:
        loaded = cfgmod.load(Path("/nonexistent/config.json"))
        self.assertEqual(loaded["theme"], cfgmod.DEFAULTS["theme"])

    def test_load_corrupt_returns_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text("{not json", encoding="utf-8")
            self.assertEqual(cfgmod.load(path)["theme"], cfgmod.DEFAULTS["theme"])

    def test_load_merges_missing_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({"theme": "dark"}), encoding="utf-8")
            loaded = cfgmod.load(path)
            self.assertEqual(loaded["theme"], "dark")
            self.assertIn("max_redirects", loaded)

    def test_get_nested(self) -> None:
        settings = cfgmod.defaults()
        self.assertIsInstance(cfgmod.get(settings, "privacy.store_access_logs"), bool)
        self.assertIsNone(cfgmod.get(settings, "nope.nope"))

    def test_set_value_nested(self) -> None:
        settings = cfgmod.defaults()
        cfgmod.set_value(settings, "web_server.base_url", "https://x.test")
        self.assertEqual(cfgmod.get(settings, "web_server.base_url"), "https://x.test")

    def test_set_value_validates_top_level(self) -> None:
        settings = cfgmod.defaults()
        with self.assertRaises(cfgmod.ConfigError):
            cfgmod.set_value(settings, "timeout", 999)

    def test_report_dir_is_absolute(self) -> None:
        settings = cfgmod.defaults()
        self.assertTrue(cfgmod.report_dir(settings).is_absolute())


class RateLimiterTests(unittest.TestCase):
    def test_budget_enforced(self) -> None:
        limiter = RateLimiter(rate=1000, burst=10, max_requests=3)
        for _ in range(3):
            limiter.acquire()
        with self.assertRaises(RateLimitExceeded):
            limiter.acquire(blocking=False)

    def test_non_blocking_raises_when_empty(self) -> None:
        limiter = RateLimiter(rate=0.1, burst=1, max_requests=100)
        limiter.acquire()
        with self.assertRaises(RateLimitExceeded):
            limiter.acquire(blocking=False)

    def test_snapshot_reports_usage(self) -> None:
        limiter = RateLimiter(rate=5, burst=5, max_requests=10)
        limiter.acquire()
        snapshot = limiter.snapshot()
        self.assertEqual(snapshot["used"], 1)
        self.assertEqual(snapshot["max_requests"], 10)


class DNSWireTests(unittest.TestCase):
    def test_encode_simple_name(self) -> None:
        encoded = net_dns.encode_name("example.com")
        self.assertEqual(encoded, b"\x07example\x03com\x00")

    def test_encode_trailing_dot(self) -> None:
        self.assertEqual(net_dns.encode_name("a.test."), net_dns.encode_name("a.test"))

    def test_encode_root(self) -> None:
        self.assertEqual(net_dns.encode_name(""), b"\x00")

    def test_encode_rejects_long_label(self) -> None:
        with self.assertRaises(net_dns.DNSError):
            net_dns.encode_name("a" * 64 + ".com")

    def test_decode_roundtrip(self) -> None:
        encoded = net_dns.encode_name("deep.sub.example.com")
        name, offset = net_dns.decode_name(encoded, 0)
        self.assertEqual(name, "deep.sub.example.com.")
        self.assertEqual(offset, len(encoded))

    def test_decode_compression_pointer(self) -> None:
        # "example.com" then a name that points back to it.
        base = net_dns.encode_name("example.com")
        packet = base + b"\x03www\xc0\x00"
        name, _ = net_dns.decode_name(packet, len(base))
        self.assertEqual(name, "www.example.com.")

    def test_decode_compression_loop_raises(self) -> None:
        with self.assertRaises(net_dns.DNSError):
            net_dns.decode_name(b"\xc0\x00", 0)

    def test_build_query_header(self) -> None:
        packet, qid = net_dns.build_query("example.com", "A", qid=0x1234)
        self.assertEqual(qid, 0x1234)
        unpacked = struct.unpack("!HHHHHH", packet[:12])
        self.assertEqual(unpacked[0], 0x1234)
        self.assertEqual(unpacked[1], 0x0100)
        self.assertEqual(unpacked[2], 1)

    def test_build_query_rejects_unknown_type(self) -> None:
        with self.assertRaises(net_dns.DNSError):
            net_dns.build_query("example.com", "NOPE")

    def _response(self, rcode: int = 0, answers: bytes = b"", count: int = 0) -> bytes:
        header = struct.pack("!HHHHHH", 0x1234, 0x8180 | rcode, 1, count, 0, 0)
        question = net_dns.encode_name("example.com") + struct.pack("!HH", 1, 1)
        return header + question + answers

    def test_parse_a_record(self) -> None:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([93, 184, 216, 34])
        parsed = net_dns.parse_packet(self._response(answers=answer, count=1))
        self.assertEqual(parsed["rcode"], 0)
        self.assertEqual(parsed["answers"][0]["type"], "A")
        self.assertEqual(parsed["answers"][0]["value"], "93.184.216.34")

    def test_parse_nxdomain(self) -> None:
        parsed = net_dns.parse_packet(self._response(rcode=3))
        self.assertEqual(parsed["rcode"], 3)
        self.assertEqual(parsed["rcode_text"], "NXDOMAIN")

    def test_parse_mx_record(self) -> None:
        rdata = struct.pack("!H", 10) + net_dns.encode_name("mail.example.com")
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 15, 1, 300, len(rdata)) + rdata
        parsed = net_dns.parse_packet(self._response(answers=answer, count=1))
        self.assertEqual(parsed["answers"][0]["type"], "MX")
        self.assertEqual(parsed["answers"][0]["value"]["preference"], 10)

    def test_parse_txt_record(self) -> None:
        text = b"v=spf1 -all"
        rdata = bytes([len(text)]) + text
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 300, len(rdata)) + rdata
        parsed = net_dns.parse_packet(self._response(answers=answer, count=1))
        self.assertEqual(parsed["answers"][0]["value"], "v=spf1 -all")

    def test_parse_short_packet_raises(self) -> None:
        with self.assertRaises(net_dns.DNSError):
            net_dns.parse_packet(b"\x00")

    def test_reverse_name_ipv4(self) -> None:
        self.assertEqual(net_dns.reverse_name("1.2.3.4"), "4.3.2.1.in-addr.arpa")

    def test_reverse_name_ipv6(self) -> None:
        self.assertTrue(net_dns.reverse_name("::1").endswith(".ip6.arpa"))

    def test_system_resolvers_non_empty(self) -> None:
        self.assertTrue(net_dns.system_resolvers())


class DefensiveTests(unittest.TestCase):
    def test_password_length(self) -> None:
        for length in (8, 16, 32, 64):
            self.assertEqual(len(ds.generate_password(length)), max(8, length))

    def test_password_length_clamped(self) -> None:
        self.assertEqual(len(ds.generate_password(2)), 8)
        self.assertEqual(len(ds.generate_password(1000)), 128)

    def test_passwords_are_unique(self) -> None:
        self.assertNotEqual(ds.generate_password(24), ds.generate_password(24))

    def test_password_avoids_ambiguous(self) -> None:
        password = ds.generate_password(40, avoid_ambiguous=True)
        self.assertFalse(any(char in password for char in ds.AMBIGUOUS))

    def test_password_contains_requested_classes(self) -> None:
        password = ds.generate_password(16, avoid_ambiguous=False)
        self.assertTrue(any(ch.isupper() for ch in password))
        self.assertTrue(any(ch.islower() for ch in password))
        self.assertTrue(any(ch.isdigit() for ch in password))

    def test_strength_ranks_weak_lower_than_strong(self) -> None:
        weak = ds.estimate_strength("password")
        strong = ds.estimate_strength("Tr0ub4dor&3-Correct-Horse-Battery")
        self.assertLess(weak["score"], strong["score"])
        self.assertIn("common password", " ".join(weak["flags"]).lower())

    def test_strength_short_flagged(self) -> None:
        self.assertIn("Shorter than 8", " ".join(ds.estimate_strength("abc")["flags"]))

    def test_strength_entropy_positive(self) -> None:
        self.assertGreater(ds.estimate_strength("aB3$xY9!qW")["entropy_bits"], 0)

    def test_humanize_seconds(self) -> None:
        self.assertEqual(ds.humanize_seconds(0.1), "instantly")
        self.assertIn("years", ds.humanize_seconds(10 ** 12))

    def test_hash_text_known_value(self) -> None:
        self.assertEqual(
            ds.hash_text("abc", "sha256"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_hash_unknown_algorithm(self) -> None:
        with self.assertRaises(ValueError):
            ds.hash_text("abc", "sha3-nope")

    def test_hash_and_verify_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "f.txt"
            path.write_bytes(b"hello")
            result = ds.hash_file(path)
            verified = ds.compare_integrity(path, result["digest"])
            self.assertTrue(verified["match"])
            self.assertFalse(ds.compare_integrity(path, "0" * 64)["match"])

    def test_base64_roundtrip(self) -> None:
        encoded = ds.base64_encode("hello world")
        self.assertEqual(ds.base64_decode(encoded), "hello world")

    def test_base64_invalid_raises(self) -> None:
        with self.assertRaises(ValueError):
            ds.base64_decode("@@@not base64@@@")

    def test_url_encode_roundtrip(self) -> None:
        self.assertEqual(ds.url_decode(ds.url_encode("a b&c=d")), "a b&c=d")

    def test_json_format_valid(self) -> None:
        pretty, error = ds.json_format('{"b":1,"a":2}')
        self.assertIsNone(error)
        self.assertIn('"a": 2', pretty)

    def test_json_format_invalid(self) -> None:
        pretty, error = ds.json_format("{oops}")
        self.assertIsNone(pretty)
        self.assertIn("invalid JSON", error)

    def test_jwt_none_algorithm_critical(self) -> None:
        import base64 as b64

        header = b64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
        payload = b64.urlsafe_b64encode(b'{"sub":"1"}').decode().rstrip("=")
        result = ds.inspect_jwt("{}.{}.sig".format(header, payload))
        titles = [item["title"] for item in result["findings"]]
        self.assertTrue(any("alg=none" in title for title in titles))

    def test_jwt_bad_structure(self) -> None:
        result = ds.inspect_jwt("not.a.jwt.at.all")
        self.assertFalse(result["valid_structure"])

    def test_jwt_missing_expiry_flagged(self) -> None:
        import base64 as b64

        header = b64.urlsafe_b64encode(b'{"alg":"HS256"}').decode().rstrip("=")
        payload = b64.urlsafe_b64encode(b'{"sub":"1"}').decode().rstrip("=")
        result = ds.inspect_jwt("{}.{}.sig".format(header, payload))
        titles = [item["title"] for item in result["findings"]]
        self.assertTrue(any("expiry" in title.lower() for title in titles))

    def test_log_analysis_detects_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.log"
            path.write_text(
                "Failed password for root\n" * 6 + "curl http://x | sh\nFATAL error\n",
                encoding="utf-8",
            )
            report = ds.analyze_log(path)
            titles = " ".join(item.title for item in report.findings).lower()
            self.assertIn("failed logins", titles)
            self.assertIn("malware", titles)
            self.assertGreater(report.risk_score, 0)

    def test_log_analysis_missing_file(self) -> None:
        report = ds.analyze_log(Path("/nonexistent/app.log"))
        self.assertTrue(report.findings)

    def test_file_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.txt"
            path.write_text("hi", encoding="utf-8")
            meta = ds.file_metadata(path)
            self.assertEqual(meta["size_bytes"], 2)
            self.assertTrue(meta["is_file"])

    def test_file_metadata_missing_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            ds.file_metadata(Path("/nonexistent/x.txt"))

    def test_checklist_not_empty(self) -> None:
        self.assertGreaterEqual(len(ds.checklist()), 8)

    def test_header_check_report(self) -> None:
        report = ds.header_check({})
        self.assertTrue(report.findings)


class LinkGeneratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = lg.LinkStore(Path(self.tmp.name) / "links.json")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_create_link(self) -> None:
        link = self.store.create("SX-1", ttl="1h")
        self.assertTrue(link.is_active)
        self.assertIn("SX-1", link.url)

    def test_ttl_presets(self) -> None:
        self.assertEqual(lg.parse_ttl("15m"), 900)
        self.assertEqual(lg.parse_ttl("7d"), 604800)
        self.assertIsNone(lg.parse_ttl("never"))

    def test_ttl_seconds(self) -> None:
        self.assertEqual(lg.parse_ttl("120"), 120)

    def test_ttl_invalid(self) -> None:
        with self.assertRaises(lg.LinkError):
            lg.parse_ttl("whenever")

    def test_password_protection(self) -> None:
        link = self.store.create("SX-2", password="hunter2")
        self.assertTrue(self.store.verify_password(link.link_id, "hunter2"))
        self.assertFalse(self.store.verify_password(link.link_id, "wrong"))

    def test_short_password_rejected(self) -> None:
        with self.assertRaises(lg.LinkError):
            self.store.create("SX-3", password="ab")

    def test_revoke(self) -> None:
        link = self.store.create("SX-4")
        self.assertTrue(self.store.revoke(link.link_id))
        self.assertFalse(self.store.get(link.link_id).is_active)

    def test_revoke_unknown(self) -> None:
        self.assertFalse(self.store.revoke("nope"))

    def test_expiry(self) -> None:
        link = self.store.create("SX-5", ttl="1")
        link.expires_at = 1.0
        self.assertTrue(link.is_expired)
        self.assertFalse(link.is_active)

    def test_access_log_records_no_address(self) -> None:
        link = self.store.create("SX-6")
        entry = self.store.record_access(link.link_id, note="reviewed")
        self.assertIn("at", entry)
        self.assertNotIn("ip", json.dumps(entry).lower())
        self.assertEqual(self.store.get(link.link_id).views, 1)

    def test_access_log_can_be_disabled(self) -> None:
        link = self.store.create("SX-7")
        entry = self.store.record_access(link.link_id, store_logs=False)
        self.assertIsNone(entry)
        self.assertEqual(self.store.get(link.link_id).views, 1)

    def test_persistence_roundtrip(self) -> None:
        link = self.store.create("SX-8", ttl="1d")
        reopened = lg.LinkStore(Path(self.tmp.name) / "links.json")
        self.assertIsNotNone(reopened.get(link.link_id))

    def test_prune_removes_old_links(self) -> None:
        link = self.store.create("SX-9", ttl="1h")
        link.expires_at = 1.0
        self.store.save()
        self.assertGreaterEqual(self.store.prune(retention_days=0), 1)

    def test_summary_mentions_privacy(self) -> None:
        self.store.create("SX-10")
        summary = lg.summarize_store(self.store)
        self.assertIn("no visitor ip", summary["privacy"].lower())

    def test_privacy_notice_is_explicit(self) -> None:
        notice = lg.PRIVACY_NOTICE.lower()
        for term in ("ip address", "camera", "microphone", "track"):
            self.assertIn(term, notice)


class BatchTests(unittest.TestCase):
    def test_load_targets_skips_comments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "u.txt"
            path.write_text("# comment\nhttps://a.test\n\nhttps://b.test\n", encoding="utf-8")
            targets = batch.load_targets(path)
            self.assertEqual(targets, ["https://a.test", "https://b.test"])

    def test_load_targets_missing_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            batch.load_targets(Path("/nonexistent/u.txt"))

    def test_analyze_urls_sorts_by_score(self) -> None:
        report = batch.analyze_urls([
            "https://example.com",
            "http://paypal-secure-verify.tk/login/account/update",
        ])
        rows = report.sections[0].data["rows"]
        self.assertGreaterEqual(rows[0]["score"], rows[-1]["score"])

    def test_analyze_urls_flags_high_risk(self) -> None:
        report = batch.analyze_urls(["http://paypal-secure-verify.tk/login/account/update"])
        self.assertGreaterEqual(report.risk_score, 50)

    def test_empty_batch(self) -> None:
        report = batch.analyze_urls([])
        self.assertEqual(report.risk_score, 0)


if __name__ == "__main__":
    unittest.main()
