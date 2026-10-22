"""Smoke tests: real localhost servers, real TLS, real CLI subprocesses."""
from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
}


class _Handler(BaseHTTPRequestHandler):
    redirect_target = "/final"

    def log_message(self, *_args) -> None:  # silence the test output
        pass

    def do_HEAD(self) -> None:  # noqa: N802
        """http_check defaults to HEAD, so the fixture must answer it."""
        self.send_response(200)
        for key, value in SECURE_HEADERS.items():
            self.send_header(key, value)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", self.redirect_target)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/leak":
            self.send_response(200)
            for key, value in SECURE_HEADERS.items():
                self.send_header(key, value)
            self.send_header("Set-Cookie", "session=supersecretcookie")
            self.send_header("Authorization", "Bearer leaktoken123456")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            return
        body = b"hello"
        self.send_response(200)
        for key, value in SECURE_HEADERS.items():
            self.send_header(key, value)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _ServerMixin:
    server: HTTPServer
    thread: threading.Thread
    port: int

    @classmethod
    def start_server(cls) -> None:
        cls.server = HTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def stop_server(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)


class HttpSmokeTests(_ServerMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.start_server()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.stop_server()

    def test_http_check_succeeds(self) -> None:
        from modules import network_diagnostics as nd

        result = nd.http_check("http://127.0.0.1:{}/".format(self.port), timeout=3)
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["status"], 200)
        self.assertIn("elapsed_ms", result)

    def test_tcp_check_open_port(self) -> None:
        from modules import network_diagnostics as nd

        result = nd.tcp_check("127.0.0.1", self.port, timeout=3)
        self.assertTrue(result["open"])
        self.assertIsNotNone(result["elapsed_ms"])

    def test_tcp_check_closed_port(self) -> None:
        from modules import network_diagnostics as nd

        # Bind and immediately close to obtain a very likely-free port.
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            free_port = probe.getsockname()[1]
        result = nd.tcp_check("127.0.0.1", free_port, timeout=1)
        self.assertFalse(result["open"])
        self.assertIsNotNone(result["error"])

    def test_header_analysis_on_real_server(self) -> None:
        from modules import network_diagnostics as nd, url_analyzer as ua

        result = nd.http_check("http://127.0.0.1:{}/".format(self.port), timeout=3)
        findings, data = ua.analyze_security_headers(result["headers"])
        self.assertEqual(data["missing"], [])
        self.assertFalse(any("Missing" in item["title"] for item in findings))

    def test_response_headers_are_redacted(self) -> None:
        from modules import network_diagnostics as nd

        result = nd.http_check("http://127.0.0.1:{}/leak".format(self.port), timeout=3)
        rendered = json.dumps(result["headers"])
        self.assertNotIn("supersecretcookie", rendered)
        self.assertNotIn("leaktoken123456", rendered)

    def test_ping_falls_back_to_tcp(self) -> None:
        from modules import network_diagnostics as nd

        result = nd.ping_host("127.0.0.1", count=2, timeout=2)
        self.assertIn(result["method"], ("icmp", "tcp"))
        self.assertIn("note", result)

    def test_port_scan_requires_authorization(self) -> None:
        from modules import network_diagnostics as nd

        report = nd.port_scan("127.0.0.1", [self.port], authorized=False)
        self.assertFalse(report.metadata.get("scan_performed"))
        self.assertTrue(report.findings)

    def test_port_scan_finds_open_port(self) -> None:
        from modules import network_diagnostics as nd

        report = nd.port_scan("127.0.0.1", [self.port], timeout=2, authorized=True)
        self.assertIn("open", " ".join(item.title for item in report.findings).lower())

    def test_authorized_testing_blocks_private_target(self) -> None:
        from modules import authorized_testing as at

        report = at.run("127.0.0.1", mode="availability", authorized=True, timeout=2)
        titles = " ".join(item.title for item in report.findings).lower()
        self.assertIn("private", titles)

    def test_authorized_testing_refused_without_flag(self) -> None:
        from modules import authorized_testing as at

        report = at.run("example.com", authorized=False)
        self.assertFalse(report.metadata["authorization_confirmed"])
        self.assertTrue(report.findings)


class TlsSmokeTests(unittest.TestCase):
    """A self-signed TLS server must be reported as untrusted, never as valid."""

    @classmethod
    def setUpClass(cls) -> None:
        self_dir = Path(__file__).resolve().parent
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cert = Path(cls.tmp.name) / "cert.pem"
        cls.key = Path(cls.tmp.name) / "key.pem"
        try:
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", str(cls.key), "-out", str(cls.cert),
                    "-days", "1", "-nodes", "-subj", "/CN=localhost",
                ],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60,
            )
            cls.openssl = True
        except (OSError, subprocess.SubprocessError):
            cls.openssl = False
            return

        cls.server = HTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cls.cert), str(cls.key))
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        if getattr(cls, "openssl", False):
            cls.server.shutdown()
            cls.server.server_close()
            cls.thread.join(timeout=3)
        cls.tmp.cleanup()

    def test_self_signed_certificate_is_rejected(self) -> None:
        if not getattr(self, "openssl", False):
            self.skipTest("openssl binary unavailable")
        from modules import url_analyzer as ua

        report = ua.analyze(
            "https://127.0.0.1:{}/".format(self.port), timeout=3, allow_private=True
        )
        titles = " ".join(item.title for item in report.findings).lower()
        self.assertIn("certificate", titles)


class CliSmokeTests(unittest.TestCase):
    """Run the real entry point as a subprocess, exactly as a user would."""

    def _run(self, *args: str, timeout: int = 90):
        env = dict(os.environ)
        env["NO_COLOR"] = "1"
        env["PYTHONPATH"] = str(ROOT)
        env["SHADOW_X_CONFIG"] = str(Path(tempfile.gettempdir()) / "sx-test-config.json")
        return subprocess.run(
            [sys.executable, str(ROOT / "main.py"), *args],
            capture_output=True, text=True, env=env, timeout=timeout, cwd=str(ROOT),
        )

    def test_version(self) -> None:
        result = self._run("version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SHADOW-X ULTIMATE", result.stdout)
        self.assertIn("v1.0.0", result.stdout)

    def test_help(self) -> None:
        result = self._run("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        for command in ("url", "domain", "net", "batch", "test", "config", "reports"):
            self.assertIn(command, result.stdout)

    def test_platform(self) -> None:
        result = self._run("platform")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Capabilities", result.stdout)

    def test_dashboard(self) -> None:
        result = self._run("dashboard")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Dashboard", result.stdout)
        self.assertIn("Module availability", result.stdout)

    def test_config(self) -> None:
        result = self._run("config")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertIn("theme", payload)

    def test_invalid_url_exits_cleanly(self) -> None:
        result = self._run("url", "not a url")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_ssrf_blocked_from_cli(self) -> None:
        result = self._run("url", "http://169.254.169.254/latest/meta-data/")
        self.assertIn("blocked", result.stdout.lower())

    def test_batch_from_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "u.txt"
            path.write_text(
                "https://example.com\nhttp://paypal-secure-verify.tk/login/account/update\n",
                encoding="utf-8",
            )
            result = self._run("batch", str(path), "--json")
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertGreaterEqual(payload["risk_score"], 50)

    def test_export_all_from_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / "config.json"
            settings = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
            settings["report_dir"] = tmp
            env_path.write_text(json.dumps(settings), encoding="utf-8")
            env = dict(os.environ)
            env["NO_COLOR"] = "1"
            env["PYTHONPATH"] = str(ROOT)
            env["SHADOW_X_CONFIG"] = str(env_path)
            result = subprocess.run(
                [sys.executable, str(ROOT / "main.py"), "url", "https://example.com",
                 "--export", "all", "--no-follow"],
                capture_output=True, text=True, env=env, timeout=120, cwd=str(ROOT),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            produced = sorted(p.suffix for p in Path(tmp).iterdir())
            self.assertIn(".json", produced)
            self.assertIn(".txt", produced)
            self.assertIn(".html", produced)


class ImportSmokeTests(unittest.TestCase):
    """Every module must import on a bare standard library."""

    def test_all_modules_import(self) -> None:
        modules = [
            "core.platform_detect", "core.ui", "core.config", "core.models",
            "core.security", "core.logging_utils", "core.net_dns",
            "modules.url_analyzer", "modules.link_generator",
            "modules.network_diagnostics", "modules.domain_intelligence",
            "modules.defensive_security", "modules.authorized_testing",
            "modules.report_generator", "modules.batch",
        ]
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT)
        script = "import {}".format(", ".join(modules))
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, env=env, timeout=60, cwd=str(ROOT),
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_ui_survives_missing_rich(self) -> None:
        from core.ui import NullUI, UI

        ui = UI(theme="matrix", color=False, animations=False, banner=False)
        ui.notify("hello", "ok")
        ui.table(["a"], [[1]])
        ui.kv([("k", "v")])
        ui.findings([{"title": "t", "severity": "high"}])
        ui.progress([1, 2, 3])
        self.assertIsInstance(ui, UI)
        self.assertEqual(NullUI().ask("x", "d"), "d")


if __name__ == "__main__":
    unittest.main()
