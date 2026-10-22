"""Tests for cross-platform detection and capability mapping."""
from __future__ import annotations

import os
import unittest
from unittest import mock

from core import platform_detect as pd


class PlatformDetectTests(unittest.TestCase):
    def setUp(self) -> None:
        pd._CACHE = None

    def tearDown(self) -> None:
        pd._CACHE = None

    def test_detect_returns_platform_info(self) -> None:
        info = pd.detect(force=True)
        self.assertIsInstance(info, pd.PlatformInfo)
        self.assertTrue(info.system)
        self.assertTrue(info.python_version)
        self.assertIsInstance(info.capabilities, dict)

    def test_detect_is_cached(self) -> None:
        first = pd.detect(force=True)
        second = pd.detect()
        self.assertIs(first, second)

    def test_capabilities_contain_expected_keys(self) -> None:
        info = pd.detect(force=True)
        for key in ("rich", "raw_socket", "dns_resolver", "traceroute", "ping"):
            self.assertIn(key, info.capabilities)
        # The bundled resolver is always available.
        self.assertTrue(info.capabilities["dns_resolver"])

    def test_termux_detection_from_prefix(self) -> None:
        with mock.patch.dict(
            os.environ, {"PREFIX": "/data/data/com.termux/files/usr"}, clear=False
        ):
            with mock.patch("os.path.isdir", return_value=False):
                info = pd.detect(force=True)
        self.assertTrue(info.is_termux)
        self.assertTrue(info.is_android)
        self.assertEqual(info.system, "termux")
        self.assertIn("Termux", info.display)

    def test_termux_limitations_mention_raw_sockets(self) -> None:
        info = pd.PlatformInfo(is_termux=True, is_android=True, system="termux")
        info.capabilities = {"traceroute": False, "raw_socket": False, "rich": True,
                            "whois": True}
        notes = pd.limitations(info)
        joined = " ".join(notes).lower()
        self.assertIn("icmp", joined)
        self.assertIn("traceroute", joined)

    def test_kali_detection(self) -> None:
        with mock.patch.object(pd, "_read_os_release", return_value={
            "ID": "kali", "PRETTY_NAME": "Kali GNU/Linux Rolling"
        }):
            with mock.patch.dict(os.environ, {}, clear=True):
                with mock.patch("os.path.isdir", return_value=False):
                    info = pd.detect(force=True)
        self.assertTrue(info.is_kali)
        self.assertFalse(info.is_termux)
        self.assertEqual(info.system, "kali")

    def test_generic_linux(self) -> None:
        with mock.patch.object(pd, "_read_os_release", return_value={
            "ID": "ubuntu", "PRETTY_NAME": "Ubuntu 24.04"
        }):
            with mock.patch.dict(os.environ, {}, clear=True):
                with mock.patch("os.path.isdir", return_value=False):
                    info = pd.detect(force=True)
        self.assertFalse(info.is_kali)
        self.assertFalse(info.is_termux)
        self.assertIn(info.system, ("linux", "unknown"))

    def test_have_command_handles_missing(self) -> None:
        self.assertFalse(pd.have_command("definitely-not-a-real-binary-xyz"))

    def test_module_available(self) -> None:
        self.assertTrue(pd.module_available("json"))
        self.assertFalse(pd.module_available("definitely_not_a_module_xyz"))

    def test_notes_never_empty(self) -> None:
        info = pd.detect(force=True)
        self.assertTrue(info.notes)

    def test_summary_line(self) -> None:
        pd._CACHE = None
        line = pd.summary_line()
        self.assertIsInstance(line, str)
        self.assertIn("(", line)

    def test_to_dict_is_json_serialisable(self) -> None:
        import json

        info = pd.detect(force=True)
        payload = json.dumps(info.to_dict())
        self.assertIn("capabilities", payload)

    def test_supports_helper(self) -> None:
        info = pd.PlatformInfo(capabilities={"ping": True, "traceroute": False})
        self.assertTrue(info.supports("ping"))
        self.assertFalse(info.supports("traceroute"))
        self.assertFalse(info.supports("nope"))


if __name__ == "__main__":
    unittest.main()
