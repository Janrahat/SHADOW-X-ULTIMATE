"""SHADOW-X ULTIMATE entry point - dashboard, menus and subcommands."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core import config as config_module  # noqa: E402
from core import logging_utils, platform_detect  # noqa: E402
from core.models import TOOL_NAME, TOOL_VERSION, Report, RiskLevel, utc_now  # noqa: E402
from core.ui import NullUI, UI, build_ui  # noqa: E402
from modules import (  # noqa: E402
    authorized_testing,
    batch,
    defensive_security,
    domain_intelligence,
    link_generator,
    network_diagnostics,
    report_generator,
    url_analyzer,
)

RECENT_LIMIT = 8

BANNER_SUBTITLE = "cross-platform security toolkit  |  Termux + Kali Linux"


def _version_string() -> str:
    return "{} v{}".format(TOOL_NAME, TOOL_VERSION)


# ---------------------------------------------------------------------------
# Dashboard
def _disk_free(path: Path) -> str:
    try:
        usage = shutil.disk_usage(str(path))
        return "{:.1f} GB free / {:.1f} GB total".format(
            usage.free / 1e9, usage.total / 1e9
        )
    except Exception:
        return "n/a"


def _memory() -> str:
    for candidate in ("/proc/meminfo",):
        try:
            values: Dict[str, int] = {}
            with open(candidate, "r", encoding="utf-8") as handle:
                for line in handle:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].endswith(":"):
                        try:
                            values[parts[0].rstrip(":")] = int(parts[1])
                        except ValueError:
                            continue
            total = values.get("MemTotal")
            available = values.get("MemAvailable") or values.get("MemFree")
            if total:
                return "{:.2f} GB total, {:.2f} GB available".format(
                    total / 1024 / 1024, (available or 0) / 1024 / 1024
                )
        except OSError:
            continue
    return "n/a"


def dashboard(ui: UI, cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Render the dashboard. Returns the values it displayed."""
    info = platform_detect.detect()
    connected = platform_detect.probe_network()
    reports_dir = config_module.report_dir(cfg)
    recent = report_generator.list_reports(reports_dir, limit=5)
    module_status = [
        ("URL analyzer", "ready"),
        ("Link generator", "ready"),
        ("Network diagnostics", "ready" if connected else "offline"),
        ("Domain intelligence", "ready" if connected else "offline"),
        ("Defensive toolbox", "ready"),
        ("Authorized testing", "ready" if connected else "offline"),
    ]

    ui.section("Dashboard")
    ui.kv(
        [
            ("Tool", "{} v{}".format(TOOL_NAME, TOOL_VERSION)),
            ("Platform", info.display),
            ("Arch", info.machine or "unknown"),
            ("Python", info.python_version),
            ("Time (UTC)", utc_now()),
            ("Network", "connected" if connected else "no route to 1.1.1.1:443"),
            ("Disk", _disk_free(ROOT)),
            ("Memory", _memory()),
            ("Reports dir", str(reports_dir)),
            ("Theme", str(cfg.get("theme"))),
        ]
    )

    ui.table(
        ["Module", "Status"],
        [[name, status] for name, status in module_status],
        title="Module availability",
    )

    if recent:
        ui.table(
            ["Report file", "Size", "Modified"],
            [
                [
                    item["name"],
                    "{} B".format(item["size"]),
                    time.strftime("%Y-%m-%d %H:%M", time.localtime(item["modified"])),
                ]
                for item in recent
            ],
            title="Saved reports",
        )
    else:
        ui.section("Saved reports")
        ui.write("  " + ui.paint("No reports yet - run an analysis first.", ui.theme["muted"]))

    if info.notes:
        ui.section("Platform notes")
        for note in info.notes[:4]:
            ui.write("  - " + note)

    return {
        "platform": info.display,
        "python": info.python_version,
        "network": connected,
        "recent_reports": len(recent),
    }


# ---------------------------------------------------------------------------
# Report presentation
def present_report(ui: UI, report: Report, cfg: Dict[str, Any], export: Optional[str] = None) -> List[Path]:
    """Print a report in the terminal and optionally export it."""
    risk = report.overall_risk.value
    ui.section("{} :: {}".format(report.module, risk.upper()))
    ui.kv(
        [
            ("Report ID", report.report_id),
            ("Target", report.target or "n/a"),
            ("Generated", report.created_at),
            ("Risk score", "{}/100".format(report.risk_score)),
            ("Findings", ", ".join(
                "{}={}".format(level, count)
                for level, count in report.count_by_severity().items()
                if count
            ) or "none"),
        ]
    )
    for section in report.sections:
        if section.data:
            ui.section(section.title)
            pairs = []
            for key, value in section.data.items():
                if isinstance(value, (dict, list)):
                    rendered = json.dumps(value, ensure_ascii=False)
                    if len(rendered) > 220:
                        rendered = rendered[:217] + "..."
                else:
                    rendered = str(value)
                pairs.append((key, rendered))
            ui.kv(pairs)
        if section.findings:
            ui.findings([finding.to_dict() for finding in section.findings], section.title)

    if report.limitations:
        ui.section("Limitations")
        for note in report.limitations:
            ui.write("  - " + note)

    written: List[Path] = []
    if export:
        try:
            directory = config_module.ensure_report_dir(cfg)
            export_all = export == "all"
            written = report_generator.save(
                report, directory, fmt="json" if export_all else export, export_all=export_all
            )
            for path in written:
                ui.success("saved {}".format(path))
        except (OSError, ValueError) as exc:
            ui.error("could not write report: {}".format(exc))
    return written


def _export_prompt(ui: UI, cfg: Dict[str, Any]) -> Optional[str]:
    answer = ui.menu(
        "Export",
        [
            ("json", "machine-readable report"),
            ("txt", "plain text for tickets"),
            ("html", "standalone browser report"),
            ("all", "all three formats"),
        ],
        footer="0) Skip export",
    )
    return {"1": "json", "2": "txt", "3": "html", "4": "all"}.get(answer)


# ---------------------------------------------------------------------------
# Interactive flows
def flow_url_analyzer(ui: UI, cfg: Dict[str, Any]) -> None:
    url = ui.ask("URL to analyse: ")
    if not url:
        ui.warning("No URL entered.")
        return
    ui.spinner("analysing {}".format(url[:40]))
    report = url_analyzer.analyze(
        url,
        timeout=float(cfg.get("timeout", 8)),
        max_redirects=int(cfg.get("max_redirects", 5)),
    )
    present_report(ui, report, cfg, _export_prompt(ui, cfg))
    ui.remember("url_analyzer: {}".format(report.target))


def flow_domain(ui: UI, cfg: Dict[str, Any]) -> None:
    domain = ui.ask("Domain: ")
    if not domain:
        return
    ui.spinner("gathering records for {}".format(domain[:40]))
    report = domain_intelligence.analyze(domain, timeout=float(cfg.get("timeout", 8)))
    present_report(ui, report, cfg, _export_prompt(ui, cfg))
    ui.remember("domain_intelligence: {}".format(domain))


def flow_network(ui: UI, cfg: Dict[str, Any]) -> None:
    choice = ui.menu(
        "Network diagnostics",
        [
            ("Diagnose a host", "DNS, latency, TCP and traceroute"),
            ("Public IP lookup", "asks a public echo service for your egress address"),
            ("Local interfaces", "addresses assigned to this device"),
        ],
    )
    if choice == "1":
        host = ui.ask("Host or URL: ")
        if not host:
            return
        report = network_diagnostics.diagnose(host, timeout=float(cfg.get("timeout", 8)))
        present_report(ui, report, cfg, _export_prompt(ui, cfg))
    elif choice == "2":
        if not ui.confirm("Query a public IP echo service? It will see your address."):
            return
        result = network_diagnostics.public_ip()
        if result.get("ip"):
            ui.success("public IP: {} (via {})".format(result["ip"], result["provider"]))
            ui.kv([(k, v) for k, v in result.items() if k not in ("ip", "provider") and v])
            ui.warning("An IP identifies a network endpoint, not a person or a street address.")
        else:
            ui.error(result.get("error") or "lookup failed")
    elif choice == "3":
        ui.table(
            ["Address", "Family", "Scope"],
            [[item["address"], item["family"], item["scope"]]
             for item in network_diagnostics.local_interfaces()],
            title="Local interfaces",
        )


def flow_link_generator(ui: UI, cfg: Dict[str, Any]) -> None:
    ui.section("Report link generator")
    for line in link_generator.PRIVACY_NOTICE.split(". "):
        if line.strip():
            ui.write("  " + line.strip().rstrip(".") + ".")
    store_path = config_module.report_dir(cfg) / "links.json"
    store = link_generator.LinkStore(store_path)
    choice = ui.menu(
        "Links",
        [
            ("Create a share link", "for a report you already generated"),
            ("List links", "active links and view counts"),
            ("Revoke a link", "immediately disables access"),
            ("Privacy summary", "what is and is not recorded"),
        ],
    )
    if choice == "1":
        report_id = ui.ask("Report ID (or file stem): ")
        if not report_id:
            return
        ttl = ui.ask("Expires in [15m/1h/24h/7d/30d/never]: ", "24h") or "24h"
        protected = ui.confirm("Password-protect this link?")
        password = ui.ask("Password: ") if protected else None
        try:
            link = store.create(
                report_id,
                ttl=ttl,
                password=password,
                base_url=str(config_module.get(cfg, "web_server.base_url", "") or ""),
            )
        except link_generator.LinkError as exc:
            ui.error(str(exc))
            return
        ui.success("link created: {}".format(link.url))
        ui.kv([("link id", link.link_id), ("expires", link.expires_at), ("protected", link.password_hash is not None)])
        ui.write("  " + ui.paint(link_generator.PRIVACY_NOTICE, ui.theme["muted"]))
    elif choice == "2":
        links = store.list_links(include_inactive=True)
        ui.table(
            ["Link ID", "Report", "Views", "Protected", "Active"],
            [[l.link_id, l.report_id, l.views, "yes" if l.password_hash else "no",
              "yes" if l.is_active else "no"] for l in links],
            title="Links",
        )
    elif choice == "3":
        link_id = ui.ask("Link ID to revoke: ")
        if link_id and store.revoke(link_id):
            ui.success("link {} revoked".format(link_id))
        else:
            ui.error("link not found")
    elif choice == "4":
        ui.kv(list(link_generator.summarize_store(store).items()))


def flow_defensive(ui: UI, cfg: Dict[str, Any]) -> None:
    choice = ui.menu(
        "Defensive toolbox",
        [
            ("Password generator", "cryptographically secure"),
            ("Password strength", "entropy, crack time, weak patterns"),
            ("Hash text or file", "SHA-256 and others"),
            ("File integrity check", "compare a known digest"),
            ("Base64 / URL encode & decode", ""),
            ("JSON validator", "parse and pretty-print"),
            ("JWT inspector", "structure only, no signature guessing"),
            ("Security checklist", "device hardening steps"),
        ],
    )
    if choice == "1":
        length = ui.ask("Length [20]: ", "20") or "20"
        try:
            password = defensive_security.generate_password(int(length))
        except ValueError:
            ui.error("length must be a number")
            return
        ui.success("generated: {}".format(password))
        strength = defensive_security.estimate_strength(password)
        ui.kv([(k, v) for k, v in strength.items() if k != "recommendation"])
    elif choice == "2":
        password = ui.ask("Password to evaluate: ")
        if not password:
            return
        result = defensive_security.estimate_strength(password)
        ui.kv([(k, v) for k, v in result.items() if k != "flags"])
        for flag in result["flags"]:
            ui.warning(flag)
        ui.info(result["recommendation"])
    elif choice == "3":
        text = ui.ask("Text (or blank to hash a file): ")
        if text:
            for algorithm in ("sha256", "sha512", "md5"):
                ui.write("  {:<8} {}".format(algorithm, defensive_security.hash_text(text, algorithm)))
        else:
            path = ui.ask("File path: ")
            if not path:
                return
            try:
                result = defensive_security.hash_file(Path(path))
            except OSError as exc:
                ui.error(str(exc))
                return
            ui.kv(list(result.items()))
    elif choice == "4":
        path = ui.ask("File path: ")
        expected = ui.ask("Expected SHA-256: ")
        if not path or not expected:
            return
        try:
            result = defensive_security.compare_integrity(Path(path), expected)
        except OSError as exc:
            ui.error(str(exc))
            return
        (ui.success if result["match"] else ui.error)(
            "{}: {} vs {}".format("MATCH" if result["match"] else "MISMATCH", result["expected"], result["actual"]))
    elif choice == "5":
        value = ui.ask("Value: ")
        if not value:
            return
        ui.kv([
            ("base64 encode", defensive_security.base64_encode(value)),
            ("url encode", defensive_security.url_encode(value)),
        ])
        try:
            ui.kv([("base64 decode", defensive_security.base64_decode(value))])
        except ValueError as exc:
            ui.warning("base64 decode: {}".format(exc))
    elif choice == "6":
        value = ui.ask("JSON: ")
        pretty, error = defensive_security.json_format(value or "")
        if error:
            ui.error(error)
        else:
            ui.write(pretty or "")
    elif choice == "7":
        token = ui.ask("JWT: ")
        if not token:
            return
        result = defensive_security.inspect_jwt(token)
        ui.kv([("segments", result["segments"]), ("header", result["header"]), ("payload", result["payload"])])
        if result["findings"]:
            ui.findings(result["findings"], "JWT findings")
        else:
            ui.success("no structural issues detected")
    elif choice == "8":
        ui.table(["#", "Item", "Why"],
                 [[index, row["item"], row["why"]]
                  for index, row in enumerate(defensive_security.checklist(), start=1)],
                 title="Device hardening checklist")


def flow_authorized(ui: UI, cfg: Dict[str, Any]) -> None:
    ui.section("Authorized security testing")
    for line in authorized_testing.SCOPE_NOTICE.split(". "):
        if line.strip():
            ui.write("  " + line.strip().rstrip(".") + ".")
    if not ui.confirm("I own this system or have written permission to test it", False):
        ui.warning("Testing cancelled - authorization is mandatory.")
        return
    target = ui.ask("Target host or URL: ")
    if not target:
        return
    mode_choice = ui.menu(
        "Mode",
        [
            ("availability", "3 connectivity samples"),
            ("connectivity", "common TCP ports, rate limited"),
            ("tls", "TLS versions and certificate"),
            ("headers", "HTTP security headers"),
            ("full", "all of the above"),
        ],
    )
    mode = {"1": "availability", "2": "connectivity", "3": "tls", "4": "headers", "5": "full"}.get(
        mode_choice, "full"
    )
    ports = [80, 443, 22, 8443]
    if mode in ("connectivity", "full"):
        raw = ui.ask("Ports (comma separated) [80,443,22,8443]: ", "80,443,22,8443")
        parsed = []
        for token in (raw or "").split(","):
            token = token.strip()
            if token.isdigit() and 1 <= int(token) <= 65535:
                parsed.append(int(token))
        ports = parsed or ports
    report = authorized_testing.run(
        target, mode=mode, ports=ports, authorized=True, timeout=float(cfg.get("timeout", 8))
    )
    present_report(ui, report, cfg, _export_prompt(ui, cfg))


def flow_batch(ui: UI, cfg: Dict[str, Any]) -> None:
    path = ui.ask("File with one URL per line: ")
    if not path:
        return
    try:
        targets = batch.load_targets(Path(path))
    except OSError as exc:
        ui.error(str(exc))
        return
    if not targets:
        ui.warning("No targets found in that file.")
        return
    deep = ui.confirm("Run deep HTTP checks too? (slower, one request per URL)", False)
    report = batch.analyze_urls(targets, deep=deep, timeout=float(cfg.get("timeout", 8)))
    present_report(ui, report, cfg, _export_prompt(ui, cfg))


def flow_settings(ui: UI, cfg: Dict[str, Any]) -> None:
    while True:
        ui.section("Settings")
        ui.table(
            ["Setting", "Value"],
            [
                ["theme", cfg.get("theme")],
                ["color", cfg.get("color")],
                ["banner", cfg.get("banner")],
                ["animations", cfg.get("animations")],
                ["report_dir", cfg.get("report_dir")],
                ["timeout", cfg.get("timeout")],
                ["max_redirects", cfg.get("max_redirects")],
                ["max_requests_per_run", cfg.get("max_requests_per_run")],
                ["rate_limit_per_second", cfg.get("rate_limit_per_second")],
                ["log_level", cfg.get("log_level")],
                ["language", cfg.get("language")],
            ],
        )
        choice = ui.menu(
            "Change a setting",
            [
                ("theme", "matrix, cyberpunk, dark, minimal"),
                ("colour output", "on/off"),
                ("banner", "on/off"),
                ("animations", "on/off"),
                ("report directory", "relative to the project"),
                ("request timeout", "1-120 seconds"),
                ("max redirects", "0-20"),
                ("request budget", "max requests per run"),
                ("rate limit", "requests per second"),
                ("log level", "DEBUG..CRITICAL"),
                ("web server base URL", "for shareable report links"),
                ("reset to defaults", "writes secure defaults"),
            ],
            footer="0) Back",
        )
        mapping = {
            "1": "theme", "2": "color", "3": "banner", "4": "animations",
            "5": "report_dir", "6": "timeout", "7": "max_redirects",
            "8": "max_requests_per_run", "9": "rate_limit_per_second",
            "10": "log_level",
        }
        if choice == "0" or not choice:
            return
        if choice == "11":
            base = ui.ask("base URL (e.g. https://intranet.example/reports): ", "")
            cfg.setdefault("web_server", {})["base_url"] = base
            cfg.setdefault("web_server", {})["enabled"] = bool(base)
            config_module.save(cfg)
            ui.success("saved")
            continue
        if choice == "12":
            if ui.confirm("Reset every setting to defaults?", False):
                cfg.clear()
                cfg.update(config_module.reset())
                ui.success("defaults restored")
            continue
        key = mapping.get(choice)
        if not key:
            ui.error("invalid choice")
            continue
        current = cfg.get(key)
        raw = ui.ask("{} [{}]: ".format(key, current), "")
        if not raw:
            continue
        try:
            _, value = config_module.set_value(cfg, key, raw)
        except config_module.ConfigError as exc:
            ui.error("{}: {}".format(key, exc))
            continue
        config_module.save(cfg)
        ui.success("{} = {}".format(key, value))
        if key in ("theme", "color", "animations", "banner"):
            ui.theme_name = str(cfg.get("theme"))
            ui.theme = __import__("core.ui", fromlist=["THEMES"]).THEMES[ui.theme_name]
            ui.animations = bool(cfg.get("animations"))


def interactive(ui: UI, cfg: Dict[str, Any]) -> int:
    """Main menu loop."""
    ui.startup(BANNER_SUBTITLE)
    while True:
        dashboard(ui, cfg)
        choice = ui.menu(
            "Main menu",
            [
                ("Analyse a URL", "structure, redirects, TLS, phishing indicators"),
                ("Domain intelligence", "DNS, WHOIS, TLS, SPF/DMARC"),
                ("Network diagnostics", "latency, TCP, DNS, public IP"),
                ("Batch URL scan", "score a file of links"),
                ("Defensive toolbox", "passwords, hashes, JWT, checklist"),
                ("Authorized testing", "scope-limited service checks"),
                ("Share report links", "expiring, revocable, consent-based"),
                ("Settings", "theme, timeouts, limits"),
            ],
            footer="0) Exit   |   r) Refresh   |   h) Home",
        )
        if choice in ("0", "q", "exit"):
            ui.write()
            ui.success("Stay safe. Only test systems you are authorized to test.")
            return 0
        if choice in ("r", "h", ""):
            continue
        actions = {
            "1": flow_url_analyzer,
            "2": flow_domain,
            "3": flow_network,
            "4": flow_batch,
            "5": flow_defensive,
            "6": flow_authorized,
            "7": flow_link_generator,
            "8": flow_settings,
        }
        action = actions.get(choice)
        if not action:
            ui.error("Invalid selection.")
            continue
        try:
            action(ui, cfg)
        except KeyboardInterrupt:
            ui.write()
            ui.warning("cancelled")
        except Exception as exc:  # never let one module kill the session
            ui.error("{}: {}".format(type(exc).__name__, exc))
        ui.pause()


# ---------------------------------------------------------------------------
# Subcommands
def _emit(ui: UI, report: Report, args: argparse.Namespace, cfg: Dict[str, Any]) -> int:
    if args.json:
        sys.stdout.write(report_generator.render(report, "json") + "\n")
    else:
        present_report(ui, report, cfg)
    if args.export:
        directory = config_module.ensure_report_dir(cfg)
        written = report_generator.save(
            report, directory, fmt="json" if args.export == "all" else args.export,
            export_all=args.export == "all",
        )
        for path in written:
            ui.success("saved {}".format(path))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shadow-x",
        description="{} v{} - cross-platform security toolkit".format(TOOL_NAME, TOOL_VERSION),
        epilog="Only test systems you own or are authorized to test.",
    )
    parser.add_argument("--theme", choices=("matrix", "cyberpunk", "dark", "minimal"))
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    parser.add_argument("--no-anim", action="store_true", help="disable animations")
    parser.add_argument("--json", action="store_true", help="print JSON instead of a table")
    parser.add_argument("--export", choices=("json", "txt", "html", "all"))
    subparsers = parser.add_subparsers(dest="command")

    # Output flags are also accepted AFTER the subcommand, which is how people
    # naturally type them (e.g. `shadow-x url https://x --export html`).
    output_flags = argparse.ArgumentParser(add_help=False)
    output_flags.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS,
        help="print JSON instead of a table",
    )
    output_flags.add_argument(
        "--export", choices=("json", "txt", "html", "all"), default=argparse.SUPPRESS,
        help="write the report to the reports directory",
    )
    common = output_flags

    subparsers.add_parser("version", help="print the version")
    subparsers.add_parser("platform", help="show platform detection details")
    subparsers.add_parser("dashboard", help="one-shot dashboard")

    url_parser = subparsers.add_parser("url", help="analyse a URL", parents=[common])
    url_parser.add_argument("target")
    url_parser.add_argument("--no-follow", action="store_true", help="skip redirect following")
    url_parser.add_argument("--timeout", type=float)

    domain_parser = subparsers.add_parser("domain", help="domain intelligence", parents=[common])
    domain_parser.add_argument("target")
    domain_parser.add_argument("--no-whois", action="store_true")
    domain_parser.add_argument("--timeout", type=float)

    net_parser = subparsers.add_parser("net", help="network diagnostics", parents=[common])
    net_parser.add_argument("target")
    net_parser.add_argument("--no-ping", action="store_true")
    net_parser.add_argument("--timeout", type=float)

    subparsers.add_parser("ip", help="public IP lookup", parents=[common])
    subparsers.add_parser("interfaces", help="local interface addresses", parents=[common])

    batch_parser = subparsers.add_parser("batch", help="score a file of URLs", parents=[common])
    batch_parser.add_argument("path")
    batch_parser.add_argument("--deep", action="store_true")

    auth_parser = subparsers.add_parser(
        "test", help="authorized testing (requires --authorized)", parents=[common]
    )
    auth_parser.add_argument("target")
    auth_parser.add_argument("--mode", choices=authorized_testing.TEST_MODES, default="full")
    auth_parser.add_argument("--ports", default="80,443,22,8443")
    auth_parser.add_argument("--authorized", action="store_true")

    subparsers.add_parser("config", help="print the effective configuration")
    subparsers.add_parser("reports", help="list saved reports", parents=[common])
    return parser


def _parse_ports(raw: str) -> List[int]:
    ports: List[int] = []
    for token in str(raw or "").split(","):
        piece = token.strip()
        if not piece:
            continue
        if "-" in piece:
            start, _, end = piece.partition("-")
            if start.isdigit() and end.isdigit():
                low, high = int(start), int(end)
                if 1 <= low <= high <= 65535:
                    ports.extend(range(low, min(high, low + 200) + 1))
        elif piece.isdigit() and 1 <= int(piece) <= 65535:
            ports.append(int(piece))
    return ports or [80, 443, 22, 8443]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = config_module.load()
    ok, errors = config_module.validate(cfg)
    if not ok:
        cfg = config_module.defaults()

    if args.theme:
        cfg["theme"] = args.theme
    if args.no_color:
        cfg["color"] = False
    if args.no_anim:
        cfg["animations"] = False

    logging_utils.setup_logging(
        str(cfg.get("log_level", "INFO")), config_module.report_dir(cfg), True
    )
    ui = build_ui(cfg)

    command = args.command or "menu"
    try:
        if command == "version":
            ui.write(_version_string())
            return 0
        if command == "platform":
            info = platform_detect.detect()
            ui.banner(BANNER_SUBTITLE)
            ui.kv(list(info.to_dict().items())[:12])
            ui.section("Capabilities")
            ui.table(["Feature", "Available"],
                     [[key, "yes" if value else "no"] for key, value in info.capabilities.items()])
            if info.notes:
                ui.section("Notes")
                for note in info.notes:
                    ui.write("  - " + note)
            return 0
        if command == "dashboard":
            ui.banner(BANNER_SUBTITLE)
            dashboard(ui, cfg)
            return 0
        if command == "url":
            report = url_analyzer.analyze(
                args.target,
                timeout=float(args.timeout or cfg.get("timeout", 8)),
                max_redirects=int(cfg.get("max_redirects", 5)),
                follow=not args.no_follow,
            )
            return _emit(ui, report, args, cfg)
        if command == "domain":
            report = domain_intelligence.analyze(
                args.target,
                timeout=float(args.timeout or cfg.get("timeout", 8)),
                include_whois=not args.no_whois,
            )
            return _emit(ui, report, args, cfg)
        if command == "net":
            report = network_diagnostics.diagnose(
                args.target,
                timeout=float(args.timeout or cfg.get("timeout", 8)),
                do_ping=not args.no_ping,
            )
            return _emit(ui, report, args, cfg)
        if command == "ip":
            result = network_diagnostics.public_ip()
            if args.json:
                ui.write(json.dumps(result, indent=2))
            elif result.get("ip"):
                ui.success("public IP: {} (via {})".format(result["ip"], result["provider"]))
                ui.kv([(k, v) for k, v in result.items() if k not in ("ip", "provider") and v])
            else:
                ui.error(result.get("error") or "lookup failed")
                return 1
            return 0
        if command == "interfaces":
            rows = [[item["address"], item["family"], item["scope"]]
                    for item in network_diagnostics.local_interfaces()]
            if args.json:
                ui.write(json.dumps(rows, indent=2))
            else:
                ui.table(["Address", "Family", "Scope"], rows, title="Local interfaces")
            return 0
        if command == "batch":
            targets = batch.load_targets(Path(args.path))
            report = batch.analyze_urls(
                targets, deep=args.deep, timeout=float(cfg.get("timeout", 8))
            )
            return _emit(ui, report, args, cfg)
        if command == "test":
            report = authorized_testing.run(
                args.target,
                mode=args.mode,
                ports=_parse_ports(args.ports),
                authorized=args.authorized,
                timeout=float(cfg.get("timeout", 8)),
            )
            return _emit(ui, report, args, cfg)
        if command == "config":
            ui.write(json.dumps(cfg, indent=2, sort_keys=True))
            return 0
        if command == "reports":
            entries = report_generator.list_reports(config_module.report_dir(cfg), limit=20)
            if args.json:
                ui.write(json.dumps(entries, indent=2))
            else:
                ui.table(
                    ["File", "Size", "Modified"],
                    [[item["name"], item["size"],
                      time.strftime("%Y-%m-%d %H:%M", time.localtime(item["modified"]))]
                     for item in entries],
                    title="Saved reports",
                )
            return 0
    except KeyboardInterrupt:
        ui.write()
        return 130
    except Exception as exc:
        ui.error("{}: {}".format(type(exc).__name__, exc))
        return 1

    return interactive(ui, cfg)


if __name__ == "__main__":
    sys.exit(main())
