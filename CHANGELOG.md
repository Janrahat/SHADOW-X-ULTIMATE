# Changelog

All notable changes to SHADOW-X ULTIMATE are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-22

First public release. Cross-platform cybersecurity toolkit that runs on both
Termux (Android) and Kali Linux from one shared Python codebase.

### Added

- **Cross-platform engine** (`core/platform_detect.py`)
  - Detects Termux on Android, Kali Linux, generic Linux, macOS and Windows.
  - Capability map for `ping`, `traceroute`, `dig`, `whois`, `openssl`, `curl`,
    `ip`, raw sockets, Rich and Colorama.
  - Honest per-platform limitation notes; never demands root.

- **Cyberpunk interface** (`core/ui.py`)
  - ASCII logo, animated boot sequence, four themes (matrix, cyberpunk, dark,
    minimal), numbered menus, progress bars, severity badges.
  - Rich + Colorama used when present; graceful fallback to plain ANSI so a
    missing optional dependency can never crash the app.
  - Terminal-width aware tables that degrade cleanly on narrow phone screens.

- **Dashboard**
  - Tool and version, detected OS, architecture, Python version, UTC time,
    connectivity, disk free, memory where available, module availability and
    the most recent saved reports.
  - Public IP is only looked up when the user explicitly asks.

- **URL analyzer** (`modules/url_analyzer.py`)
  - Validation and normalisation, component parsing, redirect-chain inspection,
    HTTP status and headers, TLS certificate details.
  - Phishing heuristics: high-abuse TLDs, brand-name embedded in an unrelated
    domain, typosquat distance, punycode/homograph, `user:pass@` userinfo,
    raw-IP hosts, link shorteners, credential-harvesting path patterns.
  - Risk score with an explicit explanation for every point.
  - Safety: private/loopback/link-local destinations refused (SSRF guard),
    redirects capped, timeouts enforced, no credentials ever attached.

- **Transparent link generator** (`modules/link_generator.py`)
  - Share your own reports with random IDs, expiry presets or any `<n><m|h|d>`
    duration, optional password protection (PBKDF2-HMAC-SHA256, 120k rounds),
    revocation, and an access log that records a timestamp and self-declared
    note only - never a visitor IP, location, device fingerprint, camera,
    microphone, file or credential.

- **Network diagnostics** (`modules/network_diagnostics.py`)
  - Public IP lookup on request, local interfaces, forward and reverse DNS,
    ICMP ping when permitted and clearly-labelled TCP latency otherwise,
    TCP connect checks, HTTP connectivity, traceroute where supported,
    rate-limited port scans that require explicit authorization.

- **Domain intelligence** (`modules/domain_intelligence.py`)
  - A, AAAA, MX, NS, TXT, CNAME, SOA, CAA and SRV lookups via a bundled
    dependency-free DNS resolver (UDP with TCP fallback, compression parsing).
  - WHOIS over port 43 with IANA referral, RDAP over HTTPS as a fallback,
    expiry countdown, TLS certificate inspection, SPF and DMARC analysis,
    heuristic reputation indicators.

- **Defensive toolbox** (`modules/defensive_security.py`)
  - Secure password generator and entropy-based strength estimator with
    crack-time estimate, SHA-256/SHA-512/MD5/BLAKE2b hashing, file-integrity
    verification, Base64 and URL encode/decode, JSON validator, JWT structure
    inspector (`alg=none`, missing `exp`/`aud`), local log analyser, file
    metadata and a device-hardening checklist.

- **Authorized testing** (`modules/authorized_testing.py`)
  - Availability sampling, rate-controlled TCP connectivity, TLS version
    probing, HTTP security-header analysis, full mode.
  - Refuses to run without explicit authorization confirmation.

- **Reporting engine** (`modules/report_generator.py`)
  - Unique report ID, UTC timestamp, target, findings with evidence, risk
    ratings, explanations, limitations and defensive recommendations.
  - JSON, TXT and standalone offline HTML exports.
  - Every export runs credential redaction first: bearer tokens, cookies,
    `Authorization` headers, JWTs, AWS/GitHub/Slack keys and `password=`
    assignments are stripped before anything is written.

- **Configuration** (`core/config.py`)
  - Themes, colour, banner, animations, report directory, timeouts, redirect
    cap, request budget, rate limit, log level, language, optional web-server
    base URL and API keys.
  - Schema validation, atomic writes, corrupt-file recovery, secure defaults.

- **Safety primitives** (`core/security.py`)
  - SSRF guards, thread-safe token-bucket rate limiter with a hard per-run
    budget, recursive credential redaction, path-traversal-safe filenames.

- **Packaging**
  - `requirements.txt` with optional-only dependencies.
  - README with separate Termux and Kali Linux install instructions.
  - MIT licence plus an additional lawful-use notice.
  - GitHub Actions CI running the suite on Python 3.9-3.12.

### Known limitations

- Termux cannot open raw sockets without root, so ICMP ping falls back to TCP
  latency probes and traceroute reports as unsupported. Both are labelled.
- An IP address identifies a network endpoint, never a person or precise home
  address; nothing in this toolkit claims otherwise.
- No third-party reputation API is queried unless a key is configured.
- The link generator shares reports you already produced; it is not, and has no
  code path to become, a tracking-link or surveillance tool.

[1.0.0]: https://github.com/Janrahat/SHADOW-X-ULTIMATE/releases/tag/v1.0.0
