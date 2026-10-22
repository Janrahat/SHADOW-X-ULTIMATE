"""Configuration loading, validation and persistence."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

THEMES = ("matrix", "cyberpunk", "dark", "minimal")
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
LANGUAGES = ("en", "ur")

CONFIG_FILENAME = "config.json"

DEFAULTS: Dict[str, Any] = {
    "theme": "cyberpunk",
    "color": True,
    "banner": True,
    "animations": True,
    "report_dir": "reports",
    "timeout": 8,
    "max_redirects": 5,
    "max_requests_per_run": 60,
    "rate_limit_per_second": 3.0,
    "log_level": "INFO",
    "language": "en",
    "web_server": {
        "enabled": False,
        "base_url": "",
        "report_path": "",
    },
    "api_integrations": {
        "virustotal_key": "",
        "shodan_key": "",
    },
    "privacy": {
        "store_access_logs": True,
        "log_retention_days": 30,
    },
}


class ConfigError(Exception):
    """Raised when a configuration value cannot be accepted."""


def project_root() -> Path:
    """Directory containing main.py (the repository root of shadow_x)."""
    return Path(__file__).resolve().parent.parent


def default_config_path() -> Path:
    override = os.environ.get("SHADOW_X_CONFIG")
    if override:
        return Path(override).expanduser()
    return project_root() / CONFIG_FILENAME


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def defaults() -> Dict[str, Any]:
    return copy.deepcopy(DEFAULTS)


def load(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load config.json, merging over secure defaults. Never raises on bad JSON."""
    path = Path(path) if path else default_config_path()
    if not path.exists():
        return defaults()
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            return defaults()
    except (OSError, ValueError):
        return defaults()
    return _deep_merge(DEFAULTS, data)


def save(config: Dict[str, Any], path: Optional[Path] = None) -> Path:
    """Persist configuration atomically so a crash cannot truncate it."""
    path = Path(path) if path else default_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2, sort_keys=True)
        handle.write("\n")
    tmp.replace(path)
    return path


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    raise ConfigError("expected a boolean (true/false), got {!r}".format(value))


def _coerce_int(value: Any, minimum: int, maximum: int) -> int:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        raise ConfigError("expected an integer, got {!r}".format(value))
    if number < minimum or number > maximum:
        raise ConfigError("value must be between {} and {}".format(minimum, maximum))
    return number


def _coerce_float(value: Any, minimum: float, maximum: float) -> float:
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        raise ConfigError("expected a number, got {!r}".format(value))
    if number < minimum or number > maximum:
        raise ConfigError("value must be between {} and {}".format(minimum, maximum))
    return number


SCHEMA: Dict[str, Dict[str, Any]] = {
    "theme": {"kind": "choice", "choices": THEMES},
    "color": {"kind": "bool"},
    "banner": {"kind": "bool"},
    "animations": {"kind": "bool"},
    "report_dir": {"kind": "path"},
    "timeout": {"kind": "int", "min": 1, "max": 120},
    "max_redirects": {"kind": "int", "min": 0, "max": 20},
    "max_requests_per_run": {"kind": "int", "min": 1, "max": 2000},
    "rate_limit_per_second": {"kind": "float", "min": 0.1, "max": 20.0},
    "log_level": {"kind": "choice", "choices": LOG_LEVELS},
    "language": {"kind": "choice", "choices": LANGUAGES},
}


def coerce(key: str, value: Any) -> Any:
    """Validate and normalise one top-level setting."""
    rule = SCHEMA.get(key)
    if not rule:
        raise ConfigError("unknown setting {!r}".format(key))
    kind = rule["kind"]
    if kind == "bool":
        return _coerce_bool(value)
    if kind == "int":
        return _coerce_int(value, rule["min"], rule["max"])
    if kind == "float":
        return _coerce_float(value, rule["min"], rule["max"])
    if kind == "choice":
        text = str(value).strip().lower()
        # Compare case-insensitively but return the canonical spelling, so
        # "INFO" stays "INFO" while "Matrix" becomes "matrix".
        canonical = {str(choice).lower(): choice for choice in rule["choices"]}
        if text not in canonical:
            raise ConfigError(
                "must be one of: {}".format(", ".join(rule["choices"]))
            )
        return canonical[text]
    if kind == "path":
        text = str(value).strip()
        if not text:
            raise ConfigError("path must not be empty")
        if any(token in text for token in ("..", "\x00")):
            raise ConfigError("path must stay inside the project directory")
        return text
    raise ConfigError("unsupported schema kind")


def get(config: Dict[str, Any], dotted: str, fallback: Any = None) -> Any:
    """Read a nested value with a dotted key: get(cfg, 'privacy.store_access_logs')."""
    current: Any = config
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return fallback
        current = current[part]
    return current


def set_value(config: Dict[str, Any], dotted: str, raw: Any) -> Tuple[Dict[str, Any], Any]:
    """Set a dotted key, validating top-level entries. Returns (config, value)."""
    parts = [part for part in dotted.split(".") if part]
    if not parts:
        raise ConfigError("setting name must not be empty")
    value = coerce(parts[0], raw) if len(parts) == 1 and parts[0] in SCHEMA else raw
    current = config
    for part in parts[:-1]:
        nxt = current.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            current[part] = nxt
        current = nxt
    current[parts[-1]] = value
    return config, value


def validate(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate every known top-level key. Returns (ok, errors)."""
    errors: List[str] = []
    merged = _deep_merge(DEFAULTS, config or {})
    for key, rule in SCHEMA.items():
        try:
            coerce(key, merged.get(key))
        except ConfigError as exc:
            errors.append("{}: {}".format(key, exc))
    return (not errors), errors


def reset(path: Optional[Path] = None) -> Dict[str, Any]:
    fresh = defaults()
    save(fresh, path)
    return fresh


def report_dir(config: Dict[str, Any]) -> Path:
    raw = str(config.get("report_dir") or "reports")
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = project_root() / candidate
    return candidate


def ensure_report_dir(config: Dict[str, Any]) -> Path:
    directory = report_dir(config)
    directory.mkdir(parents=True, exist_ok=True)
    return directory
