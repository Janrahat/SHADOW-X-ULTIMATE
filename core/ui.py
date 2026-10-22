"""Cyberpunk terminal interface with a graceful plain-ANSI fallback.

Rich and Colorama are optional. If either is missing (very common on a fresh
Termux install) the UI degrades to hand-written ANSI escapes and keeps working
instead of raising ImportError.
"""
from __future__ import annotations

import os
import shutil
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Optional dependency probing -- never fatal
# ---------------------------------------------------------------------------
try:  # pragma: no cover - depends on environment
    from rich.console import Console  # type: ignore
    from rich.panel import Panel  # type: ignore
    from rich.progress import (  # type: ignore
        BarColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
    )
    from rich.table import Table  # type: ignore
    from rich.text import Text  # type: ignore

    RICH_AVAILABLE = True
except Exception:  # pragma: no cover
    RICH_AVAILABLE = False

try:  # pragma: no cover
    import colorama  # type: ignore

    colorama.just_fix_windows_console()
    COLORAMA_AVAILABLE = True
except Exception:  # pragma: no cover
    COLORAMA_AVAILABLE = False


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

ANSI_COLORS = {
    "black": "\033[30m",
    "red": "\033[38;5;196m",
    "green": "\033[38;5;46m",
    "yellow": "\033[38;5;226m",
    "blue": "\033[38;5;39m",
    "magenta": "\033[38;5;201m",
    "cyan": "\033[38;5;51m",
    "white": "\033[38;5;255m",
    "grey": "\033[38;5;244m",
    "orange": "\033[38;5;208m",
}

THEMES: Dict[str, Dict[str, str]] = {
    "matrix": {
        "primary": "green",
        "secondary": "green",
        "accent": "white",
        "danger": "red",
        "warning": "yellow",
        "muted": "grey",
        "title": "green",
    },
    "cyberpunk": {
        "primary": "cyan",
        "secondary": "magenta",
        "accent": "yellow",
        "danger": "red",
        "warning": "yellow",
        "muted": "grey",
        "title": "magenta",
    },
    "dark": {
        "primary": "blue",
        "secondary": "white",
        "accent": "cyan",
        "danger": "red",
        "warning": "orange",
        "muted": "grey",
        "title": "white",
    },
    "minimal": {
        "primary": "white",
        "secondary": "white",
        "accent": "white",
        "danger": "white",
        "warning": "white",
        "muted": "grey",
        "title": "white",
    },
}

SEVERITY_MARKERS = {
    "info": ("i", "cyan"),
    "low": ("+", "green"),
    "medium": ("!", "yellow"),
    "high": ("x", "orange"),
    "critical": ("X", "red"),
}

SPINNER_FRAMES = ("|", "/", "-", "\\")
BLOCK_FRAMES = ("[    ]", "[=   ]", "[==  ]", "[=== ]", "[====]", "[ ===]", "[  ==]", "[   =]")


def _supports_color(stream: Any = None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return bool(stream.isatty())
    except Exception:
        return False


def terminal_size() -> Tuple[int, int]:
    """(columns, lines) with a safe minimum so narrow screens do not crash."""
    try:
        size = shutil.get_terminal_size(fallback=(80, 24))
        columns = max(40, int(size.columns))
        lines = max(12, int(size.lines))
        return columns, lines
    except Exception:
        return 80, 24


class UI:
    """One object that owns every byte written to the terminal."""

    def __init__(
        self,
        theme: str = "cyberpunk",
        color: Optional[bool] = None,
        animations: bool = True,
        banner: bool = True,
        stream: Any = None,
    ) -> None:
        self.theme_name = theme if theme in THEMES else "cyberpunk"
        self.theme = THEMES[self.theme_name]
        self.stream = stream or sys.stdout
        self.color = _supports_color(self.stream) if color is None else bool(color)
        self.animations = bool(animations) and self.color
        self.show_banner = bool(banner)
        self.columns, self.lines = terminal_size()
        self._console = (
            Console(stream=self.stream, force_terminal=self.color, legacy_windows=False)
            if RICH_AVAILABLE
            else None
        )
        self._history: List[str] = []

    # -- low level -----------------------------------------------------------
    def refresh_size(self) -> Tuple[int, int]:
        self.columns, self.lines = terminal_size()
        return self.columns, self.lines

    def paint(self, text: str, color: Optional[str] = None, bold: bool = False) -> str:
        if not self.color:
            return text
        code = ""
        if color:
            code += ANSI_COLORS.get(color, "")
        if bold:
            code += BOLD
        return "{}{}{}".format(code, text, RESET) if code else text

    def write(self, text: str = "") -> None:
        try:
            self.stream.write(text + "\n")
            self.stream.flush()
        except Exception:
            pass

    def clear(self) -> None:
        if self.color:
            self.write("\033[2J\033[H")

    def rule(self, char: str = "-") -> None:
        self.write(self.paint(char * max(20, self.columns - 2), self.theme["muted"]))

    # -- branding ------------------------------------------------------------
    def banner_text(self) -> List[str]:
        """ASCII logo; falls back to a one-line wordmark on narrow terminals."""
        wide = [
            "  ####  #     #  ###  ####  #     #     #   #  #   #   ",
            " #      #     # #   # #   # #     #      # #    # #    ",
            "  ###   ####### ##### #   # #  #  #       #      #     ",
            "     #  #     # #   # #   # # # # #      # #    # #    ",
            " ####   #     # #   # ####   #   #  #    #   #  #   #  ",
        ]
        compact = ["SHADOW-X  ULTIMATE"]
        return wide if self.columns >= 60 else compact

    def banner(self, subtitle: str = "") -> None:
        if not self.show_banner:
            return
        primary = self.theme["primary"]
        accent = self.theme["accent"]
        self.write()
        for index, line in enumerate(self.banner_text()):
            color = primary if index % 2 == 0 else self.theme["secondary"]
            self.write(self.paint(line, color, bold=True))
        if subtitle:
            self.write(self.paint("  " + subtitle, accent))
        self.rule("=")
        self.write()

    def startup(self, subtitle: str = "") -> None:
        """Animated boot sequence; instant when animations are off."""
        if not self.animations:
            self.clear()
            self.banner(subtitle)
            return
        self.clear()
        self.write()
        for frame in SPINNER_FRAMES * 2:
            self.write(
                self.paint(
                    "  {}  initialising core ...".format(frame), self.theme["primary"]
                )
            )
            time.sleep(0.04)
            self.write("\033[1A\033[2K")
        self.banner(subtitle)

    # -- structural blocks ---------------------------------------------------
    def header(self, title: str, subtitle: str = "") -> None:
        line = "  {}  ".format(title.upper())
        if subtitle:
            line += "| " + subtitle
        self.write()
        self.write(self.paint(line, self.theme["title"], bold=True))
        self.rule("=")

    def section(self, title: str) -> None:
        self.write()
        self.write(self.paint(">> " + title, self.theme["secondary"], bold=True))
        self.rule("-")

    def success(self, message: str) -> None:
        self.notify(message, "ok")

    def warning(self, message: str) -> None:
        self.notify(message, "warn")

    def error(self, message: str) -> None:
        self.notify(message, "err")

    def info(self, message: str) -> None:
        self.notify(message, "info")

    def notify(self, message: str, kind: str = "info") -> None:
        mapping = {
            "ok": ("[ OK ]", "green"),
            "warn": ("[WARN]", "yellow"),
            "err": ("[FAIL]", "red"),
            "info": ("[ .. ]", "cyan"),
        }
        label, color = mapping.get(kind, mapping["info"])
        self.write("  {} {}".format(self.paint(label, color, bold=True), message))

    # -- tables --------------------------------------------------------------
    def table(
        self,
        headers: Sequence[str],
        rows: Iterable[Sequence[Any]],
        title: str = "",
    ) -> None:
        header_list = [str(item) for item in headers]
        row_list = [[("" if cell is None else str(cell)) for cell in row] for row in rows]
        if not row_list:
            self.write(self.paint("  (no rows)", self.theme["muted"]))
            return
        if title:
            self.section(title)

        widths = [len(text) for text in header_list]
        for row in row_list:
            for index, cell in enumerate(row[: len(widths)]):
                for line in cell.splitlines() or [""]:
                    widths[index] = max(widths[index], len(line))
            if len(row) > len(widths):
                for extra in row[len(widths) :]:
                    widths.append(len(str(extra)))

        available = max(20, self.columns - 2)
        total = sum(widths) + 2 * len(widths)
        if total > available and widths:
            excess = total - available
            while excess > 0 and max(widths) > 8:
                widest = widths.index(max(widths))
                widths[widest] -= 1
                excess -= 1

        def fit(value: str, width: int) -> str:
            text = str(value)
            if len(text) <= width:
                return text.ljust(width)
            return text[: max(1, width - 1)] + "~"

        separator = "  ".join("-" * width for width in widths)
        self.write("  " + self.paint(separator, self.theme["muted"]))
        self.write(
            "  "
            + "  ".join(
                self.paint(fit(text, widths[index]), self.theme["accent"], bold=True)
                for index, text in enumerate(header_list[: len(widths)])
            )
        )
        self.write("  " + self.paint(separator, self.theme["muted"]))
        for row in row_list:
            cells = []
            for index, width in enumerate(widths):
                raw = row[index] if index < len(row) else ""
                first, _, rest = raw.partition("\n")
                cells.append(fit(first, width))
            self.write("  " + "  ".join(cells))
            if "\n" in "".join(row):
                for index, width in enumerate(widths):
                    raw = row[index] if index < len(row) else ""
                    for extra_line in raw.split("\n")[1:]:
                        self.write("  " + fit(extra_line, width))

    def kv(self, pairs: Sequence[Tuple[str, Any]], title: str = "") -> None:
        """Vertical key/value block that survives narrow screens."""
        if title:
            self.section(title)
        if not pairs:
            self.write(self.paint("  (empty)", self.theme["muted"]))
            return
        width = max(len(str(key)) for key, _ in pairs)
        for key, value in pairs:
            rendered = "" if value is None else str(value)
            label = self.paint(str(key).ljust(width), self.theme["secondary"])
            if "\n" in rendered:
                first, _, rest = rendered.partition("\n")
                self.write("  {} : {}".format(label, first))
                for line in rest.split("\n"):
                    self.write("  {}   {}".format(" " * width, line))
            else:
                self.write("  {} : {}".format(label, rendered))

    def findings(self, items: Sequence[Dict[str, Any]], title: str = "Findings") -> None:
        if not items:
            self.section(title)
            self.write(self.paint("  No findings.", self.theme["muted"]))
            return
        self.section(title)
        for item in items:
            severity = str(item.get("severity", "info")).lower()
            marker, color = SEVERITY_MARKERS.get(severity, SEVERITY_MARKERS["info"])
            badge = self.paint("[{}]".format(marker), color, bold=True)
            self.write(
                "  {} {:<8} {}".format(badge, severity.upper(), item.get("title", ""))
            )
            detail = item.get("detail")
            if detail:
                for line in str(detail).split("\n"):
                    self.write("       " + self.paint(line, self.theme["muted"]))
            recommendation = item.get("recommendation")
            if recommendation:
                self.write(
                    "       -> " + self.paint(str(recommendation), self.theme["accent"])
                )

    # -- progress feedback ---------------------------------------------------
    def progress(
        self, items: Sequence[Any], label: str = "working", delay: float = 0.0
    ) -> None:
        """Simple in-place progress bar; no-op rendering when color is off."""
        total = len(items) or 1
        if not self.animations:
            self.write("  {} 0/{}".format(label, total))
            return
        for index, _item in enumerate(items, start=1):
            ratio = index / total
            filled = int(round(ratio * 24))
            bar = "#" * filled + "-" * (24 - filled)
            line = "  {:<28} [{}] {:3d}%".format(
                label[:28], bar, int(ratio * 100)
            )
            self.write("\r" + self.paint(line, self.theme["primary"]))
            time.sleep(delay)
        self.write("\r" + " " * (self.columns - 1) + "\r")

    def spinner(self, message: str, duration: float = 0.45) -> None:
        if not self.animations:
            self.write("  {} ...".format(message))
            return
        frames = max(1, int(duration / 0.06))
        for index in range(frames):
            frame = SPINNER_FRAMES[index % len(SPINNER_FRAMES)]
            self.write(
                "\r  {} {}".format(self.paint(frame, self.theme["primary"]), message)
            )
            time.sleep(0.06)
        self.write("\r" + " " * (self.columns - 1) + "\r")

    # -- interactive ---------------------------------------------------------
    def menu(
        self,
        title: str,
        options: Sequence[Tuple[str, str]],
        footer: str = "0) Exit",
        prompt_text: str = "select",
    ) -> str:
        """Numbered menu. Returns the raw key the user typed."""
        self.section(title)
        for index, (label, description) in enumerate(options, start=1):
            self.write(
                "  {}{}){} {}".format(
                    self.paint("[", self.theme["muted"]),
                    self.paint(str(index).rjust(2), self.theme["accent"], bold=True),
                    self.paint("]", self.theme["muted"]),
                    label,
                )
            )
            if description:
                self.write(
                    "        " + self.paint(description, self.theme["muted"])
                )
        self.write()
        self.write("  " + self.paint(footer, self.theme["muted"]))
        return self.ask(prompt_text)

    def ask(self, prompt_text: str = "> ", default: str = "") -> str:
        try:
            self.stream.flush()
        except Exception:
            pass
        try:
            return input(
                self.paint("  {} ".format(prompt_text.rstrip()), self.theme["accent"])
                + ""
            ).strip()
        except (EOFError, KeyboardInterrupt):
            self.write()
            return "0"

    def confirm(self, question: str, default: bool = False) -> bool:
        suffix = " [Y/n] " if default else " [y/N] "
        answer = self.ask(question + suffix).lower()
        if not answer:
            return default
        return answer in ("y", "yes", "1", "true")

    def pause(self, message: str = "Press Enter to continue") -> None:
        self.ask(message)

    def choose(self, title: str, options: Sequence[str], default: int = 1) -> int:
        """Pick one item from a list; returns the 1-based index."""
        pairs = [(option, "") for option in options]
        while True:
            raw = self.menu(title, pairs, footer="0) Cancel")
            if raw in ("0", "", "q"):
                return default
            if raw.isdigit() and 1 <= int(raw) <= len(options):
                return int(raw)
            self.error("Invalid selection - enter a number from the list.")

    # -- report helpers ------------------------------------------------------
    def remember(self, entry: str) -> None:
        self._history.append(entry)
        del self._history[:-20]

    @property
    def history(self) -> List[str]:
        return list(self._history)


class NullUI(UI):
    """Silent UI for tests and batch mode."""

    def __init__(self) -> None:
        super().__init__(theme="minimal", color=False, animations=False, banner=False)
        self.lines: List[str] = []

    def write(self, text: str = "") -> None:  # noqa: D102
        self.lines.append(text)

    def ask(self, prompt_text: str = "> ", default: str = "") -> str:  # noqa: D102
        return default


def build_ui(config: Dict[str, Any], **overrides: Any) -> UI:
    """Create a UI from a config dict, honouring NO_COLOR / FORCE_COLOR."""
    theme = overrides.get("theme", config.get("theme", "cyberpunk"))
    color = overrides.get("color", config.get("color"))
    animations = overrides.get("animations", config.get("animations", True))
    banner = overrides.get("banner", config.get("banner", True))
    return UI(
        theme=str(theme),
        color=None if color is None else bool(color),
        animations=bool(animations),
        banner=bool(banner),
    )
