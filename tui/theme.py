"""
WAFBench Terminal UI Theme and Styling Constants.

Deterministic, zero-emoji theme optimized for OpenSSH headless sessions
using standard 16-color / 256-color safe ANSI styles and box drawings.
Strictly adheres to document/wafbench_agent_tui_guide.md and AGENTS.md.
"""

from rich import box
from rich.theme import Theme

# Use standard 16-color / 256-color safe ANSI styles for reliable OpenSSH rendering
WAFBENCH_THEME = Theme({
    "badge.ok": "bold green",
    "badge.warn": "bold yellow",
    "badge.fail": "bold red",
    "badge.info": "bold cyan",
    "badge.muted": "dim white",
    "state.direct": "bold cyan",
    "state.detection": "bold yellow",
    "state.blocking": "bold magenta",
    "header.border": "bright_black",
    "table.header": "bold white",
})

# Register default styles so unadorned Console() instances don't raise MissingStyle
try:
    import rich.default_styles
    from rich.style import Style

    rich.default_styles.DEFAULT_STYLES.setdefault("badge.ok", Style(color="green", bold=True))
    rich.default_styles.DEFAULT_STYLES.setdefault("badge.warn", Style(color="yellow", bold=True))
    rich.default_styles.DEFAULT_STYLES.setdefault("badge.fail", Style(color="red", bold=True))
    rich.default_styles.DEFAULT_STYLES.setdefault("badge.info", Style(color="cyan", bold=True))
    rich.default_styles.DEFAULT_STYLES.setdefault("badge.muted", Style(color="white", dim=True))
    rich.default_styles.DEFAULT_STYLES.setdefault("header.border", Style(color="bright_black"))
    rich.default_styles.DEFAULT_STYLES.setdefault("table.header", Style(color="white", bold=True))
    rich.default_styles.DEFAULT_STYLES.setdefault("state.direct", Style(color="cyan", bold=True))
    rich.default_styles.DEFAULT_STYLES.setdefault("state.detection", Style(color="yellow", bold=True))
    rich.default_styles.DEFAULT_STYLES.setdefault("state.blocking", Style(color="magenta", bold=True))
except Exception:
    pass

# Use single-line square box drawing by default; fallback to pure ASCII if --ascii is passed
DEFAULT_BOX = box.SQUARE
ASCII_BOX = box.ASCII

# Deterministic Academic Badges (Zero Emojis, compatible with both Rich and Textual markup)
BADGE_OK = "[bold green][OK][/bold green]"
BADGE_FAIL = "[bold red][FAIL][/bold red]"
BADGE_INVALID = "[bold yellow][INVALID][/bold yellow]"
BADGE_INCONCLUSIVE = "[bold yellow][INCONCLUSIVE][/bold yellow]"
BADGE_BLOCKED = "[bold green][WAF_403][/bold green]"
BADGE_PASSED = "[bold cyan][HTTP_200][/bold cyan]"
BADGE_READY = "[bold green][READY][/bold green]"
BADGE_WAIT = "[bold yellow][WAIT][/bold yellow]"
BADGE_DEAD = "[bold red][DEAD][/bold red]"

__all__ = [
    "WAFBENCH_THEME",
    "DEFAULT_BOX",
    "ASCII_BOX",
    "BADGE_OK",
    "BADGE_FAIL",
    "BADGE_INVALID",
    "BADGE_INCONCLUSIVE",
    "BADGE_BLOCKED",
    "BADGE_PASSED",
    "BADGE_READY",
    "BADGE_WAIT",
    "BADGE_DEAD",
]
