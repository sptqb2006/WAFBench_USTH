"""
WAFBench Terminal UI (TUI) Package.

Modular Rich and Textual presentation layer strictly conforming to
WAFBench Anti-Slop and Academic Presentation standards.
"""

from tui.theme import (
    ASCII_BOX,
    BADGE_BLOCKED,
    BADGE_DEAD,
    BADGE_FAIL,
    BADGE_INCONCLUSIVE,
    BADGE_INVALID,
    BADGE_OK,
    BADGE_PASSED,
    BADGE_READY,
    BADGE_WAIT,
    DEFAULT_BOX,
    WAFBENCH_THEME,
)
from tui.sanitizers import (
    FORBIDDEN_SLOP_PATTERN,
    format_rule_list,
    safe_str,
)
from tui.renderables import (
    build_lab_header,
    build_metrics_summary_panel,
    build_three_state_table,
    build_three_tier_inspector,
)
# Lazy import for full-screen Textual app to avoid circular import cycles with cli.py
def __getattr__(name: str):
    if name == "WAFBenchTUI":
        from tui.app import WAFBenchTUI
        return WAFBenchTUI
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

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
    "FORBIDDEN_SLOP_PATTERN",
    "safe_str",
    "format_rule_list",
    "build_lab_header",
    "build_three_state_table",
    "build_three_tier_inspector",
    "build_metrics_summary_panel",
    "WAFBenchTUI",
]
