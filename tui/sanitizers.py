"""
Anti-Slop & Markup Guardrails for WAFBench TUI.

Provides sanitization and formatting utilities to ensure zero Rich markup
injection crashes and strict prevention of forbidden AI placeholder tokens.
Adheres strictly to document/wafbench_agent_tui_guide.md (Section 3.2).
"""

import re
from typing import Any
from rich.markup import escape

# Regex catching forbidden AI placeholder patterns like <content>&<content> or [TBD]
FORBIDDEN_SLOP_PATTERN = re.compile(r"(<[^>]+>&<[^>]+>|\[TBD\]|<insert_[^>]+>)", re.IGNORECASE)


def safe_str(value: Any, fallback: str = "N/A") -> str:
    """
    Sanitizes any runtime value for Rich/Textual rendering.
    1. Replaces None or empty strings with an explicit domain fallback.
    2. Rejects AI placeholder slop patterns.
    3. Escapes Rich square-bracket markup so raw payloads render verbatim.
    """
    if value is None or value == "":
        if FORBIDDEN_SLOP_PATTERN.search(fallback):
            raise ValueError(f"Formatting violation: Forbidden placeholder pattern detected in fallback '{fallback}'")
        return escape(fallback)
    text = str(value)
    if FORBIDDEN_SLOP_PATTERN.search(text):
        raise ValueError(f"Formatting violation: Forbidden placeholder pattern detected in '{text}'")
    return escape(text)


def format_rule_list(rules: list[str] | None) -> str:
    """
    Formats a list of rule IDs safely for Rich/Textual display.
    Returns 'None' if empty or None, else comma-separated escaped rule IDs.
    """
    if not rules:
        return "None"
    return ", ".join(escape(str(r)) for r in rules)


def test_sanitizers() -> None:
    """
    Verification test function verifying:
    - safe_str("<script>alert(1)</script>")
    - safe_str("admin'-- ")
    - safe_str("[WAF_403]")
    - rejection of <test>&<test>
    and additional edge cases.
    """
    # 1. safe_str("<script>alert(1)</script>")
    val_xss = safe_str("<script>alert(1)</script>")
    assert val_xss == "<script>alert(1)</script>", f"Expected '<script>alert(1)</script>', got '{val_xss}'"

    # 2. safe_str("admin'-- ")
    val_sqli = safe_str("admin'-- ")
    assert val_sqli == "admin'-- ", f"Expected 'admin\\'-- ', got '{val_sqli}'"

    # 3. safe_str("[WAF_403]")
    val_badge = safe_str("[WAF_403]")
    assert val_badge == escape("[WAF_403]"), f"Expected '{escape('[WAF_403]')}', got '{val_badge}'"

    # 4. rejection of <test>&<test>
    rejected = False
    try:
        safe_str("<test>&<test>")
    except ValueError as exc:
        rejected = True
        assert "Forbidden placeholder pattern detected" in str(exc)
    assert rejected, "safe_str did not reject '<test>&<test>'"

    # Additional slop rejection checks: [TBD], <insert_...>, case-insensitive
    for slop in ["[TBD]", "[tbd]", "<insert_payload>", "prefix <content>&<content> suffix"]:
        try:
            safe_str(slop)
            assert False, f"safe_str failed to reject slop: {slop}"
        except ValueError:
            pass

    # Fallback checks
    assert safe_str(None) == "N/A"
    assert safe_str("") == "N/A"
    assert safe_str(None, fallback="Absent (RelevantOnly Policy)") == "Absent (RelevantOnly Policy)"
    assert safe_str("", fallback="Prevented (Phase 2 Interrupt)") == "Prevented (Phase 2 Interrupt)"

    # format_rule_list checks
    assert format_rule_list(None) == "None"
    assert format_rule_list([]) == "None"
    assert format_rule_list(["942100", "949110"]) == "942100, 949110"
    assert format_rule_list(["942100", "[949110]"]) == f"942100, {escape('[949110]')}"

    print("[OK] All sanitizers tests passed successfully.")


if __name__ == "__main__":
    test_sanitizers()
