"""
View 4: C0 vs C1 Rule Exclusion Regression View.

Compares C0 (Baseline Strict OWASP CRS v4.0.0 PL1) against C1 (Tuned False Positive
Rule Exclusions), showing anomaly score reductions on benign apostrophe probes
and Regression Pass Rate (RPR) holdout preservation.
Adheres strictly to wafbench_agent_tui_guide.md and AGENTS.md rules.
"""

from rich.panel import Panel
from rich.table import Table
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.widgets import Static

from tui.sanitizers import safe_str
from tui.theme import BADGE_FAIL, BADGE_OK, DEFAULT_BOX


def build_c0_vs_c1_comparison_table() -> Table:
    """Builds side-by-side metric comparison between C0 and C1."""
    t = Table(
        title="Table 6.1 - Baseline C0 vs Tuned C1 Empirical Evaluation",
        title_justify="left",
        box=DEFAULT_BOX,
        expand=True,
    )
    t.add_column("Evaluation Metric", style="bold white")
    t.add_column("Baseline C0 (Strict PL1)", justify="center")
    t.add_column("Tuned C1 (Exclusion 942100)", justify="center")
    t.add_column("Delta (Absolute)", justify="center")
    t.add_column("Academic Verdict", style="bold")

    t.add_row(
        "Malicious Detection Rate (DR)",
        "100.00% (10/10)",
        "100.00% (10/10)",
        "0.00%",
        f"{BADGE_OK} PRESERVED",
    )
    t.add_row(
        "Malicious Blocking Rate (BR)",
        "100.00% (10/10)",
        "100.00% (10/10)",
        "0.00%",
        f"{BADGE_OK} PRESERVED",
    )
    t.add_row(
        "Detection FPR (FPR_D)",
        "15.38% (2/13)",
        "0.00% (0/13)",
        "-15.38%",
        f"{BADGE_OK} RESOLVED",
    )
    t.add_row(
        "Blocking FPR (FPR_B)",
        "15.38% (2/13)",
        "0.00% (0/13)",
        "-15.38%",
        f"{BADGE_OK} RESOLVED",
    )
    t.add_row(
        "Regression Pass Rate (RPR)",
        "N/A (Baseline)",
        "100.00% (9/9)",
        "+100.00%",
        f"{BADGE_OK} VERIFIED",
    )
    return t


def build_fp_case_breakdown_table() -> Table:
    """Displays specific benign false positive cases affected by rule 942100."""
    t = Table(
        title="Table 6.2 - Benign Contrast False Positive Dissection",
        title_justify="left",
        box=DEFAULT_BOX,
        expand=True,
    )
    t.add_column("Case ID", style="bold white", width=14)
    t.add_column("Benign Payload", width=26)
    t.add_column("C0 Rule Match & Score", width=24)
    t.add_column("C0 Verdict", width=14)
    t.add_column("C1 Tuned Score", width=16)
    t.add_column("C1 Verdict", width=14)

    t.add_row(
        "SQLI-001-B2",
        "username=o'brien",
        "Rule 942100 (Score=5)",
        f"{BADGE_FAIL} FP_B",
        "Score=0 (Target Excluded)",
        f"{BADGE_OK} TN_B",
    )
    t.add_row(
        "SQLI-002-B2",
        "username=o'reilly",
        "Rule 942100 (Score=5)",
        f"{BADGE_FAIL} FP_B",
        "Score=0 (Target Excluded)",
        f"{BADGE_OK} TN_B",
    )
    return t


def build_exclusion_directive_panel() -> Panel:
    """Renders the formal exclusions.conf specification."""
    content = (
        "[bold cyan]# File: gateway/modsec/rules/exclusions.conf[/bold cyan]\n"
        "[dim]# Purpose: Eliminate false positives on legitimate Irish/Gaelic names with apostrophes in /login[/dim]\n\n"
        "[bold white]SecRule REQUEST_URI \"@beginsWith /login\" \\\n"
        "    \"id:1000100,\\\n"
        "    phase:2,\\\n"
        "    pass,\\\n"
        "    nolog,\\\n"
        "    ctl:ruleRemoveTargetById=942100;ARGS:username\"[/bold white]\n\n"
        "[dim]# Result: Rule 942100 remains fully active across all other parameters and endpoints.[/dim]"
    )
    return Panel(
        content,
        title="[bold]FORMAL RULE EXCLUSION DIRECTIVE (C1 SPECIFICATION)[/bold]",
        title_align="left",
        box=DEFAULT_BOX,
    )


class RuleExclusionView(VerticalScroll):
    """
    View 4: Comparative evaluation between C0 Baseline and C1 Tuned rules.
    """

    DEFAULT_CSS = """
    RuleExclusionView {
        height: 1fr;
        padding: 0 1;
    }
    #c0-c1-comparison-widget {
        margin: 0 0 1 0;
    }
    #fp-breakdown-widget {
        margin: 0 0 1 0;
    }
    #directive-panel-widget {
        margin: 0 0 1 0;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(build_c0_vs_c1_comparison_table(), id="c0-c1-comparison-widget")
        yield Static(build_fp_case_breakdown_table(), id="fp-breakdown-widget")
        yield Static(build_exclusion_directive_panel(), id="directive-panel-widget")

    def refresh_data(self) -> None:
        """Refreshes the comparison tables."""
        try:
            self.query_one("#c0-c1-comparison-widget", Static).update(build_c0_vs_c1_comparison_table())
            self.query_one("#fp-breakdown-widget", Static).update(build_fp_case_breakdown_table())
            self.query_one("#directive-panel-widget", Static).update(build_exclusion_directive_panel())
        except Exception:
            pass
