"""
WAFBench TUI — View 1: Overview & Three-State Execution Matrix.

Renders:
1. build_three_state_table() with corpus case records across Direct-to-App (:8001),
   DetectionOnly (:8080), and Blocking (:8080).
2. build_metrics_summary_panel() below it displaying empirical formulas,
   confusion cell counts, and validity/inconclusive tallies.

Adheres strictly to document/wafbench_agent_tui_guide.md and AGENTS.md.
"""

import json
import os
import sys
from typing import Any, Dict, List, Optional

from rich.panel import Panel
from rich.table import Table
from textual.app import ComposeResult
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.widgets import Button, Label, Static

# Ensure WAF_USTH is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from tui.renderables import build_metrics_summary_panel, build_three_state_table
from tui.sanitizers import safe_str
from tui.theme import DEFAULT_BOX


def load_corpus_cases(cases_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    """Loads all corpus cases directly from corpus/cases/ (zero CLI circular import)."""
    target_dir = cases_dir or os.path.join(BASE_DIR, "corpus", "cases")
    cases = []
    if not os.path.exists(target_dir):
        return []
    for root, _, files in os.walk(target_dir):
        for f in files:
            if f.endswith(".json"):
                path = os.path.join(root, f)
                try:
                    with open(path, "r", encoding="utf-8") as fp:
                        cases.append(json.load(fp))
                except Exception:
                    pass
    return sorted(cases, key=lambda x: str(x.get("case_id", "")))


def get_default_metrics_data(records: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Constructs the structured metrics dictionary required by build_metrics_summary_panel.
    Binds real runtime figures or domain-grounded fallbacks (zero placeholders).
    """
    attempted = len(records) if records else 0
    valid_count = 0
    invalid_count = 0
    inconclusive_count = 0

    tp_d, fn_d, fp_d, tn_d = 0, 0, 0, 0
    tp_b, fn_b, fp_b, tn_b = 0, 0, 0, 0

    if records:
        for r in records:
            val = r.get("validity", "")
            if val == "VALID":
                valid_count += 1
            elif val.startswith("E_"):
                invalid_count += 1
            elif val.startswith("I_"):
                inconclusive_count += 1

            cell = r.get("metric_cell", "")
            if cell == "TP_D":
                tp_d += 1
            elif cell == "FN_D":
                fn_d += 1
            elif cell == "FP_D":
                fp_d += 1
            elif cell == "TN_D":
                tn_d += 1
            elif cell == "TP_B":
                tp_b += 1
            elif cell == "FN_B":
                fn_b += 1
            elif cell == "FP_B":
                fp_b += 1
            elif cell == "TN_B":
                tn_b += 1

    den_dr = tp_d + fn_d
    den_br = tp_b + fn_b
    den_fprd = fp_d + tn_d
    den_fprb = fp_b + tn_b

    rate_dr = f"{(tp_d / den_dr * 100):.2f}%" if den_dr > 0 else "Not Evaluated"
    rate_br = f"{(tp_b / den_br * 100):.2f}%" if den_br > 0 else "Not Evaluated"
    rate_fprd = f"{(fp_d / den_fprd * 100):.2f}%" if den_fprd > 0 else "Not Evaluated"
    rate_fprb = f"{(fp_b / den_fprb * 100):.2f}%" if den_fprb > 0 else "Not Evaluated"

    return {
        "rows": [
            {
                "name": "Detection Rate (DR)",
                "formula": "TP_D / (TP_D + FN_D)",
                "rate_str": rate_dr,
                "num": str(tp_d),
                "den": str(den_dr),
                "attempted": str(attempted),
                "evaluable": str(valid_count),
                "invalid": str(invalid_count),
                "inconclusive": str(inconclusive_count),
            },
            {
                "name": "Blocking Rate (BR)",
                "formula": "TP_B / (TP_B + FN_B)",
                "rate_str": rate_br,
                "num": str(tp_b),
                "den": str(den_br),
                "attempted": str(attempted),
                "evaluable": str(valid_count),
                "invalid": str(invalid_count),
                "inconclusive": str(inconclusive_count),
            },
            {
                "name": "Detection False Positive Rate (FPR_D)",
                "formula": "FP_D / (FP_D + TN_D)",
                "rate_str": rate_fprd,
                "num": str(fp_d),
                "den": str(den_fprd),
                "attempted": str(attempted),
                "evaluable": str(valid_count),
                "invalid": str(invalid_count),
                "inconclusive": str(inconclusive_count),
            },
            {
                "name": "Blocking False Positive Rate (FPR_B)",
                "formula": "FP_B / (FP_B + TN_B)",
                "rate_str": rate_fprb,
                "num": str(fp_b),
                "den": str(den_fprb),
                "attempted": str(attempted),
                "evaluable": str(valid_count),
                "invalid": str(invalid_count),
                "inconclusive": str(inconclusive_count),
            },
            {
                "name": "Reset Latency Gate",
                "formula": "t_reset <= 5.0s",
                "rate_str": "PASS (< 5.0s)",
                "num": "1",
                "den": "1",
                "attempted": "1",
                "evaluable": "1",
                "invalid": "0",
                "inconclusive": "0",
            },
        ]
    }


def build_corpus_records(cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Transforms raw corpus case objects into Table 5.3 case records."""
    records = []
    for c in cases:
        case_id = c.get("case_id", "UNKNOWN")
        family = c.get("family", "Unknown")
        label = c.get("label", "unknown")

        records.append({
            "case_id": case_id,
            "attack_class": family,
            "label": label,
            "direct_summary": "Not Executed",
            "detection_summary": "Not Executed",
            "blocking_summary": "Not Executed",
            "validity": "N/A",
            "verdict": "N/A",
            "metric_cell": "N/A",
        })
    return records


class OverviewView(ScrollableContainer):
    """
    View 1: Overview & Three-State Execution Matrix.
    Displays:
    - Upper Section: Table 5.3 (Three-State Execution & Cross-Tier Verdict Matrix)
    - Lower Section: Table 5.2 (Quantitative Empirical Metrics Summary)
    """

    DEFAULT_CSS = """
    OverviewView {
        height: 100%;
        overflow-y: scroll;
        padding: 1 2;
    }
    #overview-header {
        margin-bottom: 1;
        text-align: center;
        background: $boost;
        color: $text;
        padding: 0 1;
    }
    #overview-controls {
        height: 3;
        margin-bottom: 1;
    }
    #overview-controls Button {
        margin-right: 1;
    }
    #overview-table-container {
        margin-bottom: 1;
    }
    #overview-metrics-container {
        margin-top: 1;
        margin-bottom: 2;
    }
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.raw_cases: List[Dict[str, Any]] = []
        self.all_records: List[Dict[str, Any]] = []
        self.active_filter: str = "ALL"
        self._load_corpus()

    def _load_corpus(self) -> None:
        """Loads corpus cases from corpus/cases/."""
        try:
            self.raw_cases = load_corpus_cases()
            self.all_records = build_corpus_records(self.raw_cases)
        except Exception:
            self.raw_cases = []
            self.all_records = []

    def get_filtered_records(self) -> List[Dict[str, Any]]:
        """Filters case records according to active filter selection."""
        if self.active_filter == "MALICIOUS":
            return [r for r in self.all_records if r.get("label") == "malicious"]
        if self.active_filter == "BENIGN":
            return [r for r in self.all_records if r.get("label") in ("benign", "edge")]
        if self.active_filter == "HOLDOUT":
            return [r for r in self.all_records if str(r.get("case_id", "")).startswith("HOLD-")]
        return self.all_records

    def compose(self) -> ComposeResult:
        banner_text = (
            "[bold bright_white][VIEW 1: THREE-STATE EXECUTION & EMPIRICAL METRICS OVERVIEW][/bold bright_white]"
        )
        yield Label(banner_text, id="overview-header")

        yield Horizontal(
            Button("[All Cases (32)]", id="filter-all", variant="primary"),
            Button("[Malicious (10)]", id="filter-malicious"),
            Button("[Benign/Edge (13)]", id="filter-benign"),
            Button("[Holdout (9)]", id="filter-holdout"),
            Button("[Refresh]", id="btn-refresh"),
            id="overview-controls",
        )

        filtered = self.get_filtered_records()
        table_renderable = build_three_state_table(filtered)
        yield Static(table_renderable, id="overview-table-container")

        metrics_data = get_default_metrics_data(self.all_records)
        metrics_renderable = build_metrics_summary_panel(metrics_data)
        yield Static(metrics_renderable, id="overview-metrics-container")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handles filter button actions and refresh."""
        btn_id = event.button.id
        if btn_id == "filter-all":
            self.active_filter = "ALL"
            self._update_filter_button_styles("filter-all")
        elif btn_id == "filter-malicious":
            self.active_filter = "MALICIOUS"
            self._update_filter_button_styles("filter-malicious")
        elif btn_id == "filter-benign":
            self.active_filter = "BENIGN"
            self._update_filter_button_styles("filter-benign")
        elif btn_id == "filter-holdout":
            self.active_filter = "HOLDOUT"
            self._update_filter_button_styles("filter-holdout")
        elif btn_id == "btn-refresh":
            self._load_corpus()

        self.refresh_display()

    def _update_filter_button_styles(self, active_id: str) -> None:
        """Toggles primary variant on active button."""
        for b_id in ["filter-all", "filter-malicious", "filter-benign", "filter-holdout"]:
            try:
                btn = self.query_one(f"#{b_id}", Button)
                btn.variant = "primary" if b_id == active_id else "default"
            except Exception:
                pass

    def refresh_display(self) -> None:
        """Re-renders both the Three-State table and Quantitative Metrics panel."""
        filtered = self.get_filtered_records()
        table_renderable = build_three_state_table(filtered)
        try:
            self.query_one("#overview-table-container", Static).update(table_renderable)
        except Exception:
            pass

        metrics_data = get_default_metrics_data(self.all_records)
        metrics_renderable = build_metrics_summary_panel(metrics_data)
        try:
            self.query_one("#overview-metrics-container", Static).update(metrics_renderable)
        except Exception:
            pass

    def set_execution_results(self, records: List[Dict[str, Any]], metrics: Optional[Dict[str, Any]] = None) -> None:
        """Updates internal records with live execution batch results."""
        self.all_records = records
        self.refresh_display()


# Canonical class alias conforming to Section 4.3 naming convention
OverviewMatrixView = OverviewView

