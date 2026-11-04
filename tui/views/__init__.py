"""
WAFBench Terminal UI Views Package.

Exports the 4 core Textual views conforming to Section 4.3 of
document/wafbench_agent_tui_guide.md:
- OverviewView / OverviewMatrixView (View 1: Three-State Execution Matrix & Metrics Summary)
- InspectorView / EvidenceInspectorView (View 2: Three-Tier Evidence Inspector)
- CanaryView / CanaryResetView (View 3: Live Canary Verification & Fast Reset Gate)
- RegressionView / RuleExclusionView (View 4: C0 Baseline vs C1 Exclusions Regression View)
"""

from tui.views.canary import CanaryResetView, CanaryView
from tui.views.inspector import EvidenceInspectorView, InspectorView
from tui.views.overview import OverviewMatrixView, OverviewView
from tui.views.regression import RegressionView, RuleExclusionView

__all__ = [
    "OverviewView",
    "OverviewMatrixView",
    "InspectorView",
    "EvidenceInspectorView",
    "CanaryView",
    "CanaryResetView",
    "RegressionView",
    "RuleExclusionView",
]
