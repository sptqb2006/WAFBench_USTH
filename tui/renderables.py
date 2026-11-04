"""
Shared Rich Components for WAFBench TUI.

Provides reusable presentation components conforming to academic publishing
standards: zero emojis, explicit formulas, deterministic ANSI styles, and
strict anti-slop escaping.
Adheres strictly to document/wafbench_agent_tui_guide.md (Section 3.3).
"""

import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from typing import Any, Dict, List
from rich.align import Align
from rich.columns import Columns
from rich.console import Group
from rich.panel import Panel
from rich.table import Table

from tui.sanitizers import format_rule_list, safe_str
from tui.theme import BADGE_FAIL, BADGE_OK, DEFAULT_BOX

__all__ = [
    "build_lab_header",
    "build_three_state_table",
    "build_three_tier_inspector",
    "build_metrics_summary_panel",
]


def build_lab_header(
    stack_status: Dict[str, Any] | None = None,
    policy_meta: Dict[str, Any] | None = None,
) -> Panel:
    """
    Component 1: Laboratory Readiness & Topology Header (UC-01, UC-03).
    Displays the 7 microservices, active ModSecurity mode (DetectionOnly vs Blocking),
    CRS baseline revision (C0 / C1), Paranoia Level, Inbound Threshold, and transport state.

    Args:
        stack_status: Dict mapping service names (wb- prefix or short name) to booleans/status strings.
        policy_meta: Dict containing mode, revision, paranoia_level, inbound_threshold, and transport.

    Returns:
        rich.panel.Panel: Styled header panel enclosing the readiness and topology metadata.
    """
    if stack_status is None:
        stack_status = {}
    if policy_meta is None:
        policy_meta = {}

    services = [
        "wb-gateway",
        "wb-app",
        "wb-app-db",
        "wb-mock",
        "wb-telemetry",
        "wb-event-db",
        "wb-dashboard",
    ]
    svc_tokens = []
    for svc in services:
        val = stack_status.get(svc)
        if val is None:
            val = stack_status.get(svc.replace("wb-", ""))

        if isinstance(val, bool):
            is_up = val
        elif isinstance(val, str):
            is_up = val.strip().lower() in ("true", "running", "healthy", "up", "online", "ok", "1")
        elif isinstance(val, dict):
            status_str = str(val.get("status", "")).strip().lower()
            is_up = val.get("healthy") is True or status_str in ("running", "healthy", "up", "online", "ok")
        else:
            is_up = bool(val)

        badge = BADGE_OK if is_up else BADGE_FAIL
        svc_tokens.append(f"{badge} {svc}")

    row1_left = " ".join(svc_tokens[:4])
    row1_right = " ".join(svc_tokens[4:])

    mode_raw = safe_str(
        policy_meta.get("mode") or policy_meta.get("waf_mode"),
        "UNKNOWN",
    )
    cleaned_mode = mode_raw
    if cleaned_mode.startswith(r"\["):
        cleaned_mode = cleaned_mode[2:]
    elif cleaned_mode.startswith("["):
        cleaned_mode = cleaned_mode[1:]
    if cleaned_mode.endswith(r"\]"):
        cleaned_mode = cleaned_mode[:-2]
    elif cleaned_mode.endswith("]"):
        cleaned_mode = cleaned_mode[:-1]

    if "detection" in cleaned_mode.lower():
        mode_styled = f"[state.detection]{cleaned_mode}[/state.detection]"
    elif "block" in cleaned_mode.lower():
        mode_styled = f"[state.blocking]{cleaned_mode}[/state.blocking]"
    elif "direct" in cleaned_mode.lower():
        mode_styled = f"[state.direct]{cleaned_mode}[/state.direct]"
    else:
        mode_styled = cleaned_mode

    revision = safe_str(policy_meta.get("revision") or policy_meta.get("crs_revision"), "C0")
    pl = safe_str(policy_meta.get("paranoia_level") or policy_meta.get("pl"), "1")
    thresh = safe_str(policy_meta.get("inbound_threshold") or policy_meta.get("threshold"), "5")
    transport = safe_str(policy_meta.get("transport"), "Local Docker")

    meta_table = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    meta_table.add_row(
        f"[bold]Containers (1-4):[/bold] {row1_left}",
        f"[bold]Revision:[/bold] {revision} (PL{pl} | InThresh={thresh})",
    )
    meta_table.add_row(
        f"[bold]Containers (5-7):[/bold] {row1_right}",
        f"[bold]Active Mode:[/bold] [{mode_styled}] | [bold]Transport:[/bold] {transport}",
    )

    w1 = "█ █ █ █▀█ █▀▀ █▀▄ █▀▀ █▄ █ █▀▀ █ █"
    w2 = "▀▄▀▄▀ █ █ █   █▄▀ ██▄ █ ▀█ █▄▄ █▀█"
    c1 = "█▀▀ █▀█ █▄ █ █▀  █▀█ █   █▀▀"
    c2 = "█▄▄ █▄█ █ ▀█  ▀█ █▄█ █▄▄ ██▄"
    art = f"[bold bright_cyan]{w1}[/]   [bold bright_yellow]{c1}[/]\n[bold bright_cyan]{w2}[/]   [bold bright_yellow]{c2}[/]"

    content = Group(
        Align.center(art),
        meta_table,
    )

    return Panel(
        content,
        box=DEFAULT_BOX,
        border_style="header.border",
    )


def build_three_state_table(case_records: List[Dict[str, Any]] | None = None) -> Table:
    """
    Component 2: Three-State Comparative Matrix (UC-04, Table 5.3).
    Displays each test case across Direct-to-App (:8001), DetectionOnly (:8080),
    and Blocking (:8080) with explicit oracle observations and validity/verdict codes.
    """
    table = Table(
        title="Three-State Execution Matrix",
        title_justify="left",
        box=DEFAULT_BOX,
        expand=True,
        show_lines=False,
    )
    table.add_column("Case ID", style="bold white", no_wrap=True)
    table.add_column("Class / Label", no_wrap=True)
    table.add_column("1. Direct Baseline (:8001)", style="state.direct")
    table.add_column("2. DetectionOnly (:8080)", style="state.detection")
    table.add_column("3. Blocking (:8080)", style="state.blocking")
    table.add_column("Validity / Verdict", no_wrap=True)

    for row in (case_records or []):
        table.add_row(
            safe_str(row.get("case_id")),
            f"{safe_str(row.get('attack_class'))} / {safe_str(row.get('label'))}",
            safe_str(row.get("direct_summary"), "Not Executed"),
            safe_str(row.get("detection_summary"), "Not Executed"),
            safe_str(row.get("blocking_summary"), "Not Executed"),
            f"[{safe_str(row.get('validity'), 'N/A')} | {safe_str(row.get('verdict'), 'N/A')}]",
        )
    return table


def build_three_tier_inspector(evidence: Dict[str, Any] | None = None) -> Panel:
    """
    Component 3: Three-Tier Raw Evidence Inspector (UC-06, Table 4.3 & 4.6).

    Displays the correlated evidence for a single X-Request-ID across Client HTTP
    Capture, WAF Audit Telemetry, and Backend Application Oracle side-by-side.

    Args:
        evidence: Dictionary containing correlated three-tier telemetry fields.
                  Tier 1: case_id, run_id, correlation_id, state, method,
                          endpoint, request_sha256, client_status, raw_payload.
                  Tier 2: waf_txn_id, config_revision, matched_rule_ids,
                          inbound_score, inbound_threshold, disruptive_action,
                          interrupt_phase, audit_ref.
                  Tier 3: app_received, oracle_target, oracle_observation,
                          backend_effect, reset_latency_s, validity, verdict,
                          metric_cell.

    Returns:
        Panel: A master Rich Panel containing 3 side-by-side equal Columns.
    """
    if evidence is None:
        evidence = {}

    def _kv_table(pairs: List[tuple[str, str]]) -> Table:
        t = Table(box=None, show_header=False, padding=(0, 1), expand=True)
        t.add_column("Field", style="bold white", no_wrap=True, width=16)
        t.add_column("Value", overflow="fold")
        for k, v in pairs:
            t.add_row(k, v)
        return t

    raw_sha = evidence.get("request_sha256")
    sha_val = f"{safe_str(raw_sha)[:16]}..." if raw_sha else safe_str(None, "N/A")

    tier1 = Panel(
        _kv_table([
            ("Case / Run ID", f"{safe_str(evidence.get('case_id'))} / {safe_str(evidence.get('run_id'))}"),
            ("X-Request-ID", safe_str(evidence.get("correlation_id"))),
            ("State", safe_str(evidence.get("state"))),
            ("Endpoint", f"{safe_str(evidence.get('method'))} {safe_str(evidence.get('endpoint'))}"),
            ("Request SHA256", sha_val),
            ("Client Status", safe_str(evidence.get("client_status"))),
            ("Raw Payload", safe_str(evidence.get("raw_payload"))),
        ]),
        title="[bold]TIER 1: CLIENT HTTP CAPTURE[/bold]",
        box=DEFAULT_BOX,
    )

    matched_rules = evidence.get("matched_rule_ids")
    if isinstance(matched_rules, list):
        matched_rules_str = format_rule_list(matched_rules) if matched_rules else "[]"
    else:
        matched_rules_str = safe_str(matched_rules, "[]")

    tier2 = Panel(
        _kv_table([
            ("WAF Txn ID", safe_str(evidence.get("waf_txn_id"), "None (Uninspected / RelevantOnly)")),
            ("Config Rev", safe_str(evidence.get("config_revision"), "C0")),
            ("Matched Rules", matched_rules_str),
            (
                "Inbound Score",
                f"{safe_str(evidence.get('inbound_score'), '0')} (Threshold: {safe_str(evidence.get('inbound_threshold'), '5')})",
            ),
            ("Disruptive Act", safe_str(evidence.get("disruptive_action"), "None")),
            ("Interrupt Phase", safe_str(evidence.get("interrupt_phase"), "None")),
            ("Audit Ref", safe_str(evidence.get("audit_ref"), "Absent")),
        ]),
        title="[bold]TIER 2: WAF AUDIT TELEMETRY[/bold]",
        box=DEFAULT_BOX,
    )

    tier3 = Panel(
        _kv_table([
            ("App Received", safe_str(evidence.get("app_received"))),
            ("Oracle Target", safe_str(evidence.get("oracle_target"))),
            ("Oracle Obs", safe_str(evidence.get("oracle_observation"))),
            ("Backend Effect", safe_str(evidence.get("backend_effect"))),
            ("Reset Gate", f"{safe_str(evidence.get('reset_latency_s'), '0.00')}s (Limit <= 5.0s)"),
            ("Validity Code", safe_str(evidence.get("validity"), "VALID")),
            ("Final Verdict", f"{safe_str(evidence.get('verdict'))} ({safe_str(evidence.get('metric_cell'))})"),
        ]),
        title="[bold]TIER 3: APPLICATION & MOCK ORACLE[/bold]",
        box=DEFAULT_BOX,
    )

    return Panel(
        Columns([tier1, tier2, tier3], expand=True, equal=True),
        title="[bold]THREE-TIER CORRELATED EVIDENCE INSPECTOR[/bold]",
        box=DEFAULT_BOX,
    )


METRIC_FORMULA_MAP: Dict[str, str] = {
    "DR": "TP_D / (TP_D + FN_D)",
    "DETECTION RATE": "TP_D / (TP_D + FN_D)",
    "DETECTION RATE (DR)": "TP_D / (TP_D + FN_D)",
    "BR": "TP_B / (TP_B + FN_B)",
    "BLOCKING RATE": "TP_B / (TP_B + FN_B)",
    "BLOCKING RATE (BR)": "TP_B / (TP_B + FN_B)",
    "FPR_D": "FP_D / (FP_D + TN_D)",
    "DETECTION FPR": "FP_D / (FP_D + TN_D)",
    "DETECTION FPR (FPR_D)": "FP_D / (FP_D + TN_D)",
    "FALSE POSITIVE RATE (DETECTION)": "FP_D / (FP_D + TN_D)",
    "FPR_B": "FP_B / (FP_B + TN_B)",
    "BLOCKING FPR": "FP_B / (FP_B + TN_B)",
    "BLOCKING FPR (FPR_B)": "FP_B / (FP_B + TN_B)",
    "FALSE POSITIVE RATE (BLOCKING)": "FP_B / (FP_B + TN_B)",
    "RPR": "Passed / Evaluable Units",
    "REGRESSION PASS RATE": "Passed / Evaluable Units",
    "REGRESSION PASS RATE (RPR)": "Passed / Evaluable Units",
}


def _canonical_metric_name(name: Any) -> str:
    """Extract canonical metric code (DR, BR, FPR_D, FPR_B, RPR) from given name."""
    raw = str(name).strip().upper() if name else ""
    if "RPR" in raw or "REGRESSION" in raw:
        return "RPR"
    if "FPR_D" in raw or ("FPR" in raw and "DETECTION" in raw):
        return "FPR_D"
    if "FPR_B" in raw or ("FPR" in raw and "BLOCK" in raw):
        return "FPR_B"
    if "FPR" in raw:
        return "FPR_D"
    if "DR" in raw or "DETECTION" in raw:
        return "DR"
    if "BR" in raw or "BLOCK" in raw:
        return "BR"
    return raw


def _resolve_metric_row(
    item: Dict[str, Any],
    metrics: Dict[str, Any],
) -> tuple[str, str, str, Any, Any, Any, Any, Any, Any]:
    """
    Resolves formula, tallies, and rates for a single metric summary row.
    Maps canonical names (DR, BR, FPR_D, FPR_B, RPR) to mathematical formulas and tallies.
    """
    raw_name = item.get("name")
    canonical = _canonical_metric_name(raw_name)

    # 1. Formula mapping
    explicit_formula = item.get("formula")
    if explicit_formula:
        formula = str(explicit_formula)
    else:
        formula = METRIC_FORMULA_MAP.get(canonical, "N/A")

    # 2. Numerator and Denominator mapping
    num = item.get("num")
    den = item.get("den")
    rate_val = item.get("rate")

    if canonical == "DR":
        if num is None:
            num = metrics.get("tp_d", 0)
        if den is None:
            den = metrics.get("tp_d", 0) + metrics.get("fn_d", 0)
        if rate_val is None:
            rate_val = metrics.get("detection_rate")
    elif canonical == "BR":
        if num is None:
            num = metrics.get("tp_b", 0)
        if den is None:
            den = metrics.get("tp_b", 0) + metrics.get("fn_b", 0)
        if rate_val is None:
            rate_val = metrics.get("blocking_rate")
    elif canonical == "FPR_D":
        if num is None:
            num = metrics.get("fp_d", 0)
        if den is None:
            den = metrics.get("fp_d", 0) + metrics.get("tn_d", 0)
        if rate_val is None:
            rate_val = metrics.get("detection_fpr")
    elif canonical == "FPR_B":
        if num is None:
            num = metrics.get("fp_b", 0)
        if den is None:
            den = metrics.get("fp_b", 0) + metrics.get("tn_b", 0)
        if rate_val is None:
            rate_val = metrics.get("blocking_fpr")
    elif canonical == "RPR":
        if num is None:
            num = metrics.get("rpr_passed", metrics.get("pass_c1", metrics.get("rpr_num", 0)))
        if den is None:
            den = metrics.get("rpr_total", metrics.get("total_c0", metrics.get("rpr_den", 0)))
        if rate_val is None:
            rate_val = metrics.get("regression_pass_rate", metrics.get("rpr"))
    else:
        if num is None:
            num = 0
        if den is None:
            den = 0

    # 3. Execution tallies
    attempted = item.get("attempted")
    if attempted is None:
        if canonical == "RPR" and metrics.get("regression_pass_rate") is None and "rpr_attempted" not in metrics:
            attempted = 0
        else:
            attempted = metrics.get("attempted", 0)

    evaluable = item.get("evaluable")
    if evaluable is None:
        evaluable = item.get("valid")
    if evaluable is None:
        if canonical == "RPR" and metrics.get("regression_pass_rate") is None and "rpr_evaluable" not in metrics:
            evaluable = 0
        else:
            evaluable = metrics.get("valid", metrics.get("evaluable", 0))

    invalid = item.get("invalid")
    if invalid is None:
        if canonical == "RPR" and metrics.get("regression_pass_rate") is None and "rpr_invalid" not in metrics:
            invalid = 0
        else:
            invalid = metrics.get("invalid", 0)

    inconclusive = item.get("inconclusive")
    if inconclusive is None:
        if canonical == "RPR" and metrics.get("regression_pass_rate") is None and "rpr_inconclusive" not in metrics:
            inconclusive = 0
        else:
            inconclusive = metrics.get("inconclusive", 0)

    # 4. Rate string formatting
    rate_str = item.get("rate_str")
    if not rate_str:
        if rate_val is not None:
            if isinstance(rate_val, (int, float)):
                rate_str = f"{float(rate_val):.2f}%"
            else:
                rate_str = str(rate_val)
        elif den is not None and int(den) > 0 and num is not None:
            rate_str = f"{(float(num) / float(den)) * 100:.2f}%"
        else:
            rate_str = "Not Evaluated"

    display_name = raw_name if raw_name is not None else canonical

    return (
        display_name,
        formula,
        rate_str,
        num,
        den,
        attempted,
        evaluable,
        invalid,
        inconclusive,
    )


def build_metrics_summary_panel(metrics: Dict[str, Any]) -> Panel:
    """
    Component 4: Quantitative Metrics Footer (Table 5.1 & 5.2).
    Displays the exact empirical formulas with explicit numerators, denominators,
    attempted/evaluable counts, and Invalid / Inconclusive tallies.

    Reads from metrics.get("rows", []), mapping names (DR, BR, FPR_D, FPR_B, RPR)
    to their exact mathematical formula and tallies.
    """
    t = Table(box=DEFAULT_BOX, expand=True, show_header=True)
    t.add_column("Metric", style="bold white")
    t.add_column("Formula")
    t.add_column("Rate (%)", justify="right")
    t.add_column("Numerator / Denominator", justify="right")
    t.add_column("Attempted / Evaluable / Invalid / Inconcl", justify="right")

    raw_rows = metrics.get("rows")
    if raw_rows is None:
        raw_rows = [
            {"name": "DR"},
            {"name": "BR"},
            {"name": "FPR_D"},
            {"name": "FPR_B"},
            {"name": "RPR"},
        ]

    for item in raw_rows:
        (
            name,
            formula,
            rate_str,
            num,
            den,
            attempted,
            evaluable,
            invalid,
            inconclusive,
        ) = _resolve_metric_row(item, metrics)

        t.add_row(
            safe_str(name),
            safe_str(formula),
            safe_str(rate_str, "Not Evaluated"),
            f"{safe_str(num, '0')} / {safe_str(den, '0')}",
            f"{safe_str(attempted, '0')} / {safe_str(evaluable, '0')} / {safe_str(invalid, '0')} / {safe_str(inconclusive, '0')}",
        )
    return Panel(
        t,
        title="[bold]TABLE 5.2 — QUANTITATIVE EMPIRICAL METRICS SUMMARY[/bold]",
        title_align="left",
        box=DEFAULT_BOX,
    )


def test_three_tier_inspector() -> None:
    """Verification test suite for Component 3: build_three_tier_inspector."""
    from rich.console import Console
    from tui.theme import WAFBENCH_THEME

    console = Console(theme=WAFBENCH_THEME, width=120)

    # 1. SQLi malicious case blocked in State 3
    sqli_evidence = {
        "case_id": "SQLI-001",
        "run_id": "RUN-20261104-01",
        "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
        "state": "State 3 (Blocking)",
        "method": "POST",
        "endpoint": "/api/v1/login",
        "request_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "client_status": "403 Forbidden",
        "raw_payload": "admin'-- ",
        "waf_txn_id": "TXN-9876543210",
        "config_revision": "C0",
        "matched_rule_ids": ["942100", "949110"],
        "inbound_score": 10,
        "inbound_threshold": 5,
        "disruptive_action": "deny (403)",
        "interrupt_phase": "Phase 2 (Request Body)",
        "audit_ref": "audit-20261104-001.log",
        "app_received": "Prevented (Phase 2 Interrupt)",
        "oracle_target": "db:users",
        "oracle_observation": "No query executed",
        "backend_effect": "None",
        "reset_latency_s": 0.04,
        "validity": "VALID",
        "verdict": "PASS: TP_B",
        "metric_cell": "TP",
    }
    p1 = build_three_tier_inspector(sqli_evidence)
    assert isinstance(p1, Panel)
    console.print(p1)

    # 2. XSS malicious case with raw HTML payload
    xss_evidence = {
        "case_id": "XSS-001",
        "run_id": "RUN-20261104-01",
        "correlation_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "state": "State 2 (DetectionOnly)",
        "method": "GET",
        "endpoint": "/search?q=<script>alert(1)</script>",
        "request_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        "client_status": "200 OK",
        "raw_payload": "<script>alert(1)</script>",
        "waf_txn_id": "TXN-1234567890",
        "config_revision": "C0",
        "matched_rule_ids": ["941100"],
        "inbound_score": 5,
        "inbound_threshold": 5,
        "disruptive_action": "None (DetectionOnly)",
        "interrupt_phase": "None",
        "audit_ref": "audit-20261104-002.log",
        "app_received": "Received (200 OK)",
        "oracle_target": "dom:reflected",
        "oracle_observation": "Payload reflected in body",
        "backend_effect": "XSS Execution",
        "reset_latency_s": 0.02,
        "validity": "VALID",
        "verdict": "PASS: TP_D",
        "metric_cell": "TP",
    }
    p2 = build_three_tier_inspector(xss_evidence)
    assert isinstance(p2, Panel)
    console.print(p2)

    # 3. Benign traffic with single quotes and special characters
    benign_evidence = {
        "case_id": "BENIGN-001",
        "run_id": "RUN-20261104-01",
        "correlation_id": "c3d4e5f6-a7b8-9012-cdef-1234567890ab",
        "state": "State 1 (Direct-to-App)",
        "method": "GET",
        "endpoint": "/profile?name=o'brien",
        "request_sha256": "1234567890abcdef",
        "client_status": "200 OK",
        "raw_payload": "o'brien",
        "waf_txn_id": None,
        "config_revision": "C0",
        "matched_rule_ids": [],
        "inbound_score": 0,
        "inbound_threshold": 5,
        "disruptive_action": None,
        "interrupt_phase": None,
        "audit_ref": None,
        "app_received": "Received (200 OK)",
        "oracle_target": "db:users",
        "oracle_observation": "Profile loaded",
        "backend_effect": "Profile retrieved",
        "reset_latency_s": 0.01,
        "validity": "VALID",
        "verdict": "PASS: TN_D",
        "metric_cell": "TN",
    }
    p3 = build_three_tier_inspector(benign_evidence)
    assert isinstance(p3, Panel)
    console.print(p3)

    # 4. Empty evidence dict (verifying domain fallbacks)
    p4 = build_three_tier_inspector({})
    assert isinstance(p4, Panel)
    console.print(p4)

    # 5. None argument
    p5 = build_three_tier_inspector(None)
    assert isinstance(p5, Panel)

    # 6. Rejection of forbidden placeholder slop
    slop_pattern_a = chr(60) + "content>&" + chr(60) + "content" + chr(62)
    slop_evidence = {
        "case_id": "SLOP-001",
        "raw_payload": slop_pattern_a,
    }
    try:
        build_three_tier_inspector(slop_evidence)
        raise AssertionError("build_three_tier_inspector failed to reject slop pattern")
    except ValueError as exc:
        assert "Forbidden placeholder pattern detected" in str(exc)

    slop_pattern_b = "[" + "TBD]"
    slop_evidence_tbd = {
        "case_id": "SLOP-002",
        "backend_effect": slop_pattern_b,
    }
    try:
        build_three_tier_inspector(slop_evidence_tbd)
        raise AssertionError("build_three_tier_inspector failed to reject slop pattern")
    except ValueError as exc:
        assert "Forbidden placeholder pattern detected" in str(exc)

    print("[OK] build_three_tier_inspector test suite passed successfully.")


def test_build_lab_header() -> None:
    """Verification test suite for Component 1: build_lab_header."""
    import io
    import re
    from rich.console import Console
    from tui.theme import WAFBENCH_THEME

    out = io.StringIO()
    console = Console(file=out, theme=WAFBENCH_THEME, width=120)

    # 1. All 7 services healthy in DetectionOnly mode
    stack_all_up = {
        "wb-gateway": True,
        "wb-app": True,
        "wb-app-db": True,
        "wb-mock": True,
        "wb-telemetry": True,
        "wb-event-db": True,
        "wb-dashboard": True,
    }
    meta_c0 = {
        "mode": "DetectionOnly",
        "revision": "C0",
        "paranoia_level": "1",
        "inbound_threshold": "5",
        "transport": "Local Docker",
    }
    p1 = build_lab_header(stack_all_up, meta_c0)
    assert isinstance(p1, Panel)
    console.print(p1)
    text1 = out.getvalue()
    for svc in ["wb-gateway", "wb-app", "wb-app-db", "wb-mock", "wb-telemetry", "wb-event-db", "wb-dashboard"]:
        assert svc in text1, f"Service {svc} missing from header output"
    assert "[OK]" in text1
    assert "[FAIL]" not in text1
    assert "Revision: C0 (PL1 | InThresh=5)" in text1
    assert "DetectionOnly" in text1

    # 2. Mixed container statuses with strings & short names in Blocking mode
    out.seek(0)
    out.truncate(0)
    stack_mixed = {
        "gateway": "running",
        "wb-app": "healthy",
        "wb-app-db": "exited",
        "mock": False,
        "wb-telemetry": "down",
        "wb-event-db": True,
        "dashboard": "stopped",
    }
    meta_c1 = {
        "mode": "Blocking",
        "revision": "C1",
        "paranoia_level": "2",
        "inbound_threshold": "3",
        "transport": "OpenSSH Headless Tunnel",
    }
    p2 = build_lab_header(stack_mixed, meta_c1)
    assert isinstance(p2, Panel)
    console.print(p2)
    text2 = out.getvalue()
    for svc in ["wb-gateway", "wb-app", "wb-app-db", "wb-mock", "wb-telemetry", "wb-event-db", "wb-dashboard"]:
        assert svc in text2, f"Service {svc} missing from header output"
    assert "[OK]" in text2
    assert "[FAIL]" in text2
    assert "Revision: C1 (PL2 | InThresh=3)" in text2
    assert "OpenSSH" in text2 and "Tunnel" in text2

    # 3. None/empty parameters (verifying graceful fallbacks)
    p3 = build_lab_header(None, None)
    assert isinstance(p3, Panel)
    console.print(p3)

    # 4. Zero emoji audit on rendered header output
    emoji_re = re.compile(r"[\U0001F300-\U0001FAFF\u2600-\u27BF]")
    assert not emoji_re.search(text1), "Emoji found in header rendering!"
    assert not emoji_re.search(text2), "Emoji found in header rendering!"

    print("[OK] build_lab_header test suite passed successfully.")


def test_build_metrics_summary_panel() -> None:
    """Verification test suite for Component 4: build_metrics_summary_panel."""
    import io
    import re
    from rich.console import Console
    from runner.report import calculate_metrics
    from tui.theme import WAFBENCH_THEME

    out = io.StringIO()
    console = Console(file=out, theme=WAFBENCH_THEME, width=120)

    # 1. Verification of mock rows mapping names (DR, BR, FPR_D, FPR_B, RPR) to formulas & tallies
    mock_metrics = {
        "rows": [
            {"name": "DR"},
            {"name": "BR"},
            {"name": "FPR_D"},
            {"name": "FPR_B"},
            {"name": "RPR"},
        ],
        "attempted": 96,
        "valid": 90,
        "invalid": 2,
        "inconclusive": 4,
        "tp_d": 12,
        "fn_d": 4,
        "tp_b": 14,
        "fn_b": 2,
        "fp_d": 1,
        "tn_d": 15,
        "fp_b": 2,
        "tn_b": 14,
        "detection_rate": 75.0,
        "blocking_rate": 87.5,
        "detection_fpr": 6.25,
        "blocking_fpr": 12.5,
    }
    p1 = build_metrics_summary_panel(mock_metrics)
    assert isinstance(p1, Panel)
    assert p1.title == "[bold]TABLE 5.2 — QUANTITATIVE EMPIRICAL METRICS SUMMARY[/bold]"
    t1 = p1.renderable
    assert isinstance(t1, Table)
    headers = [col.header for col in t1.columns]
    assert headers == [
        "Metric",
        "Formula",
        "Rate (%)",
        "Numerator / Denominator",
        "Attempted / Evaluable / Invalid / Inconcl",
    ]
    assert t1.columns[0]._cells == ["DR", "BR", "FPR_D", "FPR_B", "RPR"]
    assert t1.columns[1]._cells == [
        "TP_D / (TP_D + FN_D)",
        "TP_B / (TP_B + FN_B)",
        "FP_D / (FP_D + TN_D)",
        "FP_B / (FP_B + TN_B)",
        "Passed / Evaluable Units",
    ]
    assert t1.columns[2]._cells == ["75.00%", "87.50%", "6.25%", "12.50%", "Not Evaluated"]
    assert t1.columns[3]._cells == ["12 / 16", "14 / 16", "1 / 16", "2 / 16", "0 / 0"]
    assert t1.columns[4]._cells == [
        "96 / 90 / 2 / 4",
        "96 / 90 / 2 / 4",
        "96 / 90 / 2 / 4",
        "96 / 90 / 2 / 4",
        "0 / 0 / 0 / 0",
    ]

    # 2. Verification with real metrics structure directly from runner/report.py calculate_metrics()
    mock_results = [
        {"case_id": "SQLI-001", "state": "DetectionOnly", "validity": "VALID", "metric_cell": "TP_D"},
        {"case_id": "SQLI-002", "state": "DetectionOnly", "validity": "VALID", "metric_cell": "FN_D"},
        {"case_id": "BENIGN-001", "state": "DetectionOnly", "validity": "VALID", "metric_cell": "TN_D"},
        {"case_id": "BENIGN-002", "state": "DetectionOnly", "validity": "VALID", "metric_cell": "FP_D"},
        {"case_id": "SQLI-001", "state": "Blocking", "validity": "VALID", "metric_cell": "TP_B"},
        {"case_id": "SQLI-002", "state": "Blocking", "validity": "VALID", "metric_cell": "FN_B"},
        {"case_id": "BENIGN-001", "state": "Blocking", "validity": "VALID", "metric_cell": "TN_B"},
        {"case_id": "BENIGN-002", "state": "Blocking", "validity": "VALID", "metric_cell": "FP_B"},
        {"case_id": "ERR-001", "state": "Blocking", "validity": "E_HEALTH", "metric_cell": "INVALID"},
        {"case_id": "INC-001", "state": "Blocking", "validity": "I_UNSTABLE", "metric_cell": "INCONCLUSIVE"},
    ]
    real_metrics = calculate_metrics(mock_results)
    assert "rows" not in real_metrics
    p2 = build_metrics_summary_panel(real_metrics)
    assert isinstance(p2, Panel)
    t2 = p2.renderable
    assert t2.columns[0]._cells == ["DR", "BR", "FPR_D", "FPR_B", "RPR"]
    assert t2.columns[1]._cells == [
        "TP_D / (TP_D + FN_D)",
        "TP_B / (TP_B + FN_B)",
        "FP_D / (FP_D + TN_D)",
        "FP_B / (FP_B + TN_B)",
        "Passed / Evaluable Units",
    ]
    assert t2.columns[2]._cells == ["50.00%", "50.00%", "50.00%", "50.00%", "Not Evaluated"]
    assert t2.columns[3]._cells == ["1 / 2", "1 / 2", "1 / 2", "1 / 2", "0 / 0"]
    assert t2.columns[4]._cells == [
        "10 / 8 / 1 / 1",
        "10 / 8 / 1 / 1",
        "10 / 8 / 1 / 1",
        "10 / 8 / 1 / 1",
        "0 / 0 / 0 / 0",
    ]

    # 3. Verification of empty metrics {} and empty rows {"rows": []}
    p_empty = build_metrics_summary_panel({})
    assert isinstance(p_empty, Panel)
    assert p_empty.renderable.columns[2]._cells == ["Not Evaluated"] * 5

    p_explicit_empty = build_metrics_summary_panel({"rows": []})
    assert isinstance(p_explicit_empty, Panel)
    assert len(p_explicit_empty.renderable.columns[0]._cells) == 0

    # 4. Zero emoji audit on rendered panel
    console.print(p1)
    console.print(p2)
    rendered_text = out.getvalue()
    emoji_re = re.compile(r"[\U0001F300-\U0001FAFF\u2600-\u27BF]")
    assert not emoji_re.search(rendered_text), "Emoji found in metrics summary rendering!"

    print("[OK] build_metrics_summary_panel test suite passed successfully.")


if __name__ == "__main__":
    test_build_lab_header()
    test_build_metrics_summary_panel()
    test_three_tier_inspector()
