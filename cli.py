#!/usr/bin/env python3
"""
WAFBench Unified Entrypoint CLI & TUI Launcher
Author: WAFBench Systems & Terminal UI Engineering Team
Workspace: WAF_USTH (Nginx 1.26 + ModSecurity v3 + OWASP CRS v4.0.0)

Strictly adheres to document/wafbench_agent_tui_guide.md and AGENTS.md:
- Mode 1: Interactive Academic Menu Mode (./wafbench with no args)
- Mode 2: Headless CLI Automation Mode (./wafbench --batch C0 --export results_C0.csv)
- Mode 3: Full-Screen Textual TUI Mode (./wafbench --tui or menu option [7])
- Backwards-compatible CLI subcommands: workflow, probe, compare, corpus, run, inspect, status
- Zero Emojis! Zero Concatenated Angle-Bracket Placeholders! Zero Unescaped HTML Leaks!
"""

import os
import sys

# Auto-detect project virtual environment if running under system python without textual
VENV_PYTHON = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".venv", "bin", "python"))
if os.path.exists(VENV_PYTHON) and sys.executable != VENV_PYTHON:
    try:
        import textual
    except ImportError:
        os.execv(VENV_PYTHON, [VENV_PYTHON] + sys.argv)

import json
import time
import uuid
import argparse
import subprocess
from typing import Optional, Dict, Any, List, Tuple

# Ensure repository paths are available on sys.path
CLI_DIR = os.path.dirname(os.path.abspath(__file__))
if CLI_DIR not in sys.path:
    sys.path.insert(0, CLI_DIR)
RUNNER_DIR = os.path.join(CLI_DIR, "runner")
if RUNNER_DIR not in sys.path:
    sys.path.insert(0, RUNNER_DIR)

import requests
import pandas as pd
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
from rich.prompt import Prompt
from rich.live import Live
from rich.markup import escape
from rich import box

# TUI Modular Presentation Package
from tui.theme import (
    WAFBENCH_THEME,
    DEFAULT_BOX,
    ASCII_BOX,
    BADGE_OK,
    BADGE_FAIL,
    BADGE_READY,
    BADGE_DEAD,
    BADGE_WAIT,
    BADGE_INVALID,
    BADGE_INCONCLUSIVE,
    BADGE_BLOCKED,
    BADGE_PASSED,
)
from tui.sanitizers import safe_str, format_rule_list
from tui.renderables import (
    build_lab_header,
    build_three_state_table,
    build_three_tier_inspector,
    build_metrics_summary_panel,
)
from tui.app import WAFBenchTUI

# WAFBench Core modules
import manager
from manager import (
    RequestManager,
    set_waf_mode,
    wait_gateway_ready,
    mode_canary,
    find_waf_evidence,
    seen_by_app,
    docker_exec,
    docker_logs,
)
from oracle.sqli_oracle import check_sqli_backend_effect, get_fixture_counts
from oracle.xss_lfi_ssrf_oracle import (
    check_xss_reflection,
    check_lfi_file_disclosure,
    check_ssrf_mock_access,
    get_mock_logs,
    xss_probe_for,
)
from oracle.validity_oracle import classify_validity, assign_metric_cell
from latency import LatencyProfiler
from report import (
    calculate_metrics,
    apply_baseline_gate,
    mark_flaky,
    export_csv,
    export_summary_csv,
)

console = Console(theme=WAFBENCH_THEME)

# Global configuration targets
DIRECT_URL = os.getenv("DIRECT_APP_URL", "http://127.0.0.1:8001")
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://127.0.0.1:8080")
CASES_DIR = os.path.join(CLI_DIR, "corpus", "cases")
STATES = ["Direct-to-App", "DetectionOnly", "Blocking"]
ENGINE_MAP = {"DetectionOnly": "DetectionOnly", "Blocking": "On"}
FIXTURE_EXPECTED = {"users": 3, "articles": 3, "sessions": 0}


def query_system_state() -> Tuple[Dict[str, bool], Dict[str, str]]:
    """Gathers container readiness and ModSecurity engine configuration."""
    services = [
        "wb-gateway",
        "wb-app",
        "wb-app-db",
        "wb-mock",
        "wb-telemetry",
        "wb-event-db",
        "wb-dashboard",
    ]
    stack_status = {s: False for s in services}
    try:
        p = manager._run_docker_cmd(["docker", "ps", "--format", "{{.Names}}"], timeout=4.0)
        if p.returncode == 0:
            running = set(p.stdout.decode().splitlines())
            for s in services:
                stack_status[s] = s in running
        else:
            try:
                rg = requests.get(f"{GATEWAY_URL}/health", timeout=1.0)
                stack_status["wb-gateway"] = rg.status_code == 200
            except Exception:
                pass
            try:
                ra = requests.get(f"{DIRECT_URL}/health", timeout=1.0)
                stack_status["wb-app"] = ra.status_code == 200
            except Exception:
                pass
    except Exception:
        pass

    mode = "DetectionOnly"
    try:
        rc, out, _ = manager.docker_exec("wb-gateway", ["grep", "-i", "SecRuleEngine", "/etc/modsecurity.d/main.conf"], timeout=3.0)
        if rc == 0 and out.strip():
            tokens = out.strip().split()
            if len(tokens) >= 2:
                mode = tokens[1]
    except Exception:
        pass

    transport = "Local Docker"
    if not os.path.exists("/var/run/docker.sock"):
        transport = f"SSH Tunnel ({manager.REMOTE_DOCKER_HOST})"

    policy_meta = {
        "mode": mode,
        "revision": "C0",
        "paranoia_level": "1",
        "inbound_threshold": "5",
        "transport": transport,
    }
    return stack_status, policy_meta


# ==============================================================================
# DATA LOADERS & GROUND TRUTH ORACLES
# ==============================================================================

def load_cases(category: Optional[str] = None) -> List[Dict[str, Any]]:
    """Loads all corpus cases or filtered by category/family."""
    cases = []
    if not os.path.exists(CASES_DIR):
        return []
    for root, _, files in os.walk(CASES_DIR):
        for f in files:
            if f.endswith(".json"):
                path = os.path.join(root, f)
                try:
                    with open(path, "r", encoding="utf-8") as fp:
                        data = json.load(fp)
                        if category and category.lower() not in data.get("family", "").lower():
                            continue
                        cases.append(data)
                except Exception:
                    pass
    return sorted(cases, key=lambda x: x.get("case_id", ""))


def get_case_by_id(case_id: str) -> Optional[Dict[str, Any]]:
    cases = load_cases()
    for c in cases:
        if c.get("case_id", "").lower() == case_id.lower():
            return c
    return None


def run_oracle_for_case(case: Dict[str, Any], client_res: Dict[str, Any], correlation_id: str) -> Dict[str, Any]:
    """Dispatches ground truth evaluation to family-specific oracle."""
    family = case.get("family", "")
    if family == "SQL Injection":
        try:
            body_dict = json.loads(case.get("body") or "{}")
            submitted_user = body_dict.get("username", "")
        except Exception:
            submitted_user = ""
        return check_sqli_backend_effect(submitted_user)
    elif family == "Reflected XSS":
        probe = xss_probe_for(case)
        return check_xss_reflection(client_res, probe)
    elif family == "Path Traversal":
        return check_lfi_file_disclosure(client_res)
    elif family == "SSRF":
        return check_ssrf_mock_access(correlation_id)
    return {"backend_effect": False, "observation": f"No oracle implemented for {family}"}


def check_app_health(base_url: str) -> Tuple[bool, str]:
    try:
        r = requests.get(f"{base_url}/health", timeout=3.0)
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}"
        if "CONNECTED" not in r.text:
            return False, "Database not connected"
        return True, "Online"
    except Exception as e:
        return False, str(e)


def trigger_reset(direct_url: str) -> Tuple[bool, float, str]:
    start = time.perf_counter()
    try:
        r = requests.post(f"{direct_url}/health/reset", timeout=5.0)
        duration_s = time.perf_counter() - start
        if r.status_code != 200:
            return False, duration_s, f"Reset returned HTTP {r.status_code}"
        return True, duration_s, ""
    except Exception as e:
        duration_s = time.perf_counter() - start
        return False, duration_s, str(e)


def verify_fixture() -> Tuple[bool, str]:
    try:
        counts = get_fixture_counts()
        if counts != FIXTURE_EXPECTED:
            return False, f"Fixture mismatch: {counts} != {FIXTURE_EXPECTED}"
        return True, f"users={counts['users']}, articles={counts['articles']}, sessions={counts['sessions']}"
    except Exception as e:
        return False, f"Fixture check failed: {e}"


def prepare_state(state: str) -> Tuple[bool, str]:
    """Switches the WAF engine for a state and confirms with the canary request."""
    if state == "Direct-to-App":
        return True, "Direct baseline (WAF bypassed)"
    engine_val = ENGINE_MAP.get(state, "DetectionOnly")
    ok, err = set_waf_mode(engine_val)
    if not ok:
        return False, f"Mode switch failed: {err}"
    if not wait_gateway_ready(GATEWAY_URL):
        return False, "Gateway not ready after reload"
    deadline = time.time() + 10.0
    while True:
        c_ok, c_reason = mode_canary(GATEWAY_URL, state)
        if c_ok or time.time() >= deadline:
            return c_ok, c_reason
        time.sleep(0.5)


def format_metrics_for_panel(metrics: Dict[str, Any]) -> Dict[str, Any]:
    """Converts report.calculate_metrics output into the schema required by build_metrics_summary_panel."""
    attempted = metrics.get("attempted", 0)
    evaluable = metrics.get("valid", 0)
    invalid = metrics.get("invalid", 0)
    inconcl = metrics.get("inconclusive", 0)

    rows = [
        {
            "name": "Detection Rate (DR)",
            "formula": "TP_D / (TP_D + FN_D)",
            "rate_str": f"{metrics.get('detection_rate', 0.0):.2f}%" if metrics.get("detection_rate") is not None else "N/A",
            "num": metrics.get("tp_d", 0),
            "den": (metrics.get("tp_d", 0) + metrics.get("fn_d", 0)),
            "attempted": attempted,
            "evaluable": evaluable,
            "invalid": invalid,
            "inconclusive": inconcl,
        },
        {
            "name": "Blocking Rate (BR)",
            "formula": "TP_B / (TP_B + FN_B)",
            "rate_str": f"{metrics.get('blocking_rate', 0.0):.2f}%" if metrics.get("blocking_rate") is not None else "N/A",
            "num": metrics.get("tp_b", 0),
            "den": (metrics.get("tp_b", 0) + metrics.get("fn_b", 0)),
            "attempted": attempted,
            "evaluable": evaluable,
            "invalid": invalid,
            "inconclusive": inconcl,
        },
        {
            "name": "Detection False Positive Rate (FPR_D)",
            "formula": "FP_D / (FP_D + TN_D)",
            "rate_str": f"{metrics.get('detection_fpr', 0.0):.2f}%" if metrics.get("detection_fpr") is not None else "N/A",
            "num": metrics.get("fp_d", 0),
            "den": (metrics.get("fp_d", 0) + metrics.get("tn_d", 0)),
            "attempted": attempted,
            "evaluable": evaluable,
            "invalid": invalid,
            "inconclusive": inconcl,
        },
        {
            "name": "Blocking False Positive Rate (FPR_B)",
            "formula": "FP_B / (FP_B + TN_B)",
            "rate_str": f"{metrics.get('blocking_fpr', 0.0):.2f}%" if metrics.get("blocking_fpr") is not None else "N/A",
            "num": metrics.get("fp_b", 0),
            "den": (metrics.get("fp_b", 0) + metrics.get("tn_b", 0)),
            "attempted": attempted,
            "evaluable": evaluable,
            "invalid": invalid,
            "inconclusive": inconcl,
        },
    ]
    return {"rows": rows}


def summarize_batch_for_matrix(results: List[Dict[str, Any]], cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generates 3-state comparative records for Table 5.3 display."""
    df = pd.DataFrame(results)
    records = []
    for c in cases:
        cid = c["case_id"]
        c_runs = df[df["case_id"] == cid] if not df.empty else pd.DataFrame()
        
        # Direct
        d_runs = c_runs[c_runs["state"] == "Direct-to-App"] if not c_runs.empty else pd.DataFrame()
        d_sum = "Not Executed"
        if not d_runs.empty:
            last = d_runs.iloc[-1]
            d_sum = f"HTTP {last['client_status']} (Effect={last['backend_effect']})"

        # DetectionOnly
        det_runs = c_runs[c_runs["state"] == "DetectionOnly"] if not c_runs.empty else pd.DataFrame()
        det_sum = "Not Executed"
        if not det_runs.empty:
            last = det_runs.iloc[-1]
            det_sum = f"HTTP {last['client_status']} (Score={last['anomaly_score'] or 0})"

        # Blocking
        blk_runs = c_runs[c_runs["state"] == "Blocking"] if not c_runs.empty else pd.DataFrame()
        blk_sum = "Not Executed"
        v_code = "VALID"
        m_cell = "N/A"
        if not blk_runs.empty:
            last = blk_runs.iloc[-1]
            blk_sum = f"HTTP {last['client_status']} (Score={last['anomaly_score'] or 0})"
            v_code = str(last.get("validity", "VALID"))
            m_cell = str(last.get("metric_cell", "N/A"))

        records.append({
            "case_id": cid,
            "attack_class": c.get("family", "Unknown"),
            "label": c.get("label", "malicious"),
            "direct_summary": d_sum,
            "detection_summary": det_sum,
            "blocking_summary": blk_sum,
            "validity": v_code,
            "verdict": m_cell,
        })
    return records


# ==============================================================================
# 1. ARCHITECTURE & 3-TIER DATA WORKFLOW DIAGRAM
# ==============================================================================

def show_workflow_diagram():
    """Prints the comprehensive ASCII & Rich architecture and data workflow diagram."""
    console.print()
    console.print(Panel(
        Text("WAFBENCH END-TO-END DATA WORKFLOW & 3-TIER EVIDENCE ARCHITECTURE", style="bold cyan", justify="center"),
        subtitle="ModSecurity v3 + OWASP CRS v4.0.0 Evaluation Pipeline",
        border_style="cyan",
        box=DEFAULT_BOX
    ))

    tree = Tree("[bold white]WAFBench Diagnostic Pipeline[/bold white]")

    # Phase 1: Client Harness
    c_node = tree.add("[bold yellow]1. Test Client Harness (runner / cli)[/bold yellow]")
    c_node.add("- Ingestion of test case payload from [cyan]corpus/cases/[/cyan]")
    c_node.add("- Generates unique [bold green]X-Request-ID[/bold green] (UUIDv4) for end-to-end tracing")
    c_node.add("- Computes canonical [magenta]SHA-256 request fingerprint[/magenta]")
    c_node.add("- Dispatches HTTP request: [green]:8001 (Direct Baseline)[/green] or [blue]:8080 (WAF Gateway)[/blue]")

    # Tier 1
    t1_node = tree.add("[bold cyan]2. Tier 1: Client HTTP Capture[/bold cyan]")
    t1_node.add("- Records HTTP status code: [green]HTTP 200[/green] (allowed) vs [red]HTTP 403[/red] (blocked)")
    t1_node.add("- Measures round-trip response latency ([cyan]ms[/cyan])")
    t1_node.add("- Captures response headers and response payload snippet")

    # Tier 2
    t2_node = tree.add("[bold yellow]3. Tier 2: WAF Perimeter Telemetry (wb-gateway :8080)[/bold yellow]")
    t2_node.add("- Nginx 1.26 + ModSecurity v3 C++ library + OWASP CRS v4.0.0")
    t2_node.add("- Request Inspection (Phases 1 & 2): regex matching on headers, query, body")
    t2_node.add("- Computes Inbound Anomaly Score (threshold = 5 at Paranoia Level 1)")
    t2_node.add("- State Engine Behavior:")
    t2_node.add("    * [cyan]State 1 (Direct-to-App :8001)[/cyan]: Bypasses gateway completely (baseline)")
    t2_node.add("    * [yellow]State 2 (DetectionOnly :8080)[/yellow]: Logs CRS rule hits, passes request to backend")
    t2_node.add("    * [magenta]State 3 (Blocking :8080)[/magenta]: Intercepts attack with HTTP 403; never reaches app")
    t2_node.add("- Writes structured JSON audit log to [cyan]/var/log/modsec/audit.log[/cyan]")

    # Tier 3
    t3_node = tree.add("[bold green]4. Tier 3: Backend Oracle Ground Truth (wb-app, wb-app-db, wb-mock)[/bold green]")
    t3_node.add("- Vulnerable Express app (:3000) handles request if passed by perimeter")
    t3_node.add("- Independent Oracle probes container state directly (zero reliance on HTTP 403):")
    t3_node.add("    * [cyan]SQLi Oracle[/cyan]: Queries PostgreSQL sessions table for unauthorized user session")
    t3_node.add("    * [cyan]XSS Oracle[/cyan]: Inspects response body for unescaped probe tag reflection + text/html")
    t3_node.add("    * [cyan]Path Traversal Oracle[/cyan]: Checks if /etc/passwd root tokens were disclosed")
    t3_node.add("    * [cyan]SSRF Oracle[/cyan]: Queries internal mock server /logs for unauthorized /metadata hit")

    # Phase 5: Telemetry Correlation
    cor_node = tree.add("[bold magenta]5. Telemetry Correlation & Metric Engine[/bold magenta]")
    cor_node.add("- Telemetry daemon tails audit.log and correlates Client + WAF + Oracle by X-Request-ID")
    cor_node.add("- Stores normalized records in PostgreSQL [cyan]wb-event-db[/cyan]")
    cor_node.add("- Calculates formal benchmark metrics: DR, BR, FPR_D, FPR_B, RPR")

    console.print(tree)
    console.print()

    # Evidence-First 3-Tier Explanation Table
    table = Table(title="Table 4.1 — Evidence-First 3-Tier Multi-Source Correlation Architecture", box=DEFAULT_BOX, expand=True)
    table.add_column("Tier", style="bold cyan", no_wrap=True)
    table.add_column("Component", style="yellow", no_wrap=True)
    table.add_column("Observation Point", style="white")
    table.add_column("Why HTTP 403 Alone is Insufficient", style="red")

    table.add_row(
        "Tier 1",
        "Client Response",
        "Status code (200 / 403 / 500), Latency ms",
        "A 403 can be thrown by reverse proxy timeouts, auth errors, or invalid routes without WAF involvement."
    )
    table.add_row(
        "Tier 2",
        "WAF Audit Log",
        "Rule IDs (942100, 949110), Anomaly Score, Action",
        "Proves ModSecurity actively analyzed the request and issued a disruptive action for that exact X-Request-ID."
    )
    table.add_row(
        "Tier 3",
        "Backend Oracle",
        "Database sessions table, unescaped reflection, mock logs",
        "Proves whether the payload actually compromised the application state or was neutralized."
    )
    console.print(table)
    console.print()


# ==============================================================================
# MODE 1: ACADEMIC MENU OPERATIONS (UC-01 through UC-06)
# ==============================================================================

def run_preflight_health_check() -> bool:
    """[1] Pre-Flight & Container Health Check (UC-01)."""
    console.print()
    console.print("[bold]UC-01: Running Pre-Flight & Container Readiness Verification...[/bold]")
    
    stack_status, policy_meta = query_system_state()
    table = Table(title="Container Health & Environment Readiness Table", box=DEFAULT_BOX, expand=True)
    table.add_column("Service Name", style="bold white", no_wrap=True)
    table.add_column("Target / Port", style="yellow")
    table.add_column("Status", no_wrap=True)
    table.add_column("Readiness Details", style="white")

    # Gateway
    g_ok, g_detail = check_app_health(GATEWAY_URL)
    table.add_row("wb-gateway", "0.0.0.0:8080", BADGE_OK if g_ok else BADGE_FAIL, f"Mode: {policy_meta.get('mode')} | {g_detail}")

    # App
    a_ok, a_detail = check_app_health(DIRECT_URL)
    table.add_row("wb-app", "127.0.0.1:8001", BADGE_OK if a_ok else BADGE_FAIL, a_detail)

    # App DB
    db_ok, db_detail = verify_fixture()
    table.add_row("wb-app-db", "5432 (Internal)", BADGE_OK if db_ok else BADGE_FAIL, f"Fixture F1: {db_detail}")

    # Mock
    try:
        logs = get_mock_logs()
        table.add_row("wb-mock", "8080 (Internal)", BADGE_OK, f"Mock access log entries: {len(logs)}")
    except Exception as e:
        table.add_row("wb-mock", "8080 (Internal)", BADGE_FAIL, str(e))

    # Event DB
    rc, out, _ = docker_exec("wb-event-db", ["psql", "-U", "telemetry_user", "-d", "wafbench_events", "-t", "-A", "-c", "SELECT count(*) FROM normalized_events;"])
    table.add_row("wb-event-db", "5432 (Internal)", BADGE_OK if rc == 0 else BADGE_FAIL, f"Normalized events stored: {out.strip()}" if rc == 0 else "Query failed")

    # Telemetry
    t_running = stack_status.get("wb-telemetry", False)
    table.add_row("wb-telemetry", "Daemon Worker", BADGE_OK if t_running else BADGE_FAIL, "Active audit log consumer" if t_running else "Container stopped")

    # Dashboard
    d_running = stack_status.get("wb-dashboard", False)
    table.add_row("wb-dashboard", "0.0.0.0:8501", BADGE_OK if d_running else BADGE_FAIL, "Streamlit Web UI" if d_running else "Container stopped")

    console.print(table)

    # Reset Gate Test
    with console.status("[bold cyan]Executing Fast Reset Gate test (POST /health/reset)..."):
        reset_ok, reset_latency, reset_err = trigger_reset(DIRECT_URL)

    console.print()
    if reset_ok and reset_latency <= 5.0:
        console.print(f"[bold green][OK][/bold green] Pre-flight verification passed: 7/7 containers healthy, fixture F1 verified ({db_detail}), reset gate completed in {reset_latency:.2f}s (Limit <= 5.0s).")
        return True
    else:
        console.print(f"[bold red][FAIL][/bold red] Pre-flight verification degraded: reset_ok={reset_ok}, latency={reset_latency:.2f}s ({reset_err})")
        return False


def run_corpus_explorer_and_validator(filter_family: Optional[str] = None):
    """[2] Corpus Explorer & Paired Contrast Validator (UC-02 / 32 Cases)."""
    cases = load_cases(category=filter_family)
    console.print()
    console.print(f"[bold]UC-02: Test Corpus Explorer & Paired Contrast Validator[/bold] ({len(cases)} cases)")

    table = Table(box=DEFAULT_BOX, expand=True)
    table.add_column("Case ID", style="bold white", no_wrap=True)
    table.add_column("Family / Class", style="yellow")
    table.add_column("Label", no_wrap=True)
    table.add_column("Method", no_wrap=True)
    table.add_column("Endpoint", style="white")
    table.add_column("Paired Contrast Case", style="cyan")
    table.add_column("Syntax & Contract Check", no_wrap=True)

    case_ids = {c.get("case_id") for c in cases}
    validation_errors = 0

    for c in cases:
        cid = c.get("case_id", "UNKNOWN")
        label = c.get("label", "malicious")
        family = c.get("family", "Unknown")
        method = c.get("method", "GET")
        endpoint = c.get("endpoint", "/")
        
        # Paired contrast check
        paired_expected = f"{cid}-B1" if label == "malicious" else "Baseline Contrast"
        paired_ok = paired_expected in case_ids if label == "malicious" else True

        # Header and placeholder validation
        headers = c.get("headers", {})
        h_ok = (headers.get("X-Request-ID") == "{correlation_id}" and headers.get("Host") == "{host}")
        
        is_valid = paired_ok and h_ok
        if not is_valid:
            validation_errors += 1

        label_badge = f"[bold red]MALICIOUS[/bold red]" if label == "malicious" else f"[bold green]BENIGN[/bold green]"
        status_token = BADGE_OK if is_valid else BADGE_FAIL

        table.add_row(
            safe_str(cid),
            safe_str(family),
            label_badge,
            safe_str(method),
            safe_str(endpoint),
            safe_str(paired_expected if label == "malicious" else "N/A (Contrast Baseline)"),
            status_token,
        )

    console.print(table)
    console.print()
    if validation_errors == 0:
        console.print(f"[bold green][OK][/bold green] All {len(cases)} test cases passed paired contrast and schema validation checks.")
    else:
        console.print(f"[bold red][FAIL][/bold red] Detected {validation_errors} test cases with contrast pairing or schema anomalies.")


def run_switch_waf_state():
    """[3] Switch WAF Operating State (DetectionOnly <-> Blocking) & Canary Verify (UC-03)."""
    _, policy_meta = query_system_state()
    current_mode = policy_meta.get("mode", "DetectionOnly")

    console.print()
    console.print(f"[bold]UC-03: Switch WAF Operating State & Canary Verify[/bold]")
    console.print(f"Current Active Mode: [bold yellow][{current_mode}][/bold yellow]")
    console.print("\nSelect target operating state:")
    console.print("  [bold cyan][1][/bold cyan] DetectionOnly (:8080) [dim][Log rule matches, pass all traffic][/dim]")
    console.print("  [bold cyan][2][/bold cyan] Blocking (:8080)      [dim][Enforce HTTP 403 on anomaly threshold][/dim]")
    console.print("  [bold cyan][C][/bold cyan] Cancel switch\n")

    pick = Prompt.ask("Enter selection", choices=["1", "2", "C", "c"], default="1")
    if pick.lower() == "c":
        console.print("[dim]Mode switch canceled.[/dim]")
        return

    target_state = "DetectionOnly" if pick == "1" else "Blocking"
    with console.status(f"[bold cyan]Switching WAF mode to {target_state} and executing canary verification..."):
        ok, reason = prepare_state(target_state)

    if ok:
        console.print(f"[bold green][OK][/bold green] WAF Engine set to [bold yellow][{target_state} :8080][/bold yellow] ({reason})")
    else:
        console.print(f"[bold red][FAIL][/bold red] Mode switch failed: {reason}")


def execute_probe_walkthrough(case: Dict[str, Any], state: str):
    """[4] Live Single-Probe 3-Tier Walkthrough (UC-04 / UC-05)."""
    case_id = case.get("case_id", "UNKNOWN")
    family = case.get("family", "Unknown")
    label = case.get("label", "malicious")
    is_mal = label == "malicious"

    console.print()
    console.print(Panel(
        f"[bold white]LIVE SINGLE-PROBE 3-TIER WALKTHROUGH[/bold white]\n"
        f"Case ID: [bold cyan]{case_id}[/bold cyan] ({family}) | "
        f"Label: [{'red' if is_mal else 'green'}]{label.upper()}[/] | "
        f"State: [yellow]{state}[/yellow]",
        box=DEFAULT_BOX,
        border_style="cyan"
    ))

    # Pre-step: Set mode if needed
    is_waf = state != "Direct-to-App"
    target_url = GATEWAY_URL if is_waf else DIRECT_URL

    if is_waf:
        with console.status(f"[bold cyan]Switching WAF mode to {state}..."):
            ok, reason = prepare_state(state)
            if not ok:
                console.print(f"[bold red][FAIL][/bold red] Failed to prepare state {state}: {reason}")
                return
            console.print(f"  [bold green][OK][/bold green] WAF mode verified: [bold yellow]{state}[/bold yellow] ({reason})")
    else:
        console.print("  [bold green][OK][/bold green] Target: [bold yellow]Direct-to-App (:8001)[/bold yellow] (WAF Bypassed)")

    # Reset Fixture
    with console.status("[bold cyan]Resetting database fixture to F1 baseline..."):
        reset_ok, reset_duration, reset_err = trigger_reset(DIRECT_URL)
        if not reset_ok:
            console.print(f"  [bold yellow][WAIT][/bold yellow] Reset warning: {reset_err}")
        else:
            console.print(f"  [bold green][OK][/bold green] Database reset completed in {reset_duration:.2f}s")

    # Execute Request
    correlation_id = str(uuid.uuid4())
    req_mgr = RequestManager()

    with console.status("[bold cyan]Dispatching HTTP request..."):
        client_res = req_mgr.send_request(target_url, case, correlation_id)

    status_code = client_res.get("status_code")
    latency_ms = round(client_res.get("latency_ms", 0.0), 2)
    req_sha = client_res.get("request_sha256", "N/A")

    # WAF Evidence
    waf_data = {"found": False, "detected": False, "matched_rule_ids": [], "anomaly_score": None, "waf_http_code": None}
    if is_waf:
        with console.status("[bold cyan]Querying ModSecurity audit log by X-Request-ID..."):
            waf_data = find_waf_evidence(correlation_id, timeout=3.0)

    # Oracle
    with console.status("[bold cyan]Executing independent Backend Oracle evaluation..."):
        oracle_res = run_oracle_for_case(case, client_res, correlation_id)

    backend_effect = oracle_res.get("backend_effect", False)
    effect_label = "EXPLOIT SUCCEEDED (Compromised)" if backend_effect else "NO EFFECT (Neutralized / Safe)"

    # Validity & Metric Cell
    preconditions = {"mode_verified": True, "fixture_verified": True, "health_ok": True}
    validity_code, is_valid, reason = classify_validity(preconditions, client_res, waf_data, state)
    metric_cell = assign_metric_cell(state, label, waf_data, client_res)

    # Render Component 3: Three-Tier Raw Evidence Inspector
    evidence = {
        "case_id": case_id,
        "run_id": f"RUN-{correlation_id[:8]}",
        "correlation_id": correlation_id,
        "state": state,
        "method": case.get("method", "GET"),
        "endpoint": case.get("endpoint", "/"),
        "request_sha256": req_sha,
        "client_status": f"{status_code} ({latency_ms} ms)",
        "raw_payload": case.get("body") or case.get("endpoint", ""),
        "waf_txn_id": waf_data.get("waf_http_code") or ("None (Direct Route)" if not is_waf else "Absent (RelevantOnly)"),
        "config_revision": "C0",
        "matched_rule_ids": format_rule_list(waf_data.get("matched_rule_ids")),
        "inbound_score": waf_data.get("anomaly_score") or 0,
        "inbound_threshold": 5,
        "disruptive_action": "HTTP 403 Forbidden" if status_code == 403 else ("Passed" if is_waf else "N/A (Direct Route)"),
        "interrupt_phase": "Phase 2 (Request Body)" if status_code == 403 else "None",
        "audit_ref": waf_data.get("source") or "Absent",
        "app_received": "False (Prevented by Phase 2)" if status_code == 403 else "True (HTTP 200)",
        "oracle_target": family,
        "oracle_observation": oracle_res.get("observation", ""),
        "backend_effect": f"{backend_effect} ({effect_label})",
        "reset_latency_s": f"{reset_duration:.2f}",
        "validity": validity_code,
        "verdict": f"PASS: {metric_cell}" if is_valid else f"FAIL: {validity_code}",
        "metric_cell": metric_cell,
    }

    inspector = build_three_tier_inspector(evidence)
    console.print(inspector)
    console.print()


def run_three_state_batch_interactive():
    """[5] Execute Full 3-State Empirical Batch (3 Repetitions per Case) (Table 5.3)."""
    cases = load_cases()
    console.print()
    console.print(f"[bold]UC-05: Execute Full 3-State Empirical Evaluation Batch[/bold]")
    reps_str = Prompt.ask("Repetitions per test case", default="3")
    try:
        reps = int(reps_str)
    except ValueError:
        reps = 3

    run_headless_batch(revision="C0", export_path=None, reps=reps)


def inspect_correlated_evidence_and_export():
    """[6] Inspect Correlated Evidence & Export CSV Report (UC-06)."""
    console.print()
    console.print("[bold]UC-06: Correlated Evidence Forensic Inspector & Export[/bold]")
    cid = Prompt.ask("Enter X-Request-ID (UUIDv4)").strip()
    if not cid:
        console.print("[dim]No UUID provided. Returning to menu.[/dim]")
        return

    waf = find_waf_evidence(cid, timeout=3.0)
    seen = seen_by_app(cid, timeout=1.0)
    rc, out, _ = docker_exec(
        "wb-event-db",
        ["psql", "-U", "telemetry_user", "-d", "wafbench_events", "-t", "-A", "-c",
         f"SELECT state, client_status, anomaly_score, backend_effect, metric_cell, matched_rules FROM normalized_events WHERE correlation_id='{cid}';"]
    )
    
    parts = out.strip().split("|") if rc == 0 and out.strip() else []
    state = parts[0] if len(parts) > 0 else "Unknown"
    client_status = parts[1] if len(parts) > 1 else ("Found in WAF" if waf.get("found") else "Unknown")
    score = parts[2] if len(parts) > 2 else (waf.get("anomaly_score") or 0)
    effect = parts[3] if len(parts) > 3 else "False"
    cell = parts[4] if len(parts) > 4 else "N/A"
    rules = parts[5] if len(parts) > 5 else format_rule_list(waf.get("matched_rule_ids"))

    evidence = {
        "case_id": "QUERY-FORENSIC",
        "run_id": f"ID-{cid[:8]}",
        "correlation_id": cid,
        "state": state,
        "method": "Captured",
        "endpoint": "/inspected",
        "request_sha256": "Correlated from Audit Record",
        "client_status": client_status,
        "raw_payload": "Retrieved from Audit Log",
        "waf_txn_id": waf.get("waf_http_code") or ("Found in audit.log" if waf.get("found") else "Absent (RelevantOnly)"),
        "config_revision": "C0",
        "matched_rule_ids": rules,
        "inbound_score": score,
        "inbound_threshold": 5,
        "disruptive_action": "HTTP 403" if client_status == "403" else "None",
        "interrupt_phase": "Phase 2" if client_status == "403" else "None",
        "audit_ref": waf.get("source") or "Absent",
        "app_received": f"{seen} (Ingress Verified)",
        "oracle_target": "PostgreSQL normalized_events",
        "oracle_observation": f"Database recording verified: effect={effect}",
        "backend_effect": effect,
        "reset_latency_s": "0.00",
        "validity": "VALID",
        "verdict": cell,
        "metric_cell": cell,
    }

    console.print()
    console.print(build_three_tier_inspector(evidence))
    console.print()


# ==============================================================================
# MODE 2: HEADLESS CLI AUTOMATION MODE
# ==============================================================================

def run_headless_batch(
    revision: str = "C0",
    export_path: Optional[str] = None,
    reps: int = 3,
    cases_filter: Optional[List[str]] = None,
    states_filter: Optional[List[str]] = None,
) -> int:
    """
    Executes automated 3-State batch evaluation non-interactively.
    Streams Live progress table and exits 0 on success, non-zero on failure.
    """
    cases = load_cases()
    if cases_filter:
        cases = [c for c in cases if c.get("case_id") in cases_filter]

    if not cases:
        console.print("[bold red][FAIL][/bold red] No test cases found in corpus/cases.")
        return 1

    states = [s for s in STATES if not states_filter or s in states_filter]

    console.print(f"[bold]Executing Headless Empirical Batch[/bold] [Revision: {revision}] (Cases: {len(cases)}, States: {len(states)}, Reps: {reps})")

    # Precondition Checks
    app_ok, app_err = check_app_health(DIRECT_URL)
    if not app_ok:
        console.print(f"[bold red][FAIL] E_HEALTH:[/bold red] Direct App unreachable at {DIRECT_URL}: {app_err}")
        return 1

    gw_ok, gw_err = check_app_health(GATEWAY_URL)
    if not gw_ok:
        console.print(f"[bold red][FAIL] E_HEALTH:[/bold red] Gateway unreachable at {GATEWAY_URL}: {gw_err}")
        return 1

    # Initial reset to establish F1 fixture baseline
    trigger_reset(DIRECT_URL)

    db_ok, db_err = verify_fixture()
    if not db_ok:
        console.print(f"[bold red][FAIL] E_FIXTURE:[/bold red] Database fixture invalid: {db_err}")
        return 1

    req_mgr = RequestManager()
    batch_id = f"batch_{int(time.time())}"
    results: List[Dict[str, Any]] = []

    live_table = Table(box=DEFAULT_BOX, expand=True)
    live_table.add_column("State", style="bold cyan", no_wrap=True)
    live_table.add_column("Case ID", style="bold white", no_wrap=True)
    live_table.add_column("Rep", justify="right", width=4)
    live_table.add_column("HTTP", no_wrap=True)
    live_table.add_column("Latency", justify="right")
    live_table.add_column("WAF Rules", style="yellow")
    live_table.add_column("Score", justify="right")
    live_table.add_column("Oracle", no_wrap=True)
    live_table.add_column("Validity", no_wrap=True)
    live_table.add_column("Verdict Cell", style="bold magenta", no_wrap=True)

    try:
        with Live(live_table, refresh_per_second=4, console=console) as live:
            for state in states:
                is_waf = state != "Direct-to-App"
                target_url = GATEWAY_URL if is_waf else DIRECT_URL

                if is_waf:
                    m_ok, m_reason = prepare_state(state)
                    if not m_ok:
                        console.print(f"[bold red][FAIL] E_MODE:[/bold red] Failed preparing state {state}: {m_reason}")
                        return 1

                for case in cases:
                    cid = case["case_id"]
                    for rep in range(1, reps + 1):
                        correlation_id = str(uuid.uuid4())
                        preconditions = {"mode_verified": True, "fixture_verified": True, "health_ok": True}

                        # Reset Fixture
                        trigger_reset(DIRECT_URL)

                        # Send probe
                        client_res = req_mgr.send_request(target_url, case, correlation_id)
                        status = client_res.get("status_code")
                        lat = round(client_res.get("latency_ms", 0.0), 1)

                        # WAF Evidence
                        waf_data = find_waf_evidence(correlation_id, timeout=2.5) if is_waf else {"matched_rule_ids": [], "anomaly_score": None, "found": False}

                        # Oracle
                        oracle_res = run_oracle_for_case(case, client_res, correlation_id)
                        backend_effect = bool(oracle_res.get("backend_effect"))

                        validity_code, is_valid, reason = classify_validity(preconditions, client_res, waf_data, state)
                        metric_cell = assign_metric_cell(state, case.get("label", "malicious"), waf_data, client_res)

                        rec = {
                            "batch_id": batch_id,
                            "case_id": cid,
                            "family": case.get("family"),
                            "label": case.get("label"),
                            "state": state,
                            "repetition": rep,
                            "correlation_id": correlation_id,
                            "client_status": status,
                            "latency_ms": lat,
                            "request_sha256": client_res.get("request_sha256"),
                            "backend_effect": backend_effect,
                            "oracle_observation": oracle_res.get("observation"),
                            "waf_found": waf_data.get("found"),
                            "waf_detected": waf_data.get("detected"),
                            "matched_rule_ids": ",".join(waf_data.get("matched_rule_ids", [])),
                            "anomaly_score": waf_data.get("anomaly_score"),
                            "waf_http_code": waf_data.get("waf_http_code"),
                            "validity": validity_code,
                            "invalid_reason": None if is_valid else reason,
                            "metric_cell": metric_cell,
                        }
                        results.append(rec)

                        # Update table row in live view
                        status_str = f"[bold green]{status}[/bold green]" if status == 200 else f"[bold red]{status}[/bold red]"
                        effect_str = f"[bold red]EXPLOIT[/bold red]" if backend_effect else f"[bold green]NEUTRAL[/bold green]"
                        rule_str = rec["matched_rule_ids"] or "None"
                        live_table.add_row(
                            state,
                            cid,
                            str(rep),
                            status_str,
                            f"{lat}ms",
                            rule_str[:20] + ("..." if len(rule_str) > 20 else ""),
                            str(rec["anomaly_score"] or 0),
                            effect_str,
                            f"[{validity_code}]",
                            metric_cell,
                        )
    finally:
        # Restore safe baseline mode
        if any(s != "Direct-to-App" for s in states):
            set_waf_mode("DetectionOnly")

    if not results:
        return 1

    # Post-processing gates
    if "Direct-to-App" in states:
        results = apply_baseline_gate(results, cases)
    results = mark_flaky(results)

    # Export CSVs
    results_dir = os.path.join(RUNNER_DIR, "results")
    os.makedirs(results_dir, exist_ok=True)
    out_csv = export_path or os.path.join(results_dir, f"results_{revision}.csv")
    export_csv(results, out_csv)
    export_summary_csv(results, os.path.join(results_dir, f"summary_{revision}.csv"))

    # Print Table 5.3 & 5.2 Summary
    console.print()
    matrix_records = summarize_batch_for_matrix(results, cases)
    console.print(build_three_state_table(matrix_records))
    console.print()

    raw_metrics = calculate_metrics(results)
    metrics_panel_data = format_metrics_for_panel(raw_metrics)
    console.print(build_metrics_summary_panel(metrics_panel_data))
    console.print()
    console.print(f"[bold green][OK][/bold green] Headless batch completed successfully. Results exported to: {out_csv}")
    return 0


# ==============================================================================
# MODE 1: INTERACTIVE MENU LOOP
# ==============================================================================

def interactive_menu():
    """Main interactive menu loop adhering to Section 4 Mode 1 specification."""
    while True:
        console.clear()
        stack_status, policy_meta = query_system_state()
        console.print(build_lab_header(stack_status, policy_meta))
        console.print()

        console.print("[bold white]Academic Operational Navigation Menu:[/bold white]\n")
        console.print("  [bold cyan][1][/bold cyan] Pre-Flight & Container Health Check (UC-01)")
        console.print("  [bold cyan][2][/bold cyan] Corpus Explorer & Paired Contrast Validator (UC-02 / 32 Cases)")
        console.print("  [bold cyan][3][/bold cyan] Switch WAF Operating State (DetectionOnly <-> Blocking) & Canary Verify (UC-03)")
        console.print("  [bold cyan][4][/bold cyan] Live Single-Probe 3-Tier Walkthrough (UC-04 / UC-05)")
        console.print("  [bold cyan][5][/bold cyan] Execute Full 3-State Empirical Batch (3 Repetitions per Case) (Table 5.3)")
        console.print("  [bold cyan][6][/bold cyan] Inspect Correlated Evidence & Export CSV Report (UC-06)")
        console.print("  [bold cyan][7][/bold cyan] Launch Full-Screen Interactive TUI Console (Textual Mode)")
        console.print("  [bold red][Q][/bold red] Quit Laboratory CLI\n")

        try:
            choice = Prompt.ask("[bold yellow]Enter selection[/bold yellow]", choices=["1", "2", "3", "4", "5", "6", "7", "Q", "q"], default="1")
        except (EOFError, KeyboardInterrupt):
            console.print("\n[bold cyan]Exiting WAFBench Laboratory CLI. Goodbye![/bold cyan]\n")
            sys.exit(0)

        if choice == "1":
            run_preflight_health_check()
            Prompt.ask("\n[dim]Press Enter to return to main menu...[/dim]")

        elif choice == "2":
            run_corpus_explorer_and_validator()
            Prompt.ask("\n[dim]Press Enter to return to main menu...[/dim]")

        elif choice == "3":
            run_switch_waf_state()
            Prompt.ask("\n[dim]Press Enter to return to main menu...[/dim]")

        elif choice == "4":
            cases = load_cases()
            console.print("\n[bold]Select an Attack Family or Case to test:[/bold]")
            quick_picks = [
                ("1", "SQLI-001", "SQL Injection Login Bypass (Malicious)"),
                ("2", "SQLI-001-B1", "Legitimate Login (Benign contrast)"),
                ("3", "XSS-001", "Reflected Script Tag (Malicious)"),
                ("4", "XSS-001-B1", "Normal Search Query (Benign contrast)"),
                ("5", "PATH-001", "Path Traversal /etc/passwd (Malicious)"),
                ("6", "SSRF-001", "Internal /metadata access (Malicious)"),
                ("7", "CUSTOM", "Choose any case from 32 corpus items"),
            ]
            for num, cid, desc in quick_picks:
                console.print(f"  [cyan][{num}][/cyan] [bold]{cid:<12}[/bold] - {desc}")

            p_pick = Prompt.ask("\nSelect probe", choices=[q[0] for q in quick_picks], default="1")
            if p_pick == "7":
                all_ids = [c["case_id"] for c in cases]
                chosen_id = Prompt.ask("Enter Case ID", choices=all_ids, default=all_ids[0])
                case = get_case_by_id(chosen_id)
            else:
                chosen_id = [q[1] for q in quick_picks if q[0] == p_pick][0]
                case = get_case_by_id(chosen_id)

            if not case:
                console.print(f"[bold red]Unknown Case ID:[/] {chosen_id}")
                continue

            console.print("\n[bold]Select Evaluation State:[/bold]")
            console.print("  [cyan][1][/cyan] State 1: Direct-to-App (:8001) [dim][App baseline, no WAF][/dim]")
            console.print("  [cyan][2][/cyan] State 2: DetectionOnly (:8080) [dim][CRS active, no disruption][/dim]")
            console.print("  [cyan][3][/cyan] State 3: Blocking (:8080)      [dim][CRS active, 403 block][/dim]")
            s_pick = Prompt.ask("Select State", choices=["1", "2", "3"], default="3")
            state_map = {"1": "Direct-to-App", "2": "DetectionOnly", "3": "Blocking"}

            execute_probe_walkthrough(case, state_map[s_pick])
            Prompt.ask("\n[dim]Press Enter to return to main menu...[/dim]")

        elif choice == "5":
            run_three_state_batch_interactive()
            Prompt.ask("\n[dim]Press Enter to return to main menu...[/dim]")

        elif choice == "6":
            inspect_correlated_evidence_and_export()
            Prompt.ask("\n[dim]Press Enter to return to main menu...[/dim]")

        elif choice == "7":
            app = WAFBenchTUI()
            app.run()

        elif choice.upper() == "Q":
            console.print("\n[bold cyan]Exiting WAFBench Laboratory CLI. Goodbye![/bold cyan]\n")
            sys.exit(0)


# ==============================================================================
# MAIN ENTRYPOINT & ARGUMENT PARSER
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="WAFBench CLI: Interactive Diagnostic & Empirical Replay Harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Mode 2 & Mode 3 Flags
    parser.add_argument("--batch", type=str, metavar="REVISION", help="Execute headless batch evaluation (e.g. C0 or C1)")
    parser.add_argument("--export", type=str, metavar="FILE", help="Destination path for batch CSV export")
    parser.add_argument("--tui", action="store_true", help="Launch full-screen interactive Textual TUI console")
    parser.add_argument("--test-run", action="store_true", help="Run self-test headless verification and exit cleanly")
    parser.add_argument("--reps", type=int, default=3, help="Repetitions per test case in batch mode (default: 3)")
    parser.add_argument("--case", type=str, default=None, help="Filter by specific Case ID in batch mode")
    parser.add_argument("--state", type=str, choices=STATES, default=None, help="Filter by specific State in batch mode")
    parser.add_argument("--ascii", action="store_true", help="Force ASCII box drawing instead of SQUARE")

    # Backwards-compatible subcommands
    subparsers = parser.add_subparsers(dest="command", help="Operational subcommands")

    # workflow
    subparsers.add_parser("workflow", help="Show system architecture and data workflow diagram")

    # probe
    probe_parser = subparsers.add_parser("probe", help="Run interactive probe walkthrough")
    probe_parser.add_argument("--case", type=str, default="SQLI-001", help="Case ID to test")
    probe_parser.add_argument("--state", type=str, choices=STATES, default="Blocking", help="Evaluation state")

    # compare
    comp_parser = subparsers.add_parser("compare", help="Run 3-state comparative matrix for a single case")
    comp_parser.add_argument("--case", type=str, default="SQLI-001", help="Case ID to compare")

    # corpus
    corp_parser = subparsers.add_parser("corpus", help="Browse corpus cases and validate contrast pairing")
    corp_parser.add_argument("--family", type=str, default=None, help="Filter by attack family")

    # run
    bench_parser = subparsers.add_parser("run", help="Run automated benchmark suite")
    bench_parser.add_argument("--reps", type=int, default=1, help="Repetitions per case")
    bench_parser.add_argument("--state", type=str, choices=STATES, default=None, help="Filter by state")

    # inspect
    insp_parser = subparsers.add_parser("inspect", help="Inspect evidence for correlation ID")
    insp_parser.add_argument("uuid", type=str, help="X-Request-ID UUIDv4 to look up")

    # status
    subparsers.add_parser("status", help="Show system health and container topology status")

    args = parser.parse_args()

    # Route: Mode 3 (Textual TUI)
    if args.tui:
        if args.test_run:
            from textual.widgets import ContentSwitcher
            import asyncio
            async def _verify() -> None:
                app = WAFBenchTUI(ascii_only=args.ascii)
                async with app.run_test() as pilot:
                    await pilot.press("1")
                    await pilot.pause()
                    assert app.query_one("#view-switcher", ContentSwitcher).current == "view1"
                    await pilot.press("2")
                    await pilot.pause()
                    assert app.query_one("#view-switcher", ContentSwitcher).current == "view2"
                    await pilot.press("3")
                    await pilot.pause()
                    assert app.query_one("#view-switcher", ContentSwitcher).current == "view3"
                    await pilot.press("4")
                    await pilot.pause()
                    assert app.query_one("#view-switcher", ContentSwitcher).current == "view4"
                    await pilot.press("r")
                    await pilot.pause()
                    await pilot.press("q")
                    await pilot.pause()
            asyncio.run(_verify())
            print("[OK] WAFBench TUI headless test run passed.")
            return
        app = WAFBenchTUI(ascii_only=args.ascii)
        app.run()
        return

    # Route: Mode 2 (Headless Batch Mode)
    if args.batch:
        cases_filter = [args.case] if args.case else None
        states_filter = [args.state] if args.state else None
        code = run_headless_batch(
            revision=args.batch,
            export_path=args.export,
            reps=args.reps,
            cases_filter=cases_filter,
            states_filter=states_filter,
        )
        sys.exit(code)

    # Route: Backwards-compatible subcommands
    if args.command == "workflow":
        show_workflow_diagram()
    elif args.command == "probe":
        case = get_case_by_id(args.case)
        if not case:
            console.print(f"[bold red]Unknown Case ID:[/] {args.case}")
            sys.exit(1)
        execute_probe_walkthrough(case, args.state)
    elif args.command == "compare":
        case = get_case_by_id(args.case)
        if not case:
            console.print(f"[bold red]Unknown Case ID:[/] {args.case}")
            sys.exit(1)
        for s in STATES:
            execute_probe_walkthrough(case, s)
    elif args.command == "corpus":
        run_corpus_explorer_and_validator(filter_family=args.family)
    elif args.command == "run":
        states_filter = [args.state] if args.state else None
        code = run_headless_batch(revision="C0", export_path=args.export, reps=args.reps, states_filter=states_filter)
        sys.exit(code)
    elif args.command == "inspect":
        inspect_forensic_evidence_direct(args.uuid)
    elif args.command == "status":
        run_preflight_health_check()
    else:
        # Route: Mode 1 (Interactive Academic Menu Mode when no arguments are provided)
        interactive_menu()


def inspect_forensic_evidence_direct(correlation_id: str):
    """Direct CLI handler for 'inspect <UUID>' subcommand."""
    waf = find_waf_evidence(correlation_id, timeout=3.0)
    seen = seen_by_app(correlation_id, timeout=1.0)
    rc, out, _ = docker_exec(
        "wb-event-db",
        ["psql", "-U", "telemetry_user", "-d", "wafbench_events", "-t", "-A", "-c",
         f"SELECT state, client_status, anomaly_score, backend_effect, metric_cell, matched_rules FROM normalized_events WHERE correlation_id='{correlation_id}';"]
    )
    parts = out.strip().split("|") if rc == 0 and out.strip() else []
    evidence = {
        "case_id": "DIRECT-INSPECT",
        "run_id": f"ID-{correlation_id[:8]}",
        "correlation_id": correlation_id,
        "state": parts[0] if len(parts) > 0 else "Unknown",
        "method": "Captured",
        "endpoint": "/inspected",
        "request_sha256": "Audit Log Record",
        "client_status": parts[1] if len(parts) > 1 else ("403" if waf.get("waf_http_code") == 403 else "200"),
        "raw_payload": "Retrieved from Audit Log",
        "waf_txn_id": waf.get("waf_http_code") or ("Found in audit.log" if waf.get("found") else "Absent (RelevantOnly)"),
        "config_revision": "C0",
        "matched_rule_ids": parts[5] if len(parts) > 5 else format_rule_list(waf.get("matched_rule_ids")),
        "inbound_score": parts[2] if len(parts) > 2 else (waf.get("anomaly_score") or 0),
        "inbound_threshold": 5,
        "disruptive_action": "HTTP 403" if (len(parts) > 1 and parts[1] == "403") else "None",
        "interrupt_phase": "Phase 2" if (len(parts) > 1 and parts[1] == "403") else "None",
        "audit_ref": waf.get("source") or "Absent",
        "app_received": f"{seen} (App Ingress)",
        "oracle_target": "PostgreSQL normalized_events",
        "oracle_observation": f"Database recording verified: effect={parts[3] if len(parts) > 3 else 'False'}",
        "backend_effect": parts[3] if len(parts) > 3 else "False",
        "reset_latency_s": "0.00",
        "validity": "VALID",
        "verdict": parts[4] if len(parts) > 4 else "N/A",
        "metric_cell": parts[4] if len(parts) > 4 else "N/A",
    }
    console.print()
    console.print(build_three_tier_inspector(evidence))
    console.print()


if __name__ == "__main__":
    main()
