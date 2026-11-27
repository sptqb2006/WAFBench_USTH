#!/usr/bin/env python3
"""
WAFBench CLI: Interactive Diagnostic & Data Workflow Walkthrough Tool
Author: Kieu Dang Vuong
Workspace: WAF_USTH (Nginx 1.26 + ModSecurity v3 + OWASP CRS v4.0.0)

This CLI provides a transparent, educational walkthrough of WAFBench's
3-Tier Evidence and 3-State Evaluation Methodology.
"""

import os
import sys
import json
import time
import uuid
import argparse
import requests
from typing import Optional, Dict, Any, List

# Ensure runner directory is on sys.path
CLI_DIR = os.path.dirname(os.path.abspath(__file__))
RUNNER_DIR = os.path.join(CLI_DIR, "runner")
if RUNNER_DIR not in sys.path:
    sys.path.insert(0, RUNNER_DIR)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
from rich.prompt import Prompt, Confirm
from rich import box

# Import WAFBench Core modules
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
from report import calculate_metrics

console = Console()

# Configuration
DIRECT_URL = os.getenv("DIRECT_APP_URL", "http://127.0.0.1:8001")
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://127.0.0.1:8080")
CASES_DIR = os.path.join(CLI_DIR, "corpus", "cases")
STATES = ["Direct-to-App", "DetectionOnly", "Blocking"]
ENGINE_MAP = {"DetectionOnly": "DetectionOnly", "Blocking": "On"}


def load_cases(category: Optional[str] = None) -> List[Dict[str, Any]]:
    """Loads all corpus cases or filtered by category."""
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
        box=box.DOUBLE
    ))

    tree = Tree("[bold bright_white]WAFBench Diagnostic Pipeline[/bold bright_white]")

    # Phase 1: Client Harness
    c_node = tree.add("[bold yellow]1. Test Client Harness (runner / cli)[/bold yellow]")
    c_node.add("• Ingestion of test case payload from [cyan]corpus/cases/[/cyan]")
    c_node.add("• Generates unique [bold green]X-Request-ID[/bold green] (UUIDv4) for end-to-end tracing")
    c_node.add("• Computes canonical [magenta]SHA-256 request fingerprint[/magenta]")
    c_node.add("• Dispatches HTTP request to target: [green]:8001 (Direct)[/green] or [blue]:8080 (WAF Gateway)[/blue]")

    # Tier 1
    t1_node = tree.add("[bold bright_blue]2. Tier 1: Client Capture[/bold bright_blue]")
    t1_node.add("• Records HTTP status code: [green]200 OK[/green] (allowed) vs [red]403 Forbidden[/red] (blocked)")
    t1_node.add("• Measures round-trip response latency ([cyan]ms[/cyan])")
    t1_node.add("• Captures response headers and response body snippet")

    # Tier 2
    t2_node = tree.add("[bold bright_red]3. Tier 2: WAF Perimeter Telemetry (wb-gateway :8080)[/bold bright_red]")
    t2_node.add("• Nginx 1.26 + ModSecurity v3 C++ library + OWASP CRS v4.0.0")
    t2_node.add("• [bold]Phase 1 & 2 Request Inspection[/bold]: evaluates regex against headers, query, body")
    t2_node.add("• Computes Inbound Anomaly Score (threshold = 5 at Paranoia Level 1)")
    t2_node.add("• [bold]State Engine Behavior[/bold]:")
    t2_node.add("    ├─ [yellow]State 1 (Direct-to-App :8001)[/yellow]: Bypasses gateway completely (baseline)")
    t2_node.add("    ├─ [blue]State 2 (DetectionOnly :8080)[/blue]: Logs CRS rule hits, passes request to backend")
    t2_node.add("    └─ [red]State 3 (Blocking :8080)[/red]: Intercepts attack with HTTP 403; never reaches app")
    t2_node.add("• Writes structured JSON audit log to [cyan]/var/log/modsec/audit.log[/cyan]")

    # Tier 3
    t3_node = tree.add("[bold bright_green]4. Tier 3: Backend Oracle Ground Truth (wb-app, wb-app-db, wb-mock)[/bold bright_green]")
    t3_node.add("• Vulnerable Express app (:3000) handles request if passed by perimeter")
    t3_node.add("• Independent Oracle probes container state directly (zero reliance on HTTP 403):")
    t3_node.add("    ├─ [cyan]SQLi Oracle[/cyan]: Queries PostgreSQL [italic]sessions[/italic] table for unauthorized user session")
    t3_node.add("    ├─ [cyan]XSS Oracle[/cyan]: Inspects response body for unescaped probe tag reflection + text/html")
    t3_node.add("    ├─ [cyan]Path Traversal Oracle[/cyan]: Checks if /etc/passwd root tokens were disclosed")
    t3_node.add("    └─ [cyan]SSRF Oracle[/cyan]: Queries internal mock server /logs for unauthorized /metadata hit")

    # Phase 5: Telemetry Correlation
    cor_node = tree.add("[bold bright_magenta]5. Telemetry Correlation & Metric Engine[/bold bright_magenta]")
    cor_node.add("• [bold]telemetry/worker.py[/bold] tails audit.log and correlates Client + WAF + Oracle by [green]X-Request-ID[/green]")
    cor_node.add("• Stores normalized records in PostgreSQL [cyan]wb-event-db[/cyan] ([italic]normalized_events[/italic])")
    cor_node.add("• Calculates formal benchmark metrics: [bold]DR, BR, FPR_D, FPR_B, RPR[/bold]")

    console.print(tree)
    console.print()

    # Evidence-First 3-Tier Explanation Table
    table = Table(title="Why WAFBench Enforces the Evidence-First 3-Tier Rule", box=box.ROUNDED, expand=True)
    table.add_column("Tier", style="bold cyan", no_wrap=True)
    table.add_column("Component", style="yellow", no_wrap=True)
    table.add_column("Observation Point", style="bright_white")
    table.add_column("Why HTTP 403 Alone is Insufficient", style="bright_red")

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
# 2. STEP-BY-STEP INTERACTIVE PROBE WALKTHROUGH
# ==============================================================================

def execute_probe_walkthrough(case: Dict[str, Any], state: str):
    """Executes a single test case with detailed live step-by-step diagnostic output."""
    console.print()
    console.print(Panel(
        f"[bold bright_white]LIVE STEP-BY-STEP PROBE WALKTHROUGH[/bold bright_white]\n"
        f"Case: [bold cyan]{case.get('case_id')}[/bold cyan] ({case.get('family')}) | "
        f"Label: [{'red' if case.get('label') == 'malicious' else 'green'}]{case.get('label').upper()}[/] | "
        f"State: [yellow]{state}[/yellow]",
        box=box.ROUNDED,
        border_style="bright_blue"
    ))

    # Pre-step: Ensure WAF Mode matches requested state
    is_waf = state != "Direct-to-App"
    target_url = GATEWAY_URL if is_waf else DIRECT_URL

    if is_waf:
        with console.status(f"[bold cyan]Switching WAF mode to {state}..."):
            ok, err = set_waf_mode(ENGINE_MAP[state])
            if not ok:
                console.print(f"[bold red][!] Failed to set WAF mode:[/] {err}")
                return
            wait_gateway_ready(GATEWAY_URL)
            mode_ok, mode_reason = mode_canary(GATEWAY_URL, state)
            console.print(f"  [bold green]✓[/bold green] WAF Engine set to [bold yellow]{state}[/bold yellow] ({mode_reason})")
    else:
        console.print(f"  [bold green]✓[/bold green] Target is [bold yellow]Direct-to-App (:8001)[/bold yellow] (WAF completely bypassed)")

    # Reset Fixture
    with console.status("[bold cyan]Resetting database fixture to F1 state..."):
        try:
            r = requests.post(f"{DIRECT_URL}/health/reset", timeout=5.0)
            counts = get_fixture_counts()
            console.print(f"  [bold green]✓[/bold green] Fixture reset complete ({r.json().get('reset_duration_ms', 0)} ms) -> DB: {counts}")
        except Exception as e:
            console.print(f"  [bold yellow]![/bold yellow] Fixture reset warning: {e}")

    # Step 1: Request Assembly & Fingerprinting
    correlation_id = str(uuid.uuid4())
    req_sha256 = manager.request_fingerprint(case)

    step1_table = Table(title="[Step 1] Request Assembly & Canonical Fingerprint", box=box.SIMPLE)
    step1_table.add_column("Parameter", style="cyan")
    step1_table.add_column("Value", style="bright_white")
    step1_table.add_row("Target URL", f"{target_url}{case.get('endpoint')}")
    step1_table.add_row("HTTP Method", case.get("method", "GET"))
    step1_table.add_row("Correlation ID", f"[bold green]{correlation_id}[/bold green] (Injected as X-Request-ID)")
    step1_table.add_row("SHA-256 Fingerprint", req_sha256[:24] + "...")
    step1_table.add_row("Payload Body", case.get("body") or "[None]")
    console.print(step1_table)

    # Step 2: HTTP Transmission (Tier 1)
    mgr = RequestManager()
    with console.status("[bold cyan]Dispatching HTTP request..."):
        client_res = mgr.send_request(target_url, case, correlation_id)

    status_code = client_res.get("status_code")
    latency_ms = round(client_res.get("latency_ms", 0), 2)
    body_snippet = (client_res.get("text") or "").strip()[:160].replace("\n", " ")

    status_color = "green" if status_code == 200 else ("red" if status_code == 403 else "yellow")
    step2_table = Table(title="[Step 2] Tier 1: Client Capture", box=box.SIMPLE)
    step2_table.add_column("Observation", style="cyan")
    step2_table.add_column("Result", style="bright_white")
    step2_table.add_row("HTTP Response Code", f"[{status_color}][bold]{status_code}[/bold][/{status_color}]")
    step2_table.add_row("Round-trip Latency", f"{latency_ms} ms")
    step2_table.add_row("Response Snippet", body_snippet or "[Empty]")
    console.print(step2_table)

    # Step 3: WAF Perimeter Telemetry (Tier 2)
    step3_table = Table(title="[Step 3] Tier 2: WAF ModSecurity Telemetry", box=box.SIMPLE)
    step3_table.add_column("Metric", style="cyan")
    step3_table.add_column("Extracted Telemetry", style="bright_white")

    if is_waf:
        with console.status("[bold cyan]Searching ModSecurity audit log by X-Request-ID..."):
            waf_data = find_waf_evidence(correlation_id, timeout=3.0)
        
        found = waf_data.get("found", False)
        detected = waf_data.get("detected", False)
        rule_ids = waf_data.get("matched_rule_ids", [])
        score = waf_data.get("anomaly_score")

        step3_table.add_row("Audit Record Found", f"[green]YES[/green]" if found else f"[yellow]NO (RelevantOnly / no rule hit)[/yellow]")
        step3_table.add_row("WAF Detected", f"[bold {'red' if detected else 'green'}]{detected}[/]")
        step3_table.add_row("Inbound Anomaly Score", f"[bold cyan]{score if score is not None else 0}[/bold cyan] (Threshold: 5)")
        step3_table.add_row("Matched CRS Rule IDs", f"[bold yellow]{', '.join(rule_ids) if rule_ids else 'None'}[/bold yellow]")
        step3_table.add_row("Disruptive Action", "HTTP 403 Forbidden" if status_code == 403 else "Passed to Backend")
    else:
        waf_data = {"found": False, "detected": False, "matched_rule_ids": [], "anomaly_score": None}
        step3_table.add_row("State", "[yellow]Direct-to-App Baseline (No WAF)[/yellow]")
        step3_table.add_row("Perimeter Inspection", "[italic]Bypassed[/italic]")
    console.print(step3_table)

    # Step 4: Backend Oracle Ground Truth (Tier 3)
    with console.status("[bold cyan]Executing independent Backend Oracle verification..."):
        oracle_res = run_oracle_for_case(case, client_res, correlation_id)

    backend_effect = oracle_res.get("backend_effect", False)
    effect_color = "bold red" if backend_effect else "bold green"
    effect_label = "EXPLOIT SUCCEEDED (Compromised)" if backend_effect else "NO EFFECT (Protected / Neutralized)"

    step4_table = Table(title="[Step 4] Tier 3: Backend Oracle Ground Truth", box=box.SIMPLE)
    step4_table.add_column("Property", style="cyan")
    step4_table.add_column("Observation", style="bright_white")
    step4_table.add_row("Oracle Family Target", case.get("family"))
    step4_table.add_row("Backend State Change", f"[{effect_color}]{effect_label}[/{effect_color}]")
    step4_table.add_row("Oracle Observation", oracle_res.get("observation", ""))
    console.print(step4_table)

    # Step 5: Correlation & Metric Classification
    preconditions = {"mode_verified": True, "fixture_verified": True, "health_ok": True}
    validity_code, is_valid, reason = classify_validity(preconditions, client_res, waf_data, state)
    metric_cell = assign_metric_cell(state, case.get("label", "malicious"), waf_data, client_res)

    summary_panel = Panel(
        f"[bold bright_white]3-TIER EMPIRICAL CORRELATION VERDICT[/bold bright_white]\n\n"
        f"  • [cyan]Correlation ID[/cyan]   : [bold]{correlation_id}[/bold]\n"
        f"  • [cyan]State Evaluated[/cyan]  : [yellow]{state}[/yellow]\n"
        f"  • [cyan]Tier 1 Status[/cyan]    : [{status_color}]HTTP {status_code}[/{status_color}]\n"
        f"  • [cyan]Tier 2 Telemetry[/cyan] : Matched Rules: [yellow]{','.join(waf_data.get('matched_rule_ids') or []) or 'None'}[/yellow] | Anomaly Score: {waf_data.get('anomaly_score') or 0}\n"
        f"  • [cyan]Tier 3 Oracle[/cyan]    : [{effect_color}]{effect_label}[/{effect_color}]\n"
        f"  • [cyan]Classification[/cyan]   : [bold magenta]{metric_cell}[/bold magenta] (Validity: [{ 'green' if is_valid else 'red'}]{validity_code}[/])",
        border_style="bright_magenta",
        box=box.ROUNDED
    )
    console.print(summary_panel)
    console.print()


# ==============================================================================
# 3. 3-STATE COMPARATIVE ANALYSIS
# ==============================================================================

def run_3state_comparison(case: Dict[str, Any]):
    """Executes a single test case across all 3 states side-by-side."""
    case_id = case.get("case_id")
    console.print()
    console.print(Panel(
        f"[bold bright_white]3-STATE REPLAY COMPARISON: {case_id}[/bold bright_white]\n"
        f"Family: [cyan]{case.get('family')}[/cyan] | Label: [{'red' if case.get('label') == 'malicious' else 'green'}]{case.get('label').upper()}[/] | Method: [yellow]{case.get('method')}[/yellow] {case.get('endpoint')}",
        box=box.ROUNDED,
        border_style="cyan"
    ))

    table = Table(box=box.HEAVY_EDGE)
    table.add_column("Tier / Metric", style="bold cyan", width=22)
    table.add_column("State 1: Direct-to-App (:8001)", style="bright_white", width=28)
    table.add_column("State 2: DetectionOnly (:8080)", style="bright_white", width=28)
    table.add_column("State 3: Blocking (:8080)", style="bright_white", width=28)

    rows = {
        "Target Address": [],
        "WAF Engine Mode": [],
        "Client HTTP Status": [],
        "Round-trip Latency": [],
        "WAF CRS Rules": [],
        "Inbound Anomaly Score": [],
        "Backend Oracle Effect": [],
        "Ground Truth Verdict": [],
    }

    mgr = RequestManager()

    try:
        for state in STATES:
            is_waf = state != "Direct-to-App"
            target_url = GATEWAY_URL if is_waf else DIRECT_URL

            # Set WAF mode if needed
            if is_waf:
                set_waf_mode(ENGINE_MAP[state])
                wait_gateway_ready(GATEWAY_URL)
                mode_canary(GATEWAY_URL, state)

            # Reset DB Fixture
            requests.post(f"{DIRECT_URL}/health/reset", timeout=5.0)

            # Send probe
            cid = str(uuid.uuid4())
            c_res = mgr.send_request(target_url, case, cid)
            status = c_res.get("status_code")
            lat = round(c_res.get("latency_ms", 0), 1)

            # WAF Evidence
            if is_waf:
                waf = find_waf_evidence(cid, timeout=3.0)
            else:
                waf = {"matched_rule_ids": [], "anomaly_score": None}

            # Oracle
            oracle = run_oracle_for_case(case, c_res, cid)
            effect = oracle.get("backend_effect", False)

            # Metric Cell
            metric_cell = assign_metric_cell(state, case.get("label", "malicious"), waf, c_res)

            # Record
            rows["Target Address"].append(f":8001 (Direct)" if not is_waf else f":8080 (Gateway)")
            rows["WAF Engine Mode"].append("Bypassed" if not is_waf else state)
            rows["Client HTTP Status"].append(f"[bold {'green' if status == 200 else 'red'}]{status}[/]")
            rows["Round-trip Latency"].append(f"{lat} ms")
            rows["WAF CRS Rules"].append(", ".join(waf.get("matched_rule_ids") or []) or "[dim]None[/dim]")
            rows["Inbound Anomaly Score"].append(str(waf.get("anomaly_score") or 0))
            rows["Backend Oracle Effect"].append(f"[bold {'red' if effect else 'green'}]{'EXPLOITED' if effect else 'SAFE'}[/]")
            rows["Ground Truth Verdict"].append(f"[bold magenta]{metric_cell}[/bold magenta]")

    finally:
        # Restore safe default
        set_waf_mode("DetectionOnly")

    for metric, vals in rows.items():
        table.add_row(metric, vals[0], vals[1], vals[2])

    console.print(table)
    console.print()

    # Analytical Explanation
    console.print(Panel(
        "[bold bright_white]Methodological Takeaway:[/bold bright_white]\n"
        "• [bold]State 1 (Direct)[/bold] establishes ground truth: proves whether the vulnerability exists natively.\n"
        "• [bold]State 2 (DetectionOnly)[/bold] evaluates detection capability: logs CRS anomaly score without disruption.\n"
        "• [bold]State 3 (Blocking)[/bold] evaluates mitigation: active perimeter defense drops exploit before reaching backend.",
        box=box.ROUNDED,
        border_style="yellow"
    ))
    console.print()


# ==============================================================================
# 4. CORPUS EXPLORER
# ==============================================================================

def show_corpus_explorer(filter_family: Optional[str] = None):
    """Displays interactive table of all corpus cases."""
    cases = load_cases(category=filter_family)
    console.print()
    console.print(Panel(
        f"[bold bright_white]WAFBENCH TEST CORPUS EXPLORER[/bold bright_white] ({len(cases)} cases)",
        box=box.ROUNDED,
        border_style="cyan"
    ))

    table = Table(box=box.ROUNDED)
    table.add_column("Case ID", style="bold cyan", width=16)
    table.add_column("Family", style="yellow", width=18)
    table.add_column("Label", width=12)
    table.add_column("Method", width=8)
    table.add_column("Endpoint", style="bright_white", width=22)
    table.add_column("Payload Preview", style="dim", width=36)

    for c in cases:
        label = c.get("label", "malicious")
        label_styled = f"[bold red]MALICIOUS[/bold red]" if label == "malicious" else f"[bold green]BENIGN[/bold green]"
        body = (c.get("body") or "").replace("\n", " ")
        if not body and "endpoint" in c:
            body = c["endpoint"]
        table.add_row(
            c.get("case_id"),
            c.get("family"),
            label_styled,
            c.get("method", "GET"),
            c.get("endpoint"),
            body[:34] + ("..." if len(body) > 34 else "")
        )

    console.print(table)
    console.print()


# ==============================================================================
# 5. BENCHMARK SUITE RUNNER
# ==============================================================================

def run_benchmark_suite(reps: int = 1, state_filter: Optional[str] = None):
    """Runs benchmark batch and prints calculated DR, BR, FPR, RPR metrics."""
    import test as runner_test

    cases = load_cases()
    states = [state_filter] if state_filter else STATES

    console.print()
    console.print(Panel(
        f"[bold bright_white]EXECUTING BENCHMARK SUITE[/bold bright_white]\n"
        f"Cases: [cyan]{len(cases)}[/cyan] | States: [yellow]{', '.join(states)}[/yellow] | Repetitions: [magenta]{reps}[/magenta]",
        box=box.ROUNDED,
        border_style="green"
    ))

    # Temporarily override sys.argv to reuse runner_test.run_experiment_batch
    old_argv = sys.argv
    cli_args = ["runner/test.py", "--reps", str(reps)]
    for s in states:
        cli_args += ["--state", s]
    sys.argv = cli_args

    try:
        runner_test.run_experiment_batch()
    finally:
        sys.argv = old_argv


# ==============================================================================
# 6. FORENSIC EVIDENCE INSPECTOR
# ==============================================================================

def inspect_forensic_evidence(correlation_id: str):
    """Queries audit log and database for detailed evidence of a specific transaction."""
    console.print()
    console.print(Panel(
        f"[bold bright_white]FORENSIC EVIDENCE INSPECTOR[/bold bright_white]\n"
        f"Tracking UUID: [bold cyan]{correlation_id}[/bold cyan]",
        box=box.ROUNDED,
        border_style="magenta"
    ))

    # 1. Look up WAF Audit Log
    console.print("[bold yellow]► Looking up ModSecurity Audit Telemetry...[/bold yellow]")
    waf = find_waf_evidence(correlation_id, timeout=2.0)
    if waf.get("found"):
        console.print(f"  [green]✓[/green] Found in WAF Audit Log (Source: {waf.get('source')})")
        console.print(f"  • Matched CRS Rules : [bold yellow]{', '.join(waf.get('matched_rule_ids') or [])}[/bold yellow]")
        console.print(f"  • Anomaly Score     : [bold cyan]{waf.get('anomaly_score')}[/bold cyan]")
        console.print(f"  • WAF HTTP Code     : [bold]{waf.get('waf_http_code')}[/bold]")
    else:
        console.print(f"  [dim]• No relevant ModSecurity audit entry for this correlation ID[/dim]")

    # 2. Look up App Log
    console.print()
    console.print("[bold yellow]► Checking Express Application Ingress...[/bold yellow]")
    seen = seen_by_app(correlation_id, timeout=1.0)
    console.print(f"  • Propagated to Express: [{'green' if seen else 'yellow'}]{seen}[/]")

    # 3. Look up PostgreSQL event-db
    console.print()
    console.print("[bold yellow]► Querying PostgreSQL event-db (normalized_events)...[/bold yellow]")
    rc, out, _ = docker_exec(
        "wb-event-db",
        ["psql", "-U", "telemetry_user", "-d", "wafbench_events", "-t", "-A", "-c",
         f"SELECT state, client_status, anomaly_score, backend_effect, metric_cell, matched_rules FROM normalized_events WHERE correlation_id='{correlation_id}';"]
    )
    if rc == 0 and out.strip():
        parts = out.strip().split("|")
        table = Table(box=box.SIMPLE)
        table.add_column("Field", style="cyan")
        table.add_column("Stored Event DB Value", style="bright_white")
        table.add_row("Execution State", parts[0] if len(parts) > 0 else "")
        table.add_row("Client Status", parts[1] if len(parts) > 1 else "")
        table.add_row("Anomaly Score", parts[2] if len(parts) > 2 else "")
        table.add_row("Backend Effect", parts[3] if len(parts) > 3 else "")
        table.add_row("Metric Cell", parts[4] if len(parts) > 4 else "")
        table.add_row("Matched Rules", parts[5] if len(parts) > 5 else "")
        console.print(table)
    else:
        console.print(f"  [dim]• Not yet synchronized to PostgreSQL event-db[/dim]")
    console.print()


# ==============================================================================
# 7. SYSTEM STATUS & HEALTH CHECK
# ==============================================================================

def show_system_status():
    """Checks the health and status of all 7 containers and WAF endpoints."""
    console.print()
    console.print(Panel(
        "[bold bright_white]WAFBENCH SYSTEM HEALTH & TOPOLOGY STATUS[/bold bright_white]",
        box=box.ROUNDED,
        border_style="cyan"
    ))

    table = Table(box=box.ROUNDED, expand=True)
    table.add_column("Component", style="bold cyan", no_wrap=True)
    table.add_column("Target / Container", style="yellow")
    table.add_column("Status", no_wrap=True)
    table.add_column("Details", style="bright_white")

    # 1. Gateway
    try:
        r = requests.get(f"{GATEWAY_URL}/health", timeout=3.0)
        table.add_row("WAF Gateway", "wb-gateway (:8080)", "[bold green]ONLINE (200)[/bold green]", f"Server: {r.headers.get('Server', 'nginx')}")
    except Exception as e:
        table.add_row("WAF Gateway", "wb-gateway (:8080)", "[bold red]OFFLINE[/bold red]", str(e)[:34])

    # 2. Direct App
    try:
        r = requests.get(f"{DIRECT_URL}/health", timeout=3.0)
        table.add_row("Direct App", "wb-app (:8001)", "[bold green]ONLINE (200)[/bold green]", f"Express DB: {'CONNECTED' if 'CONNECTED' in r.text else 'DEGRADED'}")
    except Exception as e:
        table.add_row("Direct App", "wb-app (:8001)", "[bold red]OFFLINE[/bold red]", str(e)[:34])

    # 3. App DB Fixture
    try:
        counts = get_fixture_counts()
        table.add_row("App Database", "wb-app-db (PG 16)", "[bold green]CONNECTED[/bold green]", f"Users: {counts['users']}, Articles: {counts['articles']}, Sessions: {counts['sessions']}")
    except Exception as e:
        table.add_row("App Database", "wb-app-db (PG 16)", "[bold red]ERROR[/bold red]", str(e)[:34])

    # 4. Mock Internal
    try:
        logs = get_mock_logs()
        table.add_row("Mock Internal", "wb-mock (:8080 int)", "[bold green]ONLINE[/bold green]", f"Access logs recorded: {len(logs)}")
    except Exception as e:
        table.add_row("Mock Internal", "wb-mock (:8080 int)", "[bold red]ERROR[/bold red]", str(e)[:34])

    # 5. Event DB
    rc, out, _ = docker_exec("wb-event-db", ["psql", "-U", "telemetry_user", "-d", "wafbench_events", "-t", "-A", "-c", "SELECT count(*) FROM normalized_events;"])
    if rc == 0:
        table.add_row("Telemetry Event DB", "wb-event-db (PG 16)", "[bold green]CONNECTED[/bold green]", f"Normalized events count: {out.strip()}")
    else:
        table.add_row("Telemetry Event DB", "wb-event-db (PG 16)", "[bold red]ERROR[/bold red]", "Could not query event-db")

    # 6. Current WAF Mode
    rc, out, _ = docker_exec("wb-gateway", ["grep", "-i", "SecRuleEngine", "/etc/modsecurity.d/main.conf"])
    mode_text = out.strip() if rc == 0 else "Unknown"
    table.add_row("ModSecurity Mode", "SecRuleEngine", "[bold yellow]CONFIGURED[/bold yellow]", mode_text)

    console.print(table)
    console.print()


# ==============================================================================
# INTERACTIVE TERMINAL MENU
# ==============================================================================

def interactive_menu():
    """Main interactive menu loop."""
    while True:
        console.clear()
        console.print(Panel(
            "[bold bright_cyan]===================================================================\n"
            "        WAFBENCH INTERACTIVE DIAGNOSTIC & WORKFLOW CLI             \n"
            "        Empirical 3-Tier Evidence & 3-State Evaluation Engine      \n"
            "===================================================================[/bold bright_cyan]\n"
            f"[dim]Gateway: {GATEWAY_URL} | Direct: {DIRECT_URL}[/dim]",
            box=box.DOUBLE,
            border_style="cyan"
        ))

        console.print("[bold bright_white]Main Navigation Menu:[/bold bright_white]\n")
        console.print("  [bold cyan][1][/bold cyan] 📊 System Architecture & 3-Tier Data Workflow Diagram")
        console.print("  [bold cyan][2][/bold cyan] 🎯 Interactive Live Probe Walkthrough (Step-by-Step 3-Tier Trace)")
        console.print("  [bold cyan][3][/bold cyan] ⚖️  3-State Comparative Analysis (Direct vs DetectionOnly vs Blocking)")
        console.print("  [bold cyan][4][/bold cyan] 📂 Test Corpus Explorer (Browse & Inspect 32 Cases)")
        console.print("  [bold cyan][5][/bold cyan] 🚀 Run Benchmark Suite & View Formal Metrics (DR, BR, FPR, RPR)")
        console.print("  [bold cyan][6][/bold cyan] 🔍 Forensic Evidence Inspector (Query Transaction by UUID)")
        console.print("  [bold cyan][7][/bold cyan] 🩺 System Health & Container Topology Status")
        console.print("  [bold red][0][/bold red] 🚪 Exit\n")

        choice = Prompt.ask("[bold yellow]Enter selection[/bold yellow]", choices=["1", "2", "3", "4", "5", "6", "7", "0"], default="1")

        if choice == "1":
            show_workflow_diagram()
            Prompt.ask("\n[dim]Press Enter to return to main menu...[/dim]")

        elif choice == "2":
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

            console.print("\n[bold]Select Evaluation State:[/bold]")
            console.print("  [cyan][1][/cyan] State 1: Direct-to-App (:8001) [dim][App baseline, no WAF][/dim]")
            console.print("  [cyan][2][/cyan] State 2: DetectionOnly (:8080) [dim][CRS active, no disruption][/dim]")
            console.print("  [cyan][3][/cyan] State 3: Blocking (:8080)      [dim][CRS active, 403 block][/dim]")
            s_pick = Prompt.ask("Select State", choices=["1", "2", "3"], default="3")
            state_map = {"1": "Direct-to-App", "2": "DetectionOnly", "3": "Blocking"}

            execute_probe_walkthrough(case, state_map[s_pick])
            Prompt.ask("\n[dim]Press Enter to return to main menu...[/dim]")

        elif choice == "3":
            cases = load_cases()
            console.print("\n[bold]Select Case for 3-State Replay Comparison:[/bold]")
            console.print("  [cyan][1][/cyan] SQLI-001   (SQL Injection Auth Bypass)")
            console.print("  [cyan][2][/cyan] XSS-001    (Reflected XSS)")
            console.print("  [cyan][3][/cyan] PATH-001   (Path Traversal /etc/passwd)")
            console.print("  [cyan][4][/cyan] SSRF-001   (SSRF Mock Internal)")
            console.print("  [cyan][5][/cyan] Other Case ID")
            c_pick = Prompt.ask("Select option", choices=["1", "2", "3", "4", "5"], default="1")
            quick_cases = {"1": "SQLI-001", "2": "XSS-001", "3": "PATH-001", "4": "SSRF-001"}
            if c_pick == "5":
                all_ids = [c["case_id"] for c in cases]
                chosen_id = Prompt.ask("Enter Case ID", choices=all_ids, default=all_ids[0])
            else:
                chosen_id = quick_cases[c_pick]
            
            case = get_case_by_id(chosen_id)
            if case:
                run_3state_comparison(case)
            Prompt.ask("\n[dim]Press Enter to return to main menu...[/dim]")

        elif choice == "4":
            show_corpus_explorer()
            Prompt.ask("\n[dim]Press Enter to return to main menu...[/dim]")

        elif choice == "5":
            reps = int(Prompt.ask("Repetitions per case", default="1"))
            run_benchmark_suite(reps=reps)
            Prompt.ask("\n[dim]Press Enter to return to main menu...[/dim]")

        elif choice == "6":
            cid = Prompt.ask("Enter X-Request-ID (UUIDv4)")
            if cid.strip():
                inspect_forensic_evidence(cid.strip())
            Prompt.ask("\n[dim]Press Enter to return to main menu...[/dim]")

        elif choice == "7":
            show_system_status()
            Prompt.ask("\n[dim]Press Enter to return to main menu...[/dim]")

        elif choice == "0":
            console.print("\n[bold cyan]Exiting WAFBench CLI. Goodbye![/bold cyan]\n")
            sys.exit(0)


# ==============================================================================
# MAIN ENTRYPOINT & ARGPARSE
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="WAFBench CLI Diagnostic & Workflow Tool")
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    # workflow / diagram
    subparsers.add_parser("workflow", help="Show system architecture and data workflow diagram")

    # probe
    probe_parser = subparsers.add_parser("probe", help="Run interactive probe walkthrough")
    probe_parser.add_argument("--case", type=str, default="SQLI-001", help="Case ID to test")
    probe_parser.add_argument("--state", type=str, choices=STATES, default="Blocking", help="Evaluation state")

    # compare
    comp_parser = subparsers.add_parser("compare", help="Run 3-state comparative matrix")
    comp_parser.add_argument("--case", type=str, default="SQLI-001", help="Case ID to compare")

    # corpus
    corp_parser = subparsers.add_parser("corpus", help="Browse corpus cases")
    corp_parser.add_argument("--family", type=str, default=None, help="Filter by attack family")

    # benchmark
    bench_parser = subparsers.add_parser("run", help="Run automated benchmark suite")
    bench_parser.add_argument("--reps", type=int, default=1, help="Repetitions per case")
    bench_parser.add_argument("--state", type=str, choices=STATES, default=None, help="Filter by state")

    # inspect
    insp_parser = subparsers.add_parser("inspect", help="Inspect evidence for correlation ID")
    insp_parser.add_argument("uuid", type=str, help="X-Request-ID UUIDv4 to look up")

    # status
    subparsers.add_parser("status", help="Show system health and container status")

    args = parser.parse_args()

    if not args.command:
        # Launch interactive menu if no arguments passed
        interactive_menu()
    elif args.command == "workflow":
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
        run_3state_comparison(case)
    elif args.command == "corpus":
        show_corpus_explorer(filter_family=args.family)
    elif args.command == "run":
        run_benchmark_suite(reps=args.reps, state_filter=args.state)
    elif args.command == "inspect":
        inspect_forensic_evidence(args.uuid)
    elif args.command == "status":
        show_system_status()


if __name__ == "__main__":
    main()
