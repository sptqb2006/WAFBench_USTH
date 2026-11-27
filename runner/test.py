#!/usr/bin/env python3
"""
WAFBench CLI Test Runner: Orchestrates 3-State Replay with Independent Oracles
Author: Kieu Dang Vuong

Usage:
    python runner/test.py                                   # full batch
    python runner/test.py --case SQLI-001 --state DetectionOnly --reps 1
"""

import os
import sys
import json
import time
import uuid
import argparse
import subprocess

import pandas as pd
import requests

import manager
from manager import RequestManager, set_waf_mode, wait_gateway_ready, mode_canary, find_waf_evidence, seen_by_app
from oracle.sqli_oracle import check_sqli_backend_effect, get_fixture_counts
from oracle.xss_lfi_ssrf_oracle import (
    check_xss_reflection, check_lfi_file_disclosure, check_ssrf_mock_access, get_mock_logs, xss_probe_for
)
from oracle.validity_oracle import classify_validity, assign_metric_cell
from latency import LatencyProfiler
from report import (
    apply_baseline_gate, mark_flaky, calculate_metrics, export_csv, export_summary_csv, print_summary
)
try:
    from sync import sync_csv_to_event_db
except ImportError:
    sync_csv_to_event_db = None

RUNNER_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(RUNNER_DIR)


def load_dotenv(path: str) -> dict:
    values = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fp:
            for line in fp:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    values[k.strip()] = v.strip()
    return values


_DOTENV = load_dotenv(os.path.join(REPO_DIR, ".env"))


def setting(name: str, default: str) -> str:
    return os.getenv(name) or _DOTENV.get(name) or default


# Configuration Targets
DIRECT_URL = os.getenv("DIRECT_APP_URL", f"http://127.0.0.1:{setting('DIRECT_APP_PORT', '8001')}")
GATEWAY_URL = os.getenv("GATEWAY_URL", f"http://127.0.0.1:{setting('GATEWAY_PORT', '8080')}")

STATES = ["Direct-to-App", "DetectionOnly", "Blocking"]
ENGINE_FOR_STATE = {"DetectionOnly": "DetectionOnly", "Blocking": "On"}
REPETITIONS = 3
FIXTURE = {"users": 3, "articles": 3, "sessions": 0}
REQUIRED_FIELDS = ("case_id", "family", "label", "endpoint", "method")


def load_all_cases() -> list:
    cases_dir = os.path.join(REPO_DIR, "corpus", "cases")
    cases = []
    for root, _, files in os.walk(cases_dir):
        for f in files:
            if f.endswith(".json"):
                with open(os.path.join(root, f), "r", encoding="utf-8") as fp:
                    case = json.load(fp)
                missing = [k for k in REQUIRED_FIELDS if k not in case]
                if missing:
                    sys.exit(f"[!] {f}: missing required fields {missing}")
                cases.append(case)
    return sorted(cases, key=lambda x: x["case_id"])


def check_health(base_url: str) -> tuple:
    try:
        r = requests.get(f"{base_url}/health", timeout=3.0)
    except Exception as e:
        return False, f"/health unreachable: {e}"
    if r.status_code != 200:
        return False, f"/health returned {r.status_code}"
    if "CONNECTED" not in r.text:
        return False, "/health reports database not connected"
    return True, ""


def trigger_reset(direct_url: str, profiler: LatencyProfiler) -> tuple:
    start = time.perf_counter()
    try:
        r = requests.post(f"{direct_url}/health/reset", timeout=5.0)
    except Exception as e:
        return False, f"reset failed: {e}"
    profiler.record_reset((time.perf_counter() - start) * 1000)
    if r.status_code != 200:
        return False, f"reset returned {r.status_code}"
    return True, ""


def verify_fixture() -> tuple:
    """F1 fixture after reset: 3 users, 3 articles, 0 sessions, no tracked mock traffic."""
    try:
        counts = get_fixture_counts()
        mock_hits = [e for e in get_mock_logs() if e.get("correlation_id") != "anonymous"]
    except Exception as e:
        return False, f"fixture check failed: {e}"
    if counts != FIXTURE:
        return False, f"fixture mismatch: {counts}"
    if mock_hits:
        return False, f"mock logs not empty after reset ({len(mock_hits)} entries)"
    return True, ""


def run_oracle(case: dict, client_res: dict, correlation_id: str) -> dict:
    family = case["family"]
    if family == "SQL Injection":
        submitted_user = json.loads(case.get("body") or "{}").get("username", "")
        return check_sqli_backend_effect(submitted_user)
    if family == "Reflected XSS":
        return check_xss_reflection(client_res, xss_probe_for(case))
    if family == "Path Traversal":
        return check_lfi_file_disclosure(client_res)
    if family == "SSRF":
        return check_ssrf_mock_access(correlation_id)
    return {"backend_effect": False, "observation": f"No oracle for family {family}"}


def git_commit() -> str:
    try:
        return subprocess.check_output(["git", "-C", REPO_DIR, "rev-parse", "--short", "HEAD"], text=True).strip()
    except Exception:
        return "unknown"


def gateway_settings() -> str:
    rc, out, _ = manager.docker_exec(manager.GATEWAY_CONTAINER, ["printenv"])
    if rc != 0:
        return "unavailable"
    keys = ("MODSEC_RULE_ENGINE", "PARANOIA", "BLOCKING_PARANOIA", "ANOMALY_INBOUND", "ANOMALY_OUTBOUND")
    pairs = [l for l in out.splitlines() if l.split("=", 1)[0] in keys]
    return "; ".join(sorted(pairs))


def prepare_state(state: str) -> tuple:
    """Switches the WAF engine for a WAF state and confirms it with the canary."""
    ok, err = set_waf_mode(ENGINE_FOR_STATE[state])
    if not ok:
        return False, f"mode switch failed: {err}"
    if not wait_gateway_ready(GATEWAY_URL):
        return False, "gateway not ready after reload"
    # Old nginx workers keep serving the previous mode for a moment after reload
    deadline = time.time() + 10.0
    while True:
        ok, reason = mode_canary(GATEWAY_URL, state)
        if ok or time.time() >= deadline:
            return ok, reason
        time.sleep(0.5)


def parse_args():
    p = argparse.ArgumentParser(description="WAFBench three-state test runner")
    p.add_argument("--case", action="append", help="case_id to run (repeatable or comma-separated)")
    p.add_argument("--state", action="append", choices=STATES, help="state to run (repeatable)")
    p.add_argument("--reps", type=int, default=REPETITIONS, help="repetitions per case")
    return p.parse_args()


def run_experiment_batch():
    args = parse_args()
    cases = load_all_cases()
    if args.case:
        wanted = {c.strip() for arg in args.case for c in arg.split(",") if c.strip()}
        unknown = wanted - {c["case_id"] for c in cases}
        if unknown:
            sys.exit(f"[!] Unknown case_id: {sorted(unknown)}")
        cases = [c for c in cases if c["case_id"] in wanted]
    if not cases:
        print("[!] No test cases found in corpus/cases! Run corpus/script/generator.py first.")
        sys.exit(1)
    states = [s for s in STATES if not args.state or s in args.state]

    print("=" * 70)
    print("           WAFBench Automated Three-State Test Execution")
    print(f"Loaded: {len(cases)} test cases | States: {len(states)} | Repetitions: {args.reps}")
    print(f"Direct: {DIRECT_URL} | Gateway: {GATEWAY_URL}")
    print("=" * 70)

    mgr = RequestManager()
    profiler = LatencyProfiler()
    batch_id = f"batch_{int(time.time())}"
    started = time.strftime("%Y-%m-%dT%H:%M:%S")
    results = []

    print("[*] Checking baseline environment readiness...")
    ok, reason = check_health(DIRECT_URL)
    if not ok:
        print(f"[!] Target app is NOT ready at {DIRECT_URL}: {reason}")
        print("[!] Make sure the Docker environment is running (`make up`).")
        return

    audit_source = manager.resolve_audit_source() if any(s != "Direct-to-App" for s in states) else "n/a"
    print(f"[*] WAF audit source: {audit_source}")

    try:
        for state in states:
            is_waf = state != "Direct-to-App"
            target_url = GATEWAY_URL if is_waf else DIRECT_URL
            print(f"\n>>> [STATE: {state.upper()}] (Target: {target_url}) <<<")

            mode_ok, mode_reason = (True, "")
            if is_waf:
                mode_ok, mode_reason = prepare_state(state)
                print(f"  [mode] {'OK' if mode_ok else 'FAILED'}: {mode_reason}")

            for case in cases:
                # Re-check the mode before each case so a silent change is caught early
                if is_waf:
                    mode_ok, mode_reason = mode_canary(GATEWAY_URL, state)

                for rep in range(1, args.reps + 1):
                    correlation_id = str(uuid.uuid4())
                    preconditions = {"mode_verified": mode_ok, "mode_reason": mode_reason}

                    health_ok, health_reason = check_health(DIRECT_URL)
                    preconditions.update(health_ok=health_ok, health_reason=health_reason)

                    reset_ok, fixture_reason = trigger_reset(DIRECT_URL, profiler)
                    if reset_ok:
                        reset_ok, fixture_reason = verify_fixture()
                    preconditions.update(fixture_verified=reset_ok, fixture_reason=fixture_reason)
                    reset_ms = profiler.reset_times[-1] if profiler.reset_times else None

                    client_res = mgr.send_request(target_url, case, correlation_id)
                    profiler.record_request(state, client_res.get("latency_ms"))

                    waf_data = None
                    if is_waf:
                        waf_data = find_waf_evidence(correlation_id, timeout=3.0, source=audit_source)
                        if not waf_data["found"]:
                            preconditions["seen_by_app"] = seen_by_app(correlation_id)

                    oracle_res = run_oracle(case, client_res, correlation_id)
                    backend_effect = bool(oracle_res.get("backend_effect"))

                    validity_code, is_valid, reason = classify_validity(preconditions, client_res, waf_data, state)
                    metric_cell = assign_metric_cell(state, case["label"], waf_data, client_res)

                    waf = waf_data or {}
                    record = {
                        "batch_id": batch_id,
                        "case_id": case["case_id"],
                        "family": case["family"],
                        "label": case["label"],
                        "state": state,
                        "repetition": rep,
                        "correlation_id": correlation_id,
                        "client_status": client_res.get("status_code"),
                        "latency_ms": round(client_res["latency_ms"], 2) if client_res.get("latency_ms") else None,
                        "reset_ms": round(reset_ms, 2) if reset_ms else None,
                        "request_sha256": client_res.get("request_sha256"),
                        "backend_effect": backend_effect,
                        "oracle_observation": oracle_res.get("observation"),
                        "waf_found": waf.get("found"),
                        "waf_detected": waf.get("detected"),
                        "matched_rule_ids": ",".join(waf.get("matched_rule_ids", [])),
                        "anomaly_score": waf.get("anomaly_score"),
                        "waf_http_code": waf.get("waf_http_code"),
                        "validity": validity_code,
                        "invalid_reason": None if is_valid else reason,
                        "metric_cell": metric_cell,
                    }
                    results.append(record)

                    print(f"  [{state[:6]}] {case['case_id']:<12} (rep {rep}) -> HTTP {record['client_status']} | "
                          f"Effect: {backend_effect} | WAF: {record['matched_rule_ids'] or '-'} | "
                          f"{validity_code} | {metric_cell}")
    finally:
        if any(s != "Direct-to-App" for s in states):
            ok, err = set_waf_mode("DetectionOnly")
            print(f"\n[*] WAF mode restored to DetectionOnly{'' if ok else ' FAILED: ' + err}")

    if not results:
        return

    if "Direct-to-App" in states:
        results = apply_baseline_gate(results, cases)
    results = mark_flaky(results)

    results_dir = os.path.join(RUNNER_DIR, "results")
    export_csv(results, os.path.join(results_dir, f"{batch_id}.csv"))
    summary = export_summary_csv(results, os.path.join(results_dir, f"{batch_id}_summary.csv"))

    latency = profiler.summary()
    meta = {
        "batch_id": batch_id,
        "started": started,
        "finished": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "commit": git_commit(),
        "gateway_env": gateway_settings(),
        "audit_source": audit_source,
        "states": "|".join(states),
        "repetitions": args.reps,
        "cases": len(cases),
        "direct_url": DIRECT_URL,
        "gateway_url": GATEWAY_URL,
    }
    pd.DataFrame(list(meta.items()), columns=["key", "value"]).to_csv(
        os.path.join(results_dir, f"{batch_id}_meta.csv"), index=False
    )

    print_summary(calculate_metrics(results), summary, latency)

    csv_path = os.path.join(results_dir, f"{batch_id}.csv")
    if sync_csv_to_event_db:
        try:
            print("[*] Synchronizing benchmark records to PostgreSQL event-db...")
            sync_csv_to_event_db(csv_path)
        except Exception as e:
            print(f"[-] Event-DB sync skipped or failed: {e}")

    print("\n[OK] Batch run complete!")


if __name__ == "__main__":
    run_experiment_batch()
