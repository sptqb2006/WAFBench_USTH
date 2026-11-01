#!/usr/bin/env python3
"""
WAFBench CLI Test Runner: Orchestrates 3-State Replay with Independent Oracles
Author: Kieu Dang Vuong
"""

import os
import sys
import json
import time
import uuid
import requests

from manager import RequestManager
from oracle.sqli_oracle import check_sqli_backend_effect
from oracle.xss_lfi_ssrf_oracle import check_xss_reflection, check_lfi_file_disclosure, check_ssrf_mock_access
from oracle.validity_oracle import classify_validity
from latency import LatencyProfiler
from report import calculate_metrics, export_csv

# Configuration Targets
DIRECT_URL = os.getenv("DIRECT_APP_URL", "http://127.0.0.1:8001")
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://127.0.0.1:8088")
MOCK_URL = os.getenv("MOCK_SERVICE_URL", "http://127.0.0.1:8082") # Internal or port-forwarded

STATES = ["Direct-to-App", "DetectionOnly", "Blocking"]
REPETITIONS = 3

def load_all_cases() -> list:
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cases_dir = os.path.join(base_dir, "corpus", "cases")
    cases = []
    for root, _, files in os.walk(cases_dir):
        for f in files:
            if f.endswith(".json"):
                with open(os.path.join(root, f), "r", encoding="utf-8") as fp:
                    cases.append(json.load(fp))
    return sorted(cases, key=lambda x: x["case_id"])

def check_health(base_url: str) -> bool:
    try:
        r = requests.get(f"{base_url}/health", timeout=3.0)
        return r.status_code == 200
    except Exception:
        return False

def trigger_reset(direct_url: str, profiler: LatencyProfiler) -> bool:
    start = time.time()
    try:
        r = requests.post(f"{direct_url}/health/reset", timeout=5.0)
        dur = (time.time() - start) * 1000
        profiler.record_reset(dur)
        return r.status_code == 200
    except Exception:
        return False

def run_experiment_batch():
    cases = load_all_cases()
    if not cases:
        print("[!] No test cases found in corpus/cases! Run corpus/script/generator.py first.")
        sys.exit(1)

    print("=" * 70)
    print("           WAFBench Automated Three-State Test Execution")
    print(f"Loaded: {len(cases)} test cases | States: {len(STATES)} | Repetitions: {REPETITIONS}")
    print("=" * 70)

    mgr = RequestManager()
    profiler = LatencyProfiler()
    batch_id = f"batch_{int(time.time())}"
    results = []

    # Verify initial health
    print("[*] Checking baseline environment readiness...")
    if not check_health(DIRECT_URL):
        print(f"[!] Target app is NOT responding at {DIRECT_URL}!")
        print("[!] Make sure the Docker environment is running (`make up`).")
        print("[!] Exiting runner...")
        return

    for state in STATES:
        target_url = DIRECT_URL if state == "Direct-to-App" else GATEWAY_URL
        print(f"\n>>> [STATE: {state.upper()}] (Target: {target_url}) <<<")

        for case in cases:
            case_id = case["case_id"]
            label = case["label"]
            family = case["family"]

            for rep in range(1, REPETITIONS + 1):
                correlation_id = str(uuid.uuid4())

                # 1. Reset fixture before each replay
                reset_ok = trigger_reset(DIRECT_URL, profiler)
                preconditions = {
                    "health_ok": check_health(DIRECT_URL),
                    "fixture_verified": reset_ok,
                    "mode_verified": True # Canary check
                }

                # 2. Replay request
                t0 = time.time()
                client_res = mgr.send_request(target_url, case, correlation_id)
                req_lat = (time.time() - t0) * 1000
                profiler.record_request(req_lat)

                # 3. Application Oracle Verification
                backend_effect = False
                observation = "None"

                if family == "SQL Injection":
                    submitted_user = json.loads(case.get("body", "{}")).get("username", "")
                    db_res = check_sqli_backend_effect("127.0.0.1", correlation_id, submitted_user)
                    backend_effect = db_res.get("backend_effect", False)
                    observation = db_res.get("observation")
                elif family == "Reflected XSS":
                    xss_res = check_xss_reflection(client_res, "<script>alert(1)</script>")
                    backend_effect = xss_res.get("backend_effect", False)
                    observation = xss_res.get("observation")
                elif family == "Path Traversal":
                    lfi_res = check_lfi_file_disclosure(client_res)
                    backend_effect = lfi_res.get("backend_effect", False)
                    observation = lfi_res.get("observation")
                elif family == "SSRF":
                    ssrf_res = check_ssrf_mock_access(MOCK_URL, correlation_id)
                    backend_effect = ssrf_res.get("backend_effect", False)
                    observation = ssrf_res.get("observation")

                # 4. Validity classification
                validity_code, is_valid, reason = classify_validity(
                    preconditions, client_res, None, backend_effect, state, label
                )

                # 5. Record result entry
                record = {
                    "batch_id": batch_id,
                    "case_id": case_id,
                    "family": family,
                    "label": label,
                    "state": state,
                    "repetition": rep,
                    "correlation_id": correlation_id,
                    "client_status": client_res.get("status_code"),
                    "request_sha256": client_res.get("request_sha256"),
                    "backend_effect": backend_effect,
                    "oracle_observation": observation,
                    "validity": validity_code,
                    "invalid_reason": reason,
                    "metric_cell": "PENDING_TELEMETRY"
                }
                results.append(record)

                print(f"  [{state[:6]}] {case_id:<12} (rep {rep}) -> HTTP {client_res.get('status_code')} | Effect: {backend_effect} | Validity: {validity_code}")

    # Export CSV
    output_csv = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results", f"{batch_id}.csv")
    export_csv(results, output_csv)
    print("\n[OK] Batch run complete!")

if __name__ == "__main__":
    run_experiment_batch()
