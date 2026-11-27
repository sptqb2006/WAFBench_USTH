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
import subprocess
from collections import deque
import requests

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    psycopg2 = None
    RealDictCursor = None

from manager import RequestManager
from oracle.sqli_oracle import check_sqli_backend_effect
from oracle.xss_lfi_ssrf_oracle import (
    extract_xss_probe,
    check_xss_reflection,
    check_lfi_file_disclosure,
    check_ssrf_mock_access,
)
from oracle.validity_oracle import classify_validity
from latency import LatencyProfiler
from report import calculate_metrics, export_csv

# Configuration Targets
DIRECT_URL = os.getenv("DIRECT_APP_URL", "http://127.0.0.1:8001")
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://127.0.0.1:8080")
MOCK_URL = os.getenv("MOCK_SERVICE_URL", "http://127.0.0.1:8080")
GATEWAY_CONTAINER = os.getenv("GATEWAY_CONTAINER", "wb-gateway")

STATES = ["Direct-to-App", "DetectionOnly", "Blocking"]
REPETITIONS = 3

# Controlled-environment rate limiter: default 5 requests per 2 seconds
RATE_LIMIT_MAX = int(os.getenv("RATE_LIMIT_REQUESTS", "5"))
RATE_LIMIT_WINDOW = float(os.getenv("RATE_LIMIT_WINDOW_SEC", "2.0"))


class RateLimiter:
    """Fixed sliding-window rate limiter for consistent experiment pacing."""

    def __init__(self, max_requests: int = 5, window_seconds: float = 2.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.timestamps = deque()

    def wait(self):
        if self.max_requests <= 0 or self.window_seconds <= 0:
            return
        now = time.monotonic()
        while self.timestamps and (now - self.timestamps[0]) >= self.window_seconds:
            self.timestamps.popleft()

        if len(self.timestamps) >= self.max_requests:
            sleep_for = self.window_seconds - (now - self.timestamps[0])
            if sleep_for > 0:
                time.sleep(sleep_for)
            now = time.monotonic()
            while self.timestamps and (now - self.timestamps[0]) >= self.window_seconds:
                self.timestamps.popleft()

        self.timestamps.append(time.monotonic())


def get_event_db_connection():
    """Connects to PostgreSQL event-db if psycopg2 and the DB are available."""
    if psycopg2 is None:
        return None
    try:
        return psycopg2.connect(
            host=os.getenv("EVENT_DB_HOST", "127.0.0.1"),
            port=int(os.getenv("EVENT_DB_PORT", "5432")),
            dbname=os.getenv("EVENT_DB_NAME", "wafbench_events"),
            user=os.getenv("EVENT_DB_USER", "telemetry_user"),
            password=os.getenv("EVENT_DB_PASSWORD", "telemetry_secret_pass"),
            connect_timeout=3,
        )
    except Exception as e:
        print(f"[!] Could not connect to event-db: {e}")
        return None


def insert_normalized_event(
    conn,
    run_id: str,
    batch_id: str,
    case: dict,
    state: str,
    rep: int,
    correlation_id: str,
    client_res: dict,
):
    """Inserts the base client event record into normalized_events immediately on send."""
    if conn is None:
        return
    snippet = (client_res.get("text") or "")[:500]
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO normalized_events (
                    run_id, batch_id, case_id, family_id, label, state,
                    repetition, correlation_id, method, endpoint,
                    client_status, request_sha256, response_body_snippet
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    run_id,
                    batch_id,
                    case["case_id"],
                    case["family"],
                    case["label"],
                    state,
                    rep,
                    correlation_id,
                    case.get("method", "GET"),
                    case.get("endpoint", ""),
                    client_res.get("status_code"),
                    client_res.get("request_sha256"),
                    snippet,
                ),
            )
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[!] Failed to INSERT normalized_events ({correlation_id}): {e}")


def update_event_oracle_validity(
    conn,
    correlation_id: str,
    backend_effect: bool,
    observation: str,
    validity_code: str,
    reason: str,
):
    """Updates backend oracle and validity fields on the normalized_events record."""
    if conn is None:
        return
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE normalized_events
                SET backend_effect = %s,
                    oracle_observation = %s,
                    validity = %s,
                    invalid_reason = %s
                WHERE correlation_id = %s
                """,
                (backend_effect, observation, validity_code, reason, correlation_id),
            )
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[!] Failed to UPDATE normalized_events ({correlation_id}): {e}")


def fetch_waf_telemetry(
    conn,
    correlation_id: str,
    state: str,
    max_retries: int = 5,
    poll_interval: float = 0.4,
) -> dict | None:
    """
    Polls normalized_events by correlation_id to retrieve WAF telemetry written
    by telemetry-worker before calling classify_validity(...).
    """
    if conn is None or state == "Direct-to-App":
        return None

    for attempt in range(max_retries):
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT waf_txn_id, matched_rule_ids, inbound_score,
                           disruptive_action, interrupt_phase, audit_ref
                    FROM normalized_events
                    WHERE correlation_id = %s
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (correlation_id,),
                )
                row = cur.fetchone()
            if row and (row.get("waf_txn_id") or row.get("disruptive_action")):
                return dict(row)
        except Exception as e:
            print(f"[!] Error querying WAF telemetry ({correlation_id}): {e}")
            return None

        if attempt < max_retries - 1:
            time.sleep(poll_interval)

    return None


def switch_waf_mode(state: str, container: str = GATEWAY_CONTAINER) -> bool:
    """Switches ModSecurity SecRuleEngine between DetectionOnly and On and reloads Nginx."""
    if state == "Direct-to-App":
        return True

    engine_mode = "DetectionOnly" if state == "DetectionOnly" else "On"
    try:
        subprocess.run(
            [
                "docker",
                "exec",
                container,
                "sed",
                "-i",
                f"s/SecRuleEngine .*/SecRuleEngine {engine_mode}/",
                "/etc/modsecurity.d/main.conf",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        subprocess.run(
            ["docker", "exec", container, "nginx", "-s", "reload"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(1.0)
        return True
    except Exception as e:
        print(f"[!] Failed to switch WAF mode to {engine_mode}: {e}")
        return False


def verify_waf_mode_canary(gateway_url: str, state: str, mgr: RequestManager) -> bool:
    """
    Sends a deterministic canary XSS probe through the gateway to verify
    that the active WAF profile matches the expected phase behavior.
    """
    if state == "Direct-to-App":
        return True

    canary_case = {
        "endpoint": "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "method": "GET",
        "headers": {"X-Request-ID": "{correlation_id}", "Host": "{host}"},
        "body": "",
    }
    canary_id = f"canary-{state.lower()}-{uuid.uuid4().hex[:8]}"
    res = mgr.send_request(gateway_url, canary_case, canary_id)
    status = res.get("status_code")

    if state == "DetectionOnly":
        return status == 200
    if state == "Blocking":
        return status == 403
    return False


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
    print(f"Rate Limit: {RATE_LIMIT_MAX} requests / {RATE_LIMIT_WINDOW}s")
    print("=" * 70)

    mgr = RequestManager()
    profiler = LatencyProfiler()
    rate_limiter = RateLimiter(RATE_LIMIT_MAX, RATE_LIMIT_WINDOW)
    batch_id = f"batch_{int(time.time())}"
    run_id = f"run_{uuid.uuid4().hex[:8]}"
    results = []

    db_conn = get_event_db_connection()
    if db_conn:
        print("[*] Connected to event-db for live normalized_events logging.")
    else:
        print("[!] Running without live event-db connection (CSV-only fallback).")

    # Verify initial health
    print("[*] Checking baseline environment readiness...")
    if not check_health(DIRECT_URL):
        print(f"[!] Target app is NOT responding at {DIRECT_URL}!")
        print("[!] Make sure the Docker environment is running (`make up`).")
        print("[!] Exiting runner...")
        if db_conn:
            db_conn.close()
        return

    try:
        for state in STATES:
            target_url = DIRECT_URL if state == "Direct-to-App" else GATEWAY_URL
            print(f"\n>>> [STATE: {state.upper()}] (Target: {target_url}) <<<")

            # Switch SecRuleEngine and verify active WAF mode via canary check
            switched_ok = switch_waf_mode(state)
            mode_verified = switched_ok and verify_waf_mode_canary(GATEWAY_URL, state, mgr)
            if state != "Direct-to-App":
                print(f"[*] WAF Mode '{state}' switch={switched_ok} | canary mode_verified={mode_verified}")

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
                        "mode_verified": mode_verified,
                    }

                    # 2. Rate-limited replay request
                    rate_limiter.wait()
                    t0 = time.time()
                    client_res = mgr.send_request(target_url, case, correlation_id)
                    req_lat = (time.time() - t0) * 1000
                    profiler.record_request(req_lat)

                    # Insert initial record into normalized_events immediately
                    insert_normalized_event(
                        db_conn, run_id, batch_id, case, state, rep, correlation_id, client_res
                    )

                    # 3. Application Oracle Verification
                    backend_effect = False
                    observation = "None"

                    if family == "SQL Injection":
                        submitted_user = json.loads(case.get("body", "{}")).get("username", "")
                        db_res = check_sqli_backend_effect("127.0.0.1", correlation_id, submitted_user)
                        backend_effect = db_res.get("backend_effect", False)
                        observation = db_res.get("observation")
                    elif family == "Reflected XSS":
                        xss_probe = extract_xss_probe(case)
                        xss_res = check_xss_reflection(client_res, xss_probe)
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

                    # 4. Query WAF telemetry from event-db & classify validity
                    waf_data = fetch_waf_telemetry(db_conn, correlation_id, state)
                    validity_code, is_valid, reason = classify_validity(
                        preconditions, client_res, waf_data, backend_effect, state, label
                    )
                    update_event_oracle_validity(
                        db_conn, correlation_id, backend_effect, observation, validity_code, reason
                    )

                    # 5. Record result entry
                    record = {
                        "run_id": run_id,
                        "batch_id": batch_id,
                        "case_id": case_id,
                        "family": family,
                        "label": label,
                        "state": state,
                        "repetition": rep,
                        "correlation_id": correlation_id,
                        "client_status": client_res.get("status_code"),
                        "response_time_ms": round(req_lat, 2),
                        "request_sha256": client_res.get("request_sha256"),
                        "waf_disruptive_action": waf_data.get("disruptive_action") if waf_data else None,
                        "backend_effect": backend_effect,
                        "oracle_observation": observation,
                        "validity": validity_code,
                        "invalid_reason": reason,
                        "metric_cell": "PENDING_TELEMETRY" if waf_data is None else "CORRELATED",
                    }
                    results.append(record)

                    print(
                        f"  [{state[:6]}] {case_id:<12} (rep {rep}) -> HTTP {client_res.get('status_code')} "
                        f"| {req_lat:.1f}ms | Effect: {backend_effect} | Validity: {validity_code}"
                    )
    finally:
        if db_conn:
            db_conn.close()

    # Export CSV
    output_csv = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results", f"{batch_id}.csv")
    export_csv(results, output_csv)
    print("\n[OK] Batch run complete!")


if __name__ == "__main__":
    run_experiment_batch()
