#!/usr/bin/env python3
"""
WAFBench Correlation Engine (Stage 3) & Classification Function (Stage 4)
Joins the three evidence tiers on X-Request-ID and assigns validity, verdict and metric cell.
Conforming to Table 4.3 (Normalized Events), Table 4.6 (Evaluation Metrics)
and Table 5.2 (Metric Classification Matrix).

The classification rules match runner/oracle/validity_oracle.py so the database and the
runner CSV give the same cell for the same evidence:
  DetectionOnly : detected  -> TP_D / FP_D,  not detected -> FN_D / TN_D
  Blocking      : blocked = detected AND client saw 403 -> TP_B / FP_B, else FN_B / TN_B
  Direct-to-App : no cell (BASELINE), feeds the Baseline Gate only
"""

import os
import sys
from typing import Optional, Dict, Any, List, Iterable

# Ensure imports work whether run from repository root or inside Docker
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import db
except ImportError:
    db = None


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


# Same variables the gateway reads (docker-compose / .env), so the threshold is not hard-coded twice
INBOUND_THRESHOLD = _int_env("CRS_INBOUND_ANOMALY_THRESHOLD", 5)
OUTBOUND_THRESHOLD = _int_env("CRS_OUTBOUND_ANOMALY_THRESHOLD", 4)

# 949110/959100 = CRS inbound/outbound threshold exceeded; custom rule IDs differ between gateway branches
DETECTION_RULE_IDS = {949110, 959100} | {
    int(r) for r in os.getenv("WAF_CUSTOM_RULE_IDS", "10001,200001,200010,1000001").split(",") if r.strip().isdigit()
}

# How long a gateway row may wait for its audit record before it is classified without one.
# ModSecurity writes the audit log after the response (phase 5), so this must be well above that delay.
CORRELATION_TIMEOUT_S = float(os.getenv("CORRELATION_TIMEOUT_S", "5"))

WAF_STATES = ("DetectionOnly", "Blocking")
EXPECTED_ENGINE = {"DetectionOnly": "DetectionOnly", "Blocking": "Enabled"}
METRIC_CELLS = ("TP_D", "FN_D", "FP_D", "TN_D", "TP_B", "FN_B", "FP_B", "TN_B")
PASS_CELLS = {"TP_D", "TN_D", "TP_B", "TN_B"}


def is_detected(waf_data: Optional[Dict[str, Any]],
                inbound_threshold: Optional[int] = None,
                outbound_threshold: Optional[int] = None) -> bool:
    """
    A request is detected when the WAF reached a conclusion, not when a single rule added points:
    an evaluation rule (949110/959100) or a custom rule fired, or a logged total reached the threshold.
    """
    if not waf_data:
        return False
    inbound_threshold = INBOUND_THRESHOLD if inbound_threshold is None else inbound_threshold
    outbound_threshold = OUTBOUND_THRESHOLD if outbound_threshold is None else outbound_threshold

    rule_ids = set()
    for r in waf_data.get("matched_rule_ids") or []:
        try:
            rule_ids.add(int(r))
        except (TypeError, ValueError):
            pass
    if rule_ids & DETECTION_RULE_IDS:
        return True
    return ((waf_data.get("inbound_score") or 0) >= inbound_threshold
            or (waf_data.get("outbound_score") or 0) >= outbound_threshold)


def _result(correlation_id, state, label, validity, invalid_reason, verdict, metric_cell,
            detected=False, backend_effect=False, waf_data=None, oracle_observation=None) -> Dict[str, Any]:
    waf = waf_data or {}
    return {
        "correlation_id": correlation_id,
        "state": state,
        "label": label,
        "inbound_score": waf.get("inbound_score", 0) or 0,
        "disruptive_action": (waf.get("disruptive_action") or "none").lower(),
        "detected": bool(detected),
        "backend_effect": bool(backend_effect),
        "oracle_observation": oracle_observation,
        "validity": validity,
        "invalid_reason": invalid_reason,
        "verdict": verdict,
        "metric_cell": metric_cell,
    }


def correlate_event(
    client_data: Dict[str, Any],
    waf_data: Optional[Dict[str, Any]],
    oracle_data: Optional[Dict[str, Any]],
    state: str,
    inbound_threshold: Optional[int] = None,
    outbound_threshold: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Classification Function for one run.
      client_data : correlation_id, label, client_status, validity/invalid_reason set by the runner
                    (E_HEALTH, E_FIXTURE, E_MODE), app_received (True/False/None = not checked)
      waf_data    : parsed audit record, or None when the WAF logged nothing for this request
      oracle_data : backend_effect, oracle_observation
    Validity checks run in the same order as runner/oracle/validity_oracle.py.
    """
    correlation_id = client_data.get("correlation_id")
    label = (client_data.get("label") or "malicious").lower()
    client_status = client_data.get("client_status")
    oracle = oracle_data or {}
    backend_effect = bool(oracle.get("backend_effect", False))
    observation = oracle.get("oracle_observation")
    detected = is_detected(waf_data, inbound_threshold, outbound_threshold) if state in WAF_STATES else False

    def excluded(code: str, reason: str) -> Dict[str, Any]:
        verdict = "INVALID" if code.startswith("E_") else "INCONCLUSIVE"
        return _result(correlation_id, state, label, code, reason, verdict, None,
                       detected, backend_effect, waf_data, observation)

    # 0. No join key: nothing can be attributed to this run
    if not correlation_id:
        return excluded("E_CORRELATION", "Missing correlation_id from test probe transaction")

    # 1-2. Preconditions measured by the runner (health, fixture, mode canary) are kept as they are
    runner_validity = client_data.get("validity")
    if runner_validity and runner_validity != "VALID":
        return excluded(runner_validity, client_data.get("invalid_reason") or "Runner precondition failed")

    # 1. No HTTP response at the client
    if client_status is None:
        return excluded("E_HEALTH", "No HTTP response recorded for this request")

    # Direct-to-App: no WAF on the path; the run only confirms the label (Baseline Gate)
    if state not in WAF_STATES:
        if label == "malicious" and not backend_effect:
            return _result(correlation_id, state, label, "I_BASELINE_CONFLICT",
                           "Malicious probe had no backend effect without the WAF", "INCONCLUSIVE",
                           "BASELINE", False, backend_effect, None, observation)
        if label != "malicious" and backend_effect:
            return _result(correlation_id, state, label, "I_BASELINE_CONFLICT",
                           "Benign probe produced a backend effect without the WAF", "INCONCLUSIVE",
                           "BASELINE", False, backend_effect, None, observation)
        return _result(correlation_id, state, label, "VALID", None, "PASS", "BASELINE",
                       False, backend_effect, None, observation)

    # 3. The audit record states which engine processed the request; it must match the state
    engine = (waf_data or {}).get("waf_engine_mode")
    if engine and engine != EXPECTED_ENGINE[state]:
        return excluded("E_MODE", f"Audit record engine is '{engine}', expected '{EXPECTED_ENGINE[state]}' for {state}")

    # 4. Correlation: no audit record is normal for a clean request (SecAuditEngine RelevantOnly),
    #    but the request must have been seen somewhere
    if not waf_data and client_data.get("app_received") is False:
        return excluded("E_CORRELATION", "Correlation ID found neither in WAF audit log nor app log")

    # 5. A denial the WAF evidence does not explain
    if client_status == 403 and not detected:
        return excluded("I_UNATTRIBUTED", "HTTP 403 received without attributable WAF detection")

    malicious = label == "malicious"
    if state == "DetectionOnly":
        if malicious:
            cell = "TP_D" if detected else "FN_D"
        else:
            cell = "FP_D" if detected else "TN_D"
    else:
        blocked = detected and client_status == 403
        if malicious:
            cell = "TP_B" if blocked else "FN_B"
        else:
            cell = "FP_B" if blocked else "TN_B"

    return _result(correlation_id, state, label, "VALID", None,
                   "PASS" if cell in PASS_CELLS else "FAIL", cell,
                   detected, backend_effect, waf_data, observation)


# ---------------------------------------------------------------------------
# Stage 3: join a database row with its staged audit record
# ---------------------------------------------------------------------------

def row_to_inputs(row: Dict[str, Any]) -> tuple:
    """Splits a joined normalized_events row into (client_data, waf_data, oracle_data, state)."""
    client = {
        "correlation_id": row.get("correlation_id"),
        "label": row.get("label"),
        "client_status": row.get("client_status"),
        "validity": row.get("runner_validity"),
        "invalid_reason": row.get("runner_invalid_reason"),
        "app_received": row.get("app_received"),
    }
    waf = row.get("waf_parsed") or None
    oracle = {"backend_effect": row.get("backend_effect"), "oracle_observation": row.get("oracle_observation")}
    return client, waf, oracle, row.get("state")


def correlate_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Classifies one joined row. Before the first correlation, validity/invalid_reason still hold
    what the runner wrote; afterwards the runner's values live in runner_validity/runner_invalid_reason.
    """
    if row.get("correlated_at") is None:
        row = dict(row, runner_validity=row.get("validity"), runner_invalid_reason=row.get("invalid_reason"))
    return correlate_event(*row_to_inputs(row))


def correlate_and_save(
    client_data: Dict[str, Any],
    waf_data: Optional[Dict[str, Any]],
    oracle_data: Optional[Dict[str, Any]],
    state: str
) -> Dict[str, Any]:
    """Performs 3-tier correlation and directly updates the database record."""
    result = correlate_event(client_data, waf_data, oracle_data, state)
    corr_id = result.get("correlation_id")
    if corr_id and db is not None:
        try:
            db.update_verdict(corr_id, result)
        except Exception as e:
            print(f"[!] Warning: Could not commit verdict to database: {e}")
    return result


def _copy_staged_telemetry(row: Dict[str, Any]) -> None:
    """The audit record can be staged before the runner inserts its row; copy it over once both exist."""
    staged = row.get("waf_parsed")
    if staged and row.get("raw_log_ref") != staged.get("raw_log_ref"):
        db.update_waf_telemetry(row["correlation_id"], staged)


def correlate_one(correlation_id: str) -> Optional[Dict[str, Any]]:
    """
    Re-classifies one row as soon as its audit record arrives.
    Also corrects a row that timed out earlier and was classified without its (late) record.
    """
    row = db.fetch_joined_event(correlation_id)
    if not row:
        return None
    _copy_staged_telemetry(row)
    result = correlate_row(row)
    db.update_verdict(correlation_id, result)
    return result


def run_correlation_pass(timeout_s: Optional[float] = None, limit: int = 500) -> int:
    """
    Classifies every pending row that is ready: its audit record has been staged,
    or it waited longer than timeout_s (default CORRELATION_TIMEOUT_S) without one.
    Returns the number of rows written.
    """
    if timeout_s is None:
        timeout_s = CORRELATION_TIMEOUT_S
    done = 0
    for row in db.fetch_ready_events(timeout_s, limit):
        _copy_staged_telemetry(row)
        result = correlate_row(row)
        if db.update_verdict(row["correlation_id"], result):
            done += 1
    return done


# ---------------------------------------------------------------------------
# Stage 4 (batch level): Baseline Gate and Table 4.6 metrics
# ---------------------------------------------------------------------------

def apply_baseline_gate(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    A case whose Direct-to-App runs do not behave as its label says cannot measure the WAF:
    every valid gateway run of that case becomes I_BASELINE_CONFLICT. Returns the rows it changed.
    Runs per batch, after all repetitions exist (same rule as runner/report.py).
    """
    direct: Dict[tuple, List[Dict[str, Any]]] = {}
    for e in events:
        if e.get("state") == "Direct-to-App":
            direct.setdefault((e.get("batch_id"), e.get("case_id")), []).append(e)

    failed = {}
    for e in events:
        key = (e.get("batch_id"), e.get("case_id"))
        if key in failed or e.get("state") not in WAF_STATES:
            continue
        runs = direct.get(key, [])
        if not runs:
            continue   # Direct-to-App not run in this batch: nothing to gate on
        if any(r.get("validity") not in ("VALID", "I_BASELINE_CONFLICT") for r in runs):
            failed[key] = "Direct-to-App run invalid"
        elif any(r.get("validity") == "I_BASELINE_CONFLICT" for r in runs):
            failed[key] = next(r.get("invalid_reason") for r in runs if r.get("validity") == "I_BASELINE_CONFLICT")

    changed = []
    for e in events:
        key = (e.get("batch_id"), e.get("case_id"))
        if key in failed and e.get("state") in WAF_STATES and e.get("validity") == "VALID":
            e.update(validity="I_BASELINE_CONFLICT", invalid_reason=failed[key],
                     verdict="INCONCLUSIVE", metric_cell=None)
            changed.append(e)
    return changed


def _rate(num: int, den: int):
    return round(num / den * 100, 2) if den else None


def calculate_batch_metrics(
    events: Iterable[Dict[str, Any]],
    batch_id: str = "batch_default",
    config_revision: str = "C0"
) -> Dict[str, Any]:
    """
    Aggregated KPIs (Table 4.6) over gateway runs. Only VALID runs enter the rates;
    E_* runs count as invalid and I_* runs as inconclusive.
    """
    gateway = [e for e in events if e.get("state") in WAF_STATES]
    valid = [e for e in gateway if e.get("validity") == "VALID"]
    c = {cell: sum(1 for e in valid if e.get("metric_cell") == cell) for cell in METRIC_CELLS}

    return {
        "batch_id": batch_id,
        "config_revision": config_revision,
        "total_attempted": len(gateway),
        "total_evaluable": len(valid),
        "total_invalid": sum(1 for e in gateway if str(e.get("validity", "")).startswith("E_")),
        "total_inconclusive": sum(1 for e in gateway if str(e.get("validity", "")).startswith("I_")),
        **{k.lower(): v for k, v in c.items()},
        "detection_rate": _rate(c["TP_D"], c["TP_D"] + c["FN_D"]),
        "blocking_rate": _rate(c["TP_B"], c["TP_B"] + c["FN_B"]),
        "detection_fpr": _rate(c["FP_D"], c["FP_D"] + c["TN_D"]),
        "blocking_fpr": _rate(c["FP_B"], c["FP_B"] + c["TN_B"]),
        "regression_pass_rate": None,
    }


def finalize_batch(batch_id: str, config_revision: str = "C0") -> Dict[str, Any]:
    """
    End-of-batch step: classify what is still pending, apply the Baseline Gate,
    then store the batch KPIs in evaluation_metrics.
    """
    run_correlation_pass(timeout_s=0, limit=100000)
    events = db.fetch_batch_events(batch_id)
    for e in apply_baseline_gate(events):
        db.update_verdict(e["correlation_id"], e)
    metrics = calculate_batch_metrics(events, batch_id, config_revision)
    db.save_batch_metrics(metrics)
    return metrics


# ---------------------------------------------------------------------------
# Offline verification of the Classification Function
# ---------------------------------------------------------------------------

def _waf(rule_ids, inbound=0, engine="DetectionOnly", action="allow", outbound=0):
    return {"waf_txn_id": "tx", "matched_rule_ids": rule_ids, "inbound_score": inbound,
            "outbound_score": outbound, "waf_engine_mode": engine, "disruptive_action": action}


def run_correlation_test_suite():
    print("=" * 78)
    print("       WAFBench Correlation Engine Test Suite (Table 5.2)")
    print("=" * 78)

    B = "Blocking"
    D = "DetectionOnly"
    sqli_block = _waf([942100, 949110], 10, "Enabled", "block")
    cases = [
        ("SQLi blocked", {"label": "malicious", "client_status": 403}, sqli_block, False, B, "TP_B", "VALID"),
        ("SQLi bypass, no audit record", {"label": "malicious", "client_status": 200}, None, True, B, "FN_B", "VALID"),
        ("Detected but not blocked (custom rule, 200)", {"label": "malicious", "client_status": 200},
         _waf([200001], 0, "Enabled"), True, B, "FN_B", "VALID"),
        ("XSS detected in DetectionOnly", {"label": "malicious", "client_status": 200},
         _waf([941100, 949110], 15), True, D, "TP_D", "VALID"),
        ("Score below threshold is not detection", {"label": "malicious", "client_status": 200},
         _waf([920350], 3), True, D, "FN_D", "VALID"),
        ("Benign false alarm (DetectionOnly)", {"label": "benign", "client_status": 200},
         _waf([942100, 949110], 5), False, D, "FP_D", "VALID"),
        ("Benign blocked (Blocking)", {"label": "benign", "client_status": 403},
         _waf([942100, 949110], 5, "Enabled", "block"), False, B, "FP_B", "VALID"),
        ("Benign clean, no audit record (RelevantOnly)", {"label": "benign", "client_status": 200},
         None, False, B, "TN_B", "VALID"),
        ("Benign clean, edge label", {"label": "edge", "client_status": 500}, None, False, D, "TN_D", "VALID"),
        ("403 without WAF evidence", {"label": "malicious", "client_status": 403}, None, False, B, None, "I_UNATTRIBUTED"),
        ("Audit record from the wrong engine", {"label": "malicious", "client_status": 200},
         _waf([942100, 949110], 10, "DetectionOnly"), False, B, None, "E_MODE"),
        ("Seen by neither WAF nor app", {"label": "benign", "client_status": 200, "app_received": False},
         None, False, D, None, "E_CORRELATION"),
        ("Runner fixture failure is kept", {"label": "malicious", "client_status": 200, "validity": "E_FIXTURE",
         "invalid_reason": "fixture mismatch"}, sqli_block, True, D, None, "E_FIXTURE"),
        ("No HTTP response", {"label": "benign", "client_status": None}, None, False, D, None, "E_HEALTH"),
        ("Baseline: attack works without WAF", {"label": "malicious", "client_status": 200},
         None, True, "Direct-to-App", "BASELINE", "VALID"),
        ("Baseline: attack has no effect", {"label": "malicious", "client_status": 200},
         None, False, "Direct-to-App", "BASELINE", "I_BASELINE_CONFLICT"),
    ]

    print(f"{'Scenario':<46} | {'State':<13} | {'Cell':<8} | Validity")
    print("-" * 78)
    results = []
    for i, (name, client, waf, effect, state, cell, validity) in enumerate(cases):
        client = dict(client, correlation_id=f"c-{i:03d}")
        res = correlate_event(client, waf, {"backend_effect": effect}, state)
        res["batch_id"], res["case_id"] = "b1", f"CASE-{i:03d}"
        results.append(res)
        ok = res["metric_cell"] == cell and res["validity"] == validity
        print(f"{name:<46} | {state:<13} | {str(res['metric_cell']):<8} | {res['validity']} {'[OK]' if ok else '[FAIL]'}")
        assert ok, f"{name}: got {res['metric_cell']}/{res['validity']}, expected {cell}/{validity}"

    missing_id = correlate_event({"label": "benign", "client_status": 200}, None, None, D)
    assert missing_id["validity"] == "E_CORRELATION"

    # Baseline Gate: one case, Direct-to-App fails -> its gateway runs become I_BASELINE_CONFLICT
    gate_rows = [
        {"batch_id": "b2", "case_id": "X", "state": "Direct-to-App", "validity": "I_BASELINE_CONFLICT",
         "invalid_reason": "no effect", "correlation_id": "g1"},
        {"batch_id": "b2", "case_id": "X", "state": D, "validity": "VALID", "metric_cell": "FN_D", "correlation_id": "g2"},
        {"batch_id": "b2", "case_id": "Y", "state": "Direct-to-App", "validity": "VALID", "correlation_id": "g3"},
        {"batch_id": "b2", "case_id": "Y", "state": D, "validity": "VALID", "metric_cell": "TP_D", "correlation_id": "g4"},
    ]
    changed = apply_baseline_gate(gate_rows)
    assert [r["correlation_id"] for r in changed] == ["g2"]
    assert gate_rows[1]["validity"] == "I_BASELINE_CONFLICT" and gate_rows[1]["metric_cell"] is None
    assert gate_rows[3]["metric_cell"] == "TP_D"
    print("Baseline Gate propagates a failed baseline to the case's gateway runs [OK]")

    m = calculate_batch_metrics(results, "batch_verify_001")
    print("-" * 78)
    print(f"  attempted {m['total_attempted']}, evaluable {m['total_evaluable']}, "
          f"invalid {m['total_invalid']}, inconclusive {m['total_inconclusive']}")
    print(f"  DR {m['detection_rate']}%  BR {m['blocking_rate']}%  "
          f"FPR_D {m['detection_fpr']}%  FPR_B {m['blocking_fpr']}%")
    assert (m["tp_d"], m["fn_d"], m["fp_d"], m["tn_d"]) == (1, 1, 1, 1)
    assert (m["tp_b"], m["fn_b"], m["fp_b"], m["tn_b"]) == (1, 2, 1, 1)
    assert m["detection_rate"] == 50.0 and m["blocking_rate"] == 33.33
    print("=" * 78)
    print("[SUCCESS] Classification Function and metrics verified")
    print("=" * 78)


if __name__ == "__main__":
    if "--finalize" in sys.argv:
        idx = sys.argv.index("--finalize")
        batch = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else None
        if not batch:
            sys.exit("Usage: python correlation.py --finalize <batch_id> [--config C0|C1]")
        revision = sys.argv[sys.argv.index("--config") + 1] if "--config" in sys.argv else "C0"
        db.ensure_schema()
        print(finalize_batch(batch, revision))
    elif "--pass" in sys.argv:
        db.ensure_schema()
        print(f"[+] Classified {run_correlation_pass()} pending rows")
    else:
        run_correlation_test_suite()
