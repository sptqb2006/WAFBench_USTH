#!/usr/bin/env python3
"""
WAFBench Cross-Tier Correlation Engine (Client + WAF Audit + Backend Oracle)
Conforming to Table 4.3 (Normalized Events), Table 4.6 (Evaluation Metrics), 
and Table 5.2 (Metric Classification Matrix).
Author: Phan Duc Anh
"""

import sys
import os
import json
from typing import Optional, Dict, Any, List, Tuple

# Ensure imports work whether run from repository root or inside Docker
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import db
except ImportError:
    db = None


def correlate_event(
    client_data: Dict[str, Any],
    waf_data: Optional[Dict[str, Any]],
    oracle_data: Optional[Dict[str, Any]],
    state: str,
    inbound_threshold: int = 5
) -> Dict[str, Any]:
    """
    Correlates evidence across the three tiers for a single test probe:
      Tier 1: Client Capture (request params, status code, correlation_id)
      Tier 2: WAF Telemetry (inbound anomaly score, disruptive action, triggered rules)
      Tier 3: Backend Oracle (application execution outcome & database mutation)

    Returns a correlated dictionary with validity, verdict, and metric_cell assignment.
    """
    correlation_id = client_data.get("correlation_id")
    label = client_data.get("label", "malicious").lower()
    client_status = client_data.get("client_status")

    # 1. Base Validity & "HTTP Status Fallacy" Detection
    validity = "VALID"
    invalid_reason = None

    if not correlation_id:
        return {
            "correlation_id": None,
            "state": state,
            "label": label,
            "detected": False,
            "backend_effect": False,
            "validity": "E_CORRELATION",
            "invalid_reason": "Missing correlation_id from test probe transaction",
            "verdict": "INVALID",
            "metric_cell": None
        }

    # Evaluate WAF Telemetry Presence based on State
    if state == "Direct-to-App":
        # Direct-to-App bypasses the WAF gateway by design (1:0:1). Absence of WAF log is expected.
        inbound_score = 0
        detected = False
        disruptive_action = "none"
    else:
        # Gateway Traffic (DetectionOnly or Blocking) requires WAF Telemetry
        if not waf_data or not waf_data.get("waf_txn_id"):
            # Check for HTTP Status Fallacy: Client observed 403 but WAF has no record of disruption
            if client_status == 403:
                validity = "I_UNATTRIBUTED"
                invalid_reason = "HTTP 403 observed without attributable ModSecurity audit record"
            else:
                validity = "E_MISSING_WAF_LOG"
                invalid_reason = f"No WAF telemetry captured for gateway state '{state}'"
            inbound_score = 0
            detected = False
            disruptive_action = "none"
        else:
            inbound_score = waf_data.get("inbound_score", 0)
            detected = inbound_score >= inbound_threshold
            disruptive_action = waf_data.get("disruptive_action", "none").lower()

    # 2. Backend Oracle Outcome
    backend_effect = False
    oracle_observation = "None"
    if oracle_data:
        backend_effect = bool(oracle_data.get("backend_effect", False))
        oracle_observation = oracle_data.get("oracle_observation", "None")

    # 3. Scientific Metric Cell & Verdict Assignment (Table 5.2)
    metric_cell = None
    verdict = "INCONCLUSIVE"

    if validity != "VALID":
        verdict = "INVALID" if validity.startswith("E_") else "INCONCLUSIVE"

    elif state == "Direct-to-App":
        # Baseline Gate Verification
        if label == "malicious":
            if backend_effect:
                verdict = "PASS"   # Baseline confirmed: attack demonstrably compromises unshielded target
            else:
                validity = "I_BASELINE_CONFLICT"
                invalid_reason = "Malicious probe failed to compromise unshielded application baseline"
                verdict = "INCONCLUSIVE"
        else:
            # Benign baseline: should NOT cause backend compromise
            verdict = "PASS" if not backend_effect else "FAIL"

    elif state == "DetectionOnly":
        # WAF inspects and forwards (1:1:1). Gateway status should be 200.
        if label == "malicious":
            if detected:
                metric_cell = "TP_D"
                verdict = "PASS"
            else:
                metric_cell = "FN_D"
                verdict = "FAIL"   # Detection Miss
        else: # benign or edge
            if detected:
                metric_cell = "FP_D"
                verdict = "FAIL"   # False Alarm
            else:
                metric_cell = "TN_D"
                verdict = "PASS"

    elif state == "Blocking":
        # WAF inspects and enforces (1:1:0). Gateway status should be 403 on block.
        if label == "malicious":
            if disruptive_action == "block" and not backend_effect:
                metric_cell = "TP_B"
                verdict = "PASS"   # True Positive Block
            elif backend_effect:
                metric_cell = "FN_B"
                verdict = "FAIL"   # Bypass: WAF failed to protect backend
            else:
                # WAF did not block, but backend was not affected -> inconclusive
                verdict = "INCONCLUSIVE"
                invalid_reason = "WAF did not block probe, yet backend was uncompromised"
        else: # benign or edge
            if disruptive_action == "block":
                metric_cell = "FP_B"
                verdict = "FAIL"   # Erroneous Block of legitimate traffic
            else:
                metric_cell = "TN_B"
                verdict = "PASS"

    return {
        "correlation_id": correlation_id,
        "state": state,
        "label": label,
        "inbound_score": inbound_score,
        "disruptive_action": disruptive_action,
        "detected": detected,
        "backend_effect": backend_effect,
        "oracle_observation": oracle_observation,
        "validity": validity,
        "invalid_reason": invalid_reason,
        "verdict": verdict,
        "metric_cell": metric_cell
    }


def calculate_batch_metrics(
    events: List[Dict[str, Any]],
    batch_id: str = "batch_default",
    config_revision: str = "C0"
) -> Dict[str, Any]:
    """
    Computes aggregated quantitative benchmark KPIs conforming to Table 4.6.
    Strictly excludes Inconclusive and Invalid events from the denominator.
    """
    total_attempted = len(events)
    total_invalid = sum(1 for e in events if e.get("validity", "").startswith("E_"))
    total_inconclusive = sum(1 for e in events if e.get("verdict") == "INCONCLUSIVE")
    total_evaluable = sum(1 for e in events if e.get("validity") == "VALID" and e.get("verdict") != "INCONCLUSIVE")

    valid_events = [e for e in events if e.get("validity") == "VALID"]

    # 1. Detection Rate (DR) in DetectionOnly
    det_mal = [e for e in valid_events if e.get("state") == "DetectionOnly" and e.get("label") == "malicious"]
    tp_d = sum(1 for e in det_mal if e.get("metric_cell") == "TP_D")
    fn_d = sum(1 for e in det_mal if e.get("metric_cell") == "FN_D")
    dr = round((tp_d / (tp_d + fn_d) * 100), 2) if (tp_d + fn_d) > 0 else 0.0

    # 2. Blocking Rate (BR) in Blocking
    blk_mal = [e for e in valid_events if e.get("state") == "Blocking" and e.get("label") == "malicious"]
    tp_b = sum(1 for e in blk_mal if e.get("metric_cell") == "TP_B")
    fn_b = sum(1 for e in blk_mal if e.get("metric_cell") == "FN_B")
    br = round((tp_b / (tp_b + fn_b) * 100), 2) if (tp_b + fn_b) > 0 else 0.0

    # 3. Detection False Positive Rate (FPR_D)
    det_benign = [e for e in valid_events if e.get("state") == "DetectionOnly" and e.get("label") in ("benign", "edge")]
    fp_d = sum(1 for e in det_benign if e.get("metric_cell") == "FP_D")
    tn_d = sum(1 for e in det_benign if e.get("metric_cell") == "TN_D")
    fpr_d = round((fp_d / (fp_d + tn_d) * 100), 2) if (fp_d + tn_d) > 0 else 0.0

    # 4. Blocking False Positive Rate (FPR_B)
    blk_benign = [e for e in valid_events if e.get("state") == "Blocking" and e.get("label") in ("benign", "edge")]
    fp_b = sum(1 for e in blk_benign if e.get("metric_cell") == "FP_B")
    tn_b = sum(1 for e in blk_benign if e.get("metric_cell") == "TN_B")
    fpr_b = round((fp_b / (fp_b + tn_b) * 100), 2) if (fp_b + tn_b) > 0 else 0.0

    return {
        "batch_id": batch_id,
        "config_revision": config_revision,
        "total_attempted": total_attempted,
        "total_evaluable": total_evaluable,
        "total_invalid": total_invalid,
        "total_inconclusive": total_inconclusive,
        "tp_d": tp_d,
        "fn_d": fn_d,
        "tp_b": tp_b,
        "fn_b": fn_b,
        "fp_d": fp_d,
        "tn_d": tn_d,
        "fp_b": fp_b,
        "tn_b": tn_b,
        "detection_rate": dr,
        "blocking_rate": br,
        "detection_fpr": fpr_d,
        "blocking_fpr": fpr_b,
        "regression_pass_rate": 100.0 if config_revision == "C0" else None
    }


def correlate_and_save(
    client_data: Dict[str, Any],
    waf_data: Optional[Dict[str, Any]],
    oracle_data: Optional[Dict[str, Any]],
    state: str
) -> Dict[str, Any]:
    """
    Performs 3-tier correlation and directly updates the database record.
    """
    result = correlate_event(client_data, waf_data, oracle_data, state)
    corr_id = result.get("correlation_id")

    if corr_id and db is not None:
        try:
            db.update_verdict(corr_id, result)
        except Exception as e:
            print(f"[!] Warning: Could not commit verdict to database: {e}")

    return result


def run_correlation_test_suite():
    """
    Runs automated verification across all 8 empirical evaluation scenarios.
    """
    print("=" * 78)
    print("       WAFBench Cross-Tier Correlation Engine Test Suite (Table 5.2)")
    print("=" * 78)

    test_cases = [
        # 1. SQLi successfully blocked in Blocking mode
        {
            "name": "SQLi Intercepted (Blocking Mode)",
            "client": {"correlation_id": "c-001", "label": "malicious", "client_status": 403},
            "waf": {"waf_txn_id": "tx-1", "inbound_score": 10, "disruptive_action": "block"},
            "oracle": {"backend_effect": False, "oracle_observation": "Intercepted at gateway"},
            "state": "Blocking",
            "expected_cell": "TP_B", "expected_verdict": "PASS"
        },
        # 2. SQLi bypass in Blocking mode (WAF failed, DB mutated)
        {
            "name": "SQLi Bypass (Blocking Mode Failure)",
            "client": {"correlation_id": "c-002", "label": "malicious", "client_status": 200},
            "waf": {"waf_txn_id": "tx-2", "inbound_score": 0, "disruptive_action": "none"},
            "oracle": {"backend_effect": True, "oracle_observation": "Unauthorized admin session created"},
            "state": "Blocking",
            "expected_cell": "FN_B", "expected_verdict": "FAIL"
        },
        # 3. XSS detected in DetectionOnly mode
        {
            "name": "XSS Detected (DetectionOnly Mode)",
            "client": {"correlation_id": "c-003", "label": "malicious", "client_status": 200},
            "waf": {"waf_txn_id": "tx-3", "inbound_score": 5, "disruptive_action": "allow"},
            "oracle": {"backend_effect": True, "oracle_observation": "Script tag reflected"},
            "state": "DetectionOnly",
            "expected_cell": "TP_D", "expected_verdict": "PASS"
        },
        # 4. XSS missed in DetectionOnly mode
        {
            "name": "XSS Missed (DetectionOnly Mode Failure)",
            "client": {"correlation_id": "c-004", "label": "malicious", "client_status": 200},
            "waf": {"waf_txn_id": "tx-4", "inbound_score": 0, "disruptive_action": "allow"},
            "oracle": {"backend_effect": True, "oracle_observation": "Script tag reflected"},
            "state": "DetectionOnly",
            "expected_cell": "FN_D", "expected_verdict": "FAIL"
        },
        # 5. Benign request false positive alarm (DetectionOnly)
        {
            "name": "Benign False Alarm (DetectionOnly Mode)",
            "client": {"correlation_id": "c-005", "label": "benign", "client_status": 200},
            "waf": {"waf_txn_id": "tx-5", "inbound_score": 8, "disruptive_action": "allow"},
            "oracle": {"backend_effect": False, "oracle_observation": "Clean query executed"},
            "state": "DetectionOnly",
            "expected_cell": "FP_D", "expected_verdict": "FAIL"
        },
        # 6. Benign request erroneously blocked (Blocking)
        {
            "name": "Benign Erroneously Blocked (Blocking Mode)",
            "client": {"correlation_id": "c-006", "label": "benign", "client_status": 403},
            "waf": {"waf_txn_id": "tx-6", "inbound_score": 10, "disruptive_action": "block"},
            "oracle": {"backend_effect": False, "oracle_observation": "Intercepted at gateway"},
            "state": "Blocking",
            "expected_cell": "FP_B", "expected_verdict": "FAIL"
        },
        # 7. Benign request cleanly allowed (Blocking)
        {
            "name": "Benign Clean Request (Blocking Mode)",
            "client": {"correlation_id": "c-007", "label": "benign", "client_status": 200},
            "waf": {"waf_txn_id": "tx-7", "inbound_score": 0, "disruptive_action": "allow"},
            "oracle": {"backend_effect": False, "oracle_observation": "Normal search completed"},
            "state": "Blocking",
            "expected_cell": "TN_B", "expected_verdict": "PASS"
        },
        # 8. HTTP Status Fallacy: 403 received with NO WAF log
        {
            "name": "HTTP Status Fallacy (403 without WAF evidence)",
            "client": {"correlation_id": "c-008", "label": "malicious", "client_status": 403},
            "waf": None, # Missing WAF audit log
            "oracle": {"backend_effect": False, "oracle_observation": "None"},
            "state": "Blocking",
            "expected_cell": None, "expected_verdict": "INCONCLUSIVE"
        },
        # 9. Direct-to-App Baseline Verification (No WAF log expected)
        {
            "name": "Direct-to-App Baseline Verification",
            "client": {"correlation_id": "c-009", "label": "malicious", "client_status": 200},
            "waf": None, # By design, Direct-to-App has no WAF log
            "oracle": {"backend_effect": True, "oracle_observation": "SQLi exploit successful unshielded"},
            "state": "Direct-to-App",
            "expected_cell": None, "expected_verdict": "PASS"
        }
    ]

    all_results = []
    print(f"{'Scenario Name':<42} | {'State':<14} | {'Cell':<5} | {'Verdict':<12} | Status")
    print("-" * 78)

    for tc in test_cases:
        res = correlate_event(tc["client"], tc["waf"], tc["oracle"], tc["state"])
        all_results.append(res)
        cell_match = res["metric_cell"] == tc["expected_cell"]
        verdict_match = res["verdict"] == tc["expected_verdict"]
        passed = cell_match and verdict_match

        cell_str = str(res["metric_cell"]) if res["metric_cell"] else "N/A"
        print(
            f"{tc['name']:<42} | {tc['state']:<14} | {cell_str:<5} | "
            f"{res['verdict']:<12} | {'[OK]' if passed else '[FAIL]'}"
        )
        assert passed, f"Failed assertion on scenario: {tc['name']}"

    print("-" * 78)
    print("\n[Computing Aggregated Batch Benchmark Metrics (Table 4.6)]")
    metrics = calculate_batch_metrics(all_results, batch_id="batch_verify_001")
    print(f"  * Total Attempted   : {metrics['total_attempted']}")
    print(f"  * Total Evaluable   : {metrics['total_evaluable']}")
    print(f"  * Total Inconclusive: {metrics['total_inconclusive']} (excluded from rates)")
    print(f"  * Detection Rate    : {metrics['detection_rate']}% (TP_D={metrics['tp_d']}, FN_D={metrics['fn_d']})")
    print(f"  * Blocking Rate     : {metrics['blocking_rate']}% (TP_B={metrics['tp_b']}, FN_B={metrics['fn_b']})")
    print(f"  * Detection FPR     : {metrics['detection_fpr']}% (FP_D={metrics['fp_d']}, TN_D={metrics['tn_d']})")
    print(f"  * Blocking FPR      : {metrics['blocking_fpr']}% (FP_B={metrics['fp_b']}, TN_B={metrics['tn_b']})")
    print("=" * 78)
    print("[SUCCESS] All 3-tier correlation scenarios and formulas verified cleanly!")
    print("=" * 78)


if __name__ == "__main__":
    run_correlation_test_suite()
