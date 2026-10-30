#!/usr/bin/env python3
"""
Cross-Tier Correlation Engine (Client + WAF Audit + Backend Oracle)
Author: Phan Duc Anh
"""

def correlate_event(client_data: dict, waf_data: dict, oracle_data: dict, state: str) -> dict:
    """
    Correlates evidence across the three tiers for a single run and determines verdict & metric cell.
    """
    correlation_id = client_data.get("correlation_id")
    label = client_data.get("label", "malicious")
    inbound_threshold = 5

    # 1. WAF Detection & Enforcement
    inbound_score = waf_data.get("inbound_score", 0) if waf_data else 0
    detected = inbound_score >= inbound_threshold
    disruptive_action = waf_data.get("disruptive_action", "none") if waf_data else "none"

    # 2. Backend Effect
    backend_effect = oracle_data.get("backend_effect", False) if oracle_data else False

    # 3. Validity Check
    validity = "VALID"
    invalid_reason = None
    if not correlation_id:
        validity = "E_CORRELATION"
        invalid_reason = "Missing correlation_id"

    # 4. Metric Cell Assignment (Table 5.2)
    metric_cell = None
    verdict = "INCONCLUSIVE"

    if validity == "VALID":
        if state == "DetectionOnly":
            if label == "malicious":
                if detected:
                    verdict = "PASS"
                    metric_cell = "TP_D"
                else:
                    verdict = "FAIL"
                    metric_cell = "FN_D"
            else: # benign or edge
                if detected:
                    verdict = "FAIL"
                    metric_cell = "FP_D"  # False Positive!
                else:
                    verdict = "PASS"
                    metric_cell = "TN_D"

        elif state == "Blocking":
            if label == "malicious":
                if disruptive_action == "block" and not backend_effect:
                    verdict = "PASS"
                    metric_cell = "TP_B"
                else:
                    verdict = "FAIL"
                    metric_cell = "FN_B"
            else: # benign or edge
                if disruptive_action == "block":
                    verdict = "FAIL"
                    metric_cell = "FP_B"  # Erroneously blocked!
                else:
                    verdict = "PASS"
                    metric_cell = "TN_B"

        elif state == "Direct-to-App":
            if label == "malicious":
                verdict = "PASS" if backend_effect else "I_BASELINE_CONFLICT"
            else:
                verdict = "PASS" if not backend_effect else "FAIL"

    return {
        "correlation_id": correlation_id,
        "state": state,
        "label": label,
        "detected": detected,
        "backend_effect": backend_effect,
        "validity": validity,
        "invalid_reason": invalid_reason,
        "verdict": verdict,
        "metric_cell": metric_cell
    }
