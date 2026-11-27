#!/usr/bin/env python3
"""
Validity & Inconclusive Classification Rules (Table 5.1) and metric cell assignment
Author: Kieu Dang Vuong
"""

WAF_STATES = ("DetectionOnly", "Blocking")


def classify_validity(preconditions: dict, client_res: dict, waf_data: dict, state: str) -> tuple:
    """
    Returns (validity_code, is_valid, reason) according to Table 5.1.
    I_BASELINE_CONFLICT is assigned per case after the batch (report.apply_baseline_gate).
    """
    # 1. Health check failure (also covers a request that got no HTTP response)
    if not preconditions.get("health_ok", False):
        return ("E_HEALTH", False, preconditions.get("health_reason", "Pre-flight health check failed"))
    if not client_res.get("success"):
        return ("E_HEALTH", False, f"No HTTP response: {client_res.get('error')}")

    # 2. Fixture verification failure
    if not preconditions.get("fixture_verified", False):
        return ("E_FIXTURE", False, preconditions.get("fixture_reason", "Post-reset fixture assertion failed"))

    if state in WAF_STATES:
        # 3. Mode Canary deviation
        if not preconditions.get("mode_verified", False):
            return ("E_MODE", False, preconditions.get("mode_reason", "WAF mode canary deviated"))

        # 4. Correlation: the request must show up at the WAF or at the app
        if not (waf_data or {}).get("found") and not preconditions.get("seen_by_app", False):
            return ("E_CORRELATION", False, "Correlation ID found neither in WAF audit log nor app log")

    # 5. Inconclusive: denial that the WAF evidence does not explain
    if client_res.get("status_code") == 403 and not (waf_data or {}).get("detected"):
        return ("I_UNATTRIBUTED", False, "HTTP 403 received without attributable WAF detection")

    return ("VALID", True, "All validation assertions satisfied")


def assign_metric_cell(state: str, label: str, waf_data: dict, client_res: dict) -> str:
    """
    DetectionOnly: detected = anomaly threshold or custom rule matched in the audit log.
    Blocking: blocked = HTTP 403 at the client with matching WAF detection.
    Direct-to-App runs feed the Baseline Gate only.
    """
    if state not in WAF_STATES:
        return "BASELINE"

    detected = bool((waf_data or {}).get("detected"))
    malicious = label == "malicious"

    if state == "DetectionOnly":
        if malicious:
            return "TP_D" if detected else "FN_D"
        return "FP_D" if detected else "TN_D"

    blocked = detected and client_res.get("status_code") == 403
    if malicious:
        return "TP_B" if blocked else "FN_B"
    return "FP_B" if blocked else "TN_B"
