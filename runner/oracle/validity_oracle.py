#!/usr/bin/env python3
"""
Validity & Inconclusive Classification Rules (Table 5.1)
Author: Kieu Dang Vuong
"""

def classify_validity(preconditions: dict, client_res: dict, waf_data: dict, backend_effect: bool, state: str, label: str) -> tuple:
    """
    Returns (validity_code, is_valid, reason) according to Table 5.1
    """
    # 1. Health check failure
    if not preconditions.get("health_ok", False):
        return ("E_HEALTH", False, "Pre-flight health check failed")

    # 2. Fixture verification failure
    if not preconditions.get("fixture_verified", False):
        return ("E_FIXTURE", False, "Post-reset fixture assertion failed")

    # 3. Mode Canary deviation
    if not preconditions.get("mode_verified", False):
        return ("E_MODE", False, "Active WAF mode canary deviated from expected profile")

    # 4. Correlation ID missing
    if not client_res.get("correlation_id"):
        return ("E_CORRELATION", False, "Correlation ID missing from request transaction")

    # 5. Inconclusive: Unattributed denial
    status = client_res.get("status_code")
    if status == 403 and (not waf_data or waf_data.get("disruptive_action") != "block"):
        return ("I_UNATTRIBUTED", True, "HTTP 403 received without attributable WAF disruption")

    # 6. Inconclusive: Baseline conflict (Malicious case fails even in Direct-to-App)
    if state == "Direct-to-App" and label == "malicious" and not backend_effect:
        return ("I_BASELINE_CONFLICT", True, "Malicious case showed no effect in direct baseline")

    return ("VALID", True, "All validation assertions satisfied")
