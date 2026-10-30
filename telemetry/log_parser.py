#!/usr/bin/env python3
"""
ModSecurity Serial JSON Audit Log Parser -> ECS-lite Normalization
Author: Phan Duc Anh
"""

import json
import re

def parse_audit_record(json_str: str) -> dict:
    """
    Parses a single ModSecurity v3 serial JSON audit record into an ECS-lite dictionary.
    """
    try:
        data = json.loads(json_str.strip())
    except Exception:
        return None

    txn = data.get("transaction", {})
    req = txn.get("request", {})
    headers = req.get("headers", {})

    # Extract correlation ID from X-Request-ID header
    correlation_id = headers.get("X-Request-ID") or headers.get("x-request-id")

    # Extract matched rule IDs and calculate total inbound score
    messages = txn.get("messages", [])
    matched_rule_ids = []
    inbound_score = 0

    for msg in messages:
        rule_data = msg.get("details", {})
        rule_id = rule_data.get("ruleId")
        if rule_id:
            matched_rule_ids.append(int(rule_id))
        
        # Extract anomaly score contribution from message string
        msg_text = msg.get("message", "")
        score_match = re.search(r"Inbound Anomaly Score.*?(\d+)", msg_text)
        if score_match:
            try:
                inbound_score = max(inbound_score, int(score_match.group(1)))
            except ValueError:
                pass

    producer = txn.get("producer", {})
    disruptive_action = "none"
    if txn.get("response", {}).get("http_code") == 403:
        disruptive_action = "block"

    return {
        "waf_txn_id": txn.get("unique_id"),
        "correlation_id": correlation_id,
        "matched_rule_ids": matched_rule_ids,
        "inbound_score": inbound_score,
        "disruptive_action": disruptive_action,
        "client_ip": txn.get("client_ip"),
        "method": req.get("method"),
        "uri": req.get("uri"),
        "audit_raw": json_str
    }
