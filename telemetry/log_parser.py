#!/usr/bin/env python3
"""ModSecurity v3 Serial JSON Audit Log Parser -> ECS-lite Normalization
Conforming to WAFBench Table 4.3 (Normalized Events) & Table 3 (Audit Log Mapping)
Author: Phan Duc Anh
"""

import sys
import os
import json
import re
import hashlib
from typing import Optional, Dict, Any, List


def extract_inbound_score(messages: List[Dict[str, Any]]) -> int:
    """
    Extracts the cumulative inbound anomaly score from CRS evaluation messages.
    CRS v4 rule 949110 emits: 'Inbound Anomaly Score Exceeded (Total Inbound Score: 10 - Anomaly Threshold 5)'
    """
    highest_score = 0
    for msg in messages:
        text = msg.get("message", "")
        # Pattern 1: CRS v4 total score format
        match = re.search(r"Total (?:Inbound )?Score:\s*(\d+)", text, re.IGNORECASE)
        if match:
            highest_score = max(highest_score, int(match.group(1)))
            continue

        # Pattern 2: Generic anomaly score mentions
        match = re.search(r"Inbound Anomaly Score.*?(\d+)", text, re.IGNORECASE)
        if match:
            highest_score = max(highest_score, int(match.group(1)))

    return highest_score


def identify_root_rule(messages: List[Dict[str, Any]]) -> tuple:
    """
    Identifies the primary offending attack rule from triggered CRS messages.
    Distinguishes root attack rules (942xxx for SQLi, 941xxx for XSS, etc.) 
    from evaluation meta-rules (949110 / 959100 / 980130).
    """
    root_id = None
    root_name = None
    payload_snippet = None
    matched_variable = None

    # Priority ranges for CRS attack families:
    # 942xxx: SQLi, 941xxx: XSS, 930xxx: Path Traversal, 934xxx: SSRF, 920xxx: Protocol
    for msg in messages:
        details = msg.get("details", {})
        raw_rule_id = details.get("ruleId")
        if not raw_rule_id:
            continue

        try:
            rule_id = int(raw_rule_id)
        except ValueError:
            continue

        # Skip scoring/meta-rules to find the underlying vulnerability detector
        if rule_id in (949110, 959100, 980130):
            continue

        # Prefer specific attack family rules
        if root_id is None or (930000 <= rule_id <= 944999):
            root_id = rule_id
            root_name = details.get("ruleName") or msg.get("message")
            payload_snippet = details.get("data")
            matched_variable = details.get("variable")
            if 930000 <= rule_id <= 944999:
                break

    return root_id, root_name, payload_snippet, matched_variable


def parse_audit_record(json_str: str) -> Optional[Dict[str, Any]]:
    """
    Parses a single ModSecurity v3 serial JSON audit record into an ECS-lite dictionary.
    Returns None if the JSON is malformed or missing transaction data.
    """
    if not json_str or not json_str.strip():
        return None

    try:
        data = json.loads(json_str.strip())
    except Exception:
        return None

    txn = data.get("transaction", {})
    if not txn:
        return None

    # 1. Compute SHA-256 fingerprint of the raw line for audit referencing
    raw_log_ref = "sha256:" + hashlib.sha256(json_str.strip().encode("utf-8")).hexdigest()

    # 2. Extract transaction & client identity
    waf_txn_id = txn.get("unique_id") or txn.get("transaction_id")
    client_ip = txn.get("client_ip")

    req = txn.get("request", {})
    method = req.get("method")
    uri = req.get("uri")
    headers = req.get("headers", {})

    # Case-insensitive search for X-Request-ID header
    correlation_id = None
    for k, v in headers.items():
        if k.lower() == "x-request-id":
            correlation_id = v
            break

    # 3. Response and disruptive action
    resp = txn.get("response", {})
    status_code = resp.get("http_code")
    producer = txn.get("producer", {})
    action = producer.get("action", "").lower()

    disruptive_action = "none"
    interrupt_phase = None

    if status_code == 403 or action in ("interrupted", "block", "deny"):
        disruptive_action = "block"
        interrupt_phase = producer.get("phase", 2)
    elif status_code is not None:
        disruptive_action = "allow"

    # 4. Message details, rules, and anomaly scores
    messages = txn.get("messages", [])
    matched_rule_ids = []
    for msg in messages:
        rid = msg.get("details", {}).get("ruleId")
        if rid:
            try:
                matched_rule_ids.append(int(rid))
            except ValueError:
                pass

    root_id, root_name, payload_snippet, matched_var = identify_root_rule(messages)
    inbound_score = extract_inbound_score(messages)

    return {
        "waf_txn_id": waf_txn_id,
        "correlation_id": correlation_id,
        "matched_rule_ids": matched_rule_ids,
        "root_rule_id": root_id,
        "root_rule_name": root_name,
        "inbound_score": inbound_score,
        "disruptive_action": disruptive_action,
        "interrupt_phase": interrupt_phase,
        "waf_payload_snippet": payload_snippet,
        "waf_matched_variable": matched_var,
        "raw_log_ref": raw_log_ref,
        "client_ip": client_ip,
        "method": method,
        "uri": uri,
        "status_code": status_code,
    }


def get_sample_audit_log_sqli() -> str:
    """Returns a representative ModSecurity v3 serial JSON record for an SQLi attack."""
    return json.dumps({
        "transaction": {
            "client_ip": "127.0.0.1",
            "time": "02/Nov/2026:14:32:05 +0000",
            "transaction_id": "172753392512.928174",
            "unique_id": "172753392512.928174",
            "request": {
                "method": "POST",
                "uri": "/login",
                "http_version": 1.1,
                "headers": {
                    "Host": "localhost:8080",
                    "User-Agent": "WAFBench-Runner/1.0",
                    "Content-Type": "application/json",
                    "X-Request-ID": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
                }
            },
            "response": {
                "http_code": 403
            },
            "producer": {
                "modsecurity": "ModSecurity v3.0.12",
                "connector": "ModSecurity-nginx v1.0.3",
                "action": "interrupted",
                "phase": 2
            },
            "messages": [
                {
                    "message": "SQL Injection Attack Detected via libinjection",
                    "details": {
                        "match": "matched libinjection operator",
                        "ruleId": "942100",
                        "ruleName": "SQLi libinjection operator",
                        "file": "/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
                        "lineNumber": "45",
                        "data": "admin' --",
                        "variable": "ARGS:username"
                    }
                },
                {
                    "message": "Inbound Anomaly Score Exceeded (Total Inbound Score: 10 - Anomaly Threshold 5)",
                    "details": {
                        "match": "operator GE",
                        "ruleId": "949110",
                        "ruleName": "Inbound Anomaly Score Evaluation",
                        "file": "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf",
                        "lineNumber": "88",
                        "data": "",
                        "variable": "TX:INBOUND_ANOMALY_SCORE"
                    }
                }
            ]
        }
    })


def get_sample_audit_log_benign() -> str:
    """Returns a representative ModSecurity v3 serial JSON record for benign traffic."""
    return json.dumps({
        "transaction": {
            "client_ip": "127.0.0.1",
            "time": "02/Nov/2026:14:33:15 +0000",
            "transaction_id": "172753392512.928175",
            "unique_id": "172753392512.928175",
            "request": {
                "method": "GET",
                "uri": "/search?q=hello",
                "http_version": 1.1,
                "headers": {
                    "Host": "localhost:8080",
                    "X-Request-ID": "b1234567-89ab-cdef-0123-456789abcdef"
                }
            },
            "response": {
                "http_code": 200
            },
            "producer": {
                "action": "allow"
            },
            "messages": []
        }
    })


def run_tests():
    """Runs automated verification on sample ModSecurity audit records."""
    print("=" * 78)
    print("           WAFBench ModSecurity Log Parser Verification Suite")
    print("=" * 78)

    #
    #
    # VERY IMPORTANT NOTE: the values and variables below only serves as test information so that the program can be checked and see if it works fully or not
    #
    #

    # Test 1: SQL Injection (Blocked)
    print("\n[Test 1] Parsing SQL Injection Audit Record (Blocking Mode)...")
    raw_sqli = get_sample_audit_log_sqli()
    parsed_sqli = parse_audit_record(raw_sqli)

    assert parsed_sqli is not None, "Failed to parse valid SQLi record"
    assert parsed_sqli["correlation_id"] == "f47ac10b-58cc-4372-a567-0e02b2c3d479"
    assert parsed_sqli["inbound_score"] == 10
    assert parsed_sqli["disruptive_action"] == "block"
    assert parsed_sqli["root_rule_id"] == 942100
    assert parsed_sqli["waf_payload_snippet"] == "admin' --"
    assert parsed_sqli["waf_matched_variable"] == "ARGS:username"
    assert parsed_sqli["status_code"] == 403

    print("[+] Test 1 Passed! Extracted ECS-lite fields:")
    for k, v in parsed_sqli.items():
        print(f"    * {k:<22}: {v}")

    # Test 2: Benign Traffic (Passed)
    print("\n[Test 2] Parsing Benign Traffic Record (Clean)...")
    raw_benign = get_sample_audit_log_benign()
    parsed_benign = parse_audit_record(raw_benign)

    assert parsed_benign is not None, "Failed to parse valid benign record"
    assert parsed_benign["correlation_id"] == "b1234567-89ab-cdef-0123-456789abcdef"
    assert parsed_benign["inbound_score"] == 0
    assert parsed_benign["disruptive_action"] == "allow"
    assert parsed_benign["root_rule_id"] is None
    assert parsed_benign["status_code"] == 200

    print("[+] Test 2 Passed! Extracted ECS-lite fields:")
    for k, v in parsed_benign.items():
        print(f"    * {k:<22}: {v}")

    # Test 3: Malformed JSON handling
    print("\n[Test 3] Testing Malformed JSON & Incomplete Line Handling...")
    bad_parsed = parse_audit_record("{ this is not valid json }")
    assert bad_parsed is None, "Malformed JSON must return None"
    print("[+] Test 3 Passed! Correctly shielded against malformed input.")

    print("\n" + "=" * 78)
    print("[SUCCESS] All log-parser tests passed cleanly!")
    print("=" * 78)


if __name__ == "__main__":
    if "--test" in sys.argv or len(sys.argv) == 1:
        run_tests()
    elif len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        # Direct string parse from CLI argument
        res = parse_audit_record(sys.argv[1])
        print(json.dumps(res, indent=2))
