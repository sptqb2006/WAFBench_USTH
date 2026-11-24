#!/usr/bin/env python3
"""ModSecurity v3 Serial JSON Audit Log Parser -> ECS-lite Normalization (Stage 2: Evidence Collection)
Conforming to WAFBench Table 4.3 (Normalized Events) & Table 3 (Audit Log Mapping)
"""

import sys
import json
import re
import hashlib
from typing import Optional, Dict, Any, List

# CRS evaluation rules: they report the total score, they do not detect an attack family themselves
INBOUND_EVAL_RULE = 949110
OUTBOUND_EVAL_RULE = 959100
META_RULES = {INBOUND_EVAL_RULE, OUTBOUND_EVAL_RULE, 980130, 980140, 980170}

_TOTAL_SCORE = re.compile(r"Total (?:Inbound |Outbound )?Score:\s*(\d+)", re.IGNORECASE)
_MATCHED_VAR = re.compile(r"found within ([A-Z_]+(?::[^:\s]+)?)")
_MATCH_AGAINST_VAR = re.compile(r"against variable `([^']+)'")


def _message_text(msg: Dict[str, Any]) -> str:
    details = msg.get("details", {}) or {}
    return f"{msg.get('message', '')} {details.get('data', '')}"


def _rule_id(msg: Dict[str, Any]) -> Optional[int]:
    raw = (msg.get("details", {}) or {}).get("ruleId")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def extract_scores(messages: List[Dict[str, Any]]) -> tuple:
    """
    Returns (inbound_score, outbound_score).
    CRS v4 writes the total only in its evaluation rules:
      949110 'Inbound Anomaly Score Exceeded (Total Score: 10)'
      959100 'Outbound Anomaly Score Exceeded (Total Score: 4)'
    When no evaluation rule fired, the total stayed below the threshold and is not logged (0 here).
    """
    inbound, outbound = 0, 0
    for msg in messages:
        match = _TOTAL_SCORE.search(_message_text(msg))
        if not match:
            continue
        score = int(match.group(1))
        rid = _rule_id(msg)
        text = msg.get("message", "").lower()
        if rid == OUTBOUND_EVAL_RULE or "outbound" in text:
            outbound = max(outbound, score)
        else:
            inbound = max(inbound, score)
    return inbound, outbound


def extract_inbound_score(messages: List[Dict[str, Any]]) -> int:
    """Kept for callers of the previous API."""
    return extract_scores(messages)[0]


def identify_root_rule(messages: List[Dict[str, Any]]) -> tuple:
    """
    Identifies the primary offending attack rule from triggered CRS messages.
    Skips evaluation/meta rules (949110 / 959100 / 980xxx) and prefers attack family rules
    (930xxx-944xxx: LFI, RFI, RCE, PHP, XSS, SQLi...). Custom rules are used as a fallback.
    """
    root = (None, None, None, None)
    for msg in messages:
        rule_id = _rule_id(msg)
        if rule_id is None or rule_id in META_RULES:
            continue
        details = msg.get("details", {}) or {}
        data = details.get("data")
        variable = details.get("variable")
        if not variable:
            # "Matched Data: ... found within ARGS:q: ..." or "... against variable `REQUEST_HEADERS:Host' ..."
            found = _MATCHED_VAR.search(data or "") or _MATCH_AGAINST_VAR.search(details.get("match") or "")
            variable = found.group(1) if found else None
        candidate = (rule_id, details.get("ruleName") or msg.get("message"), data, variable)
        if 930000 <= rule_id <= 944999:
            return candidate
        if root[0] is None:
            root = candidate
    return root


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

    txn = data.get("transaction", {}) if isinstance(data, dict) else {}
    if not txn:
        return None

    # 1. SHA-256 fingerprint of the raw line, kept as a reference to the audit entry
    raw_log_ref = "sha256:" + hashlib.sha256(json_str.strip().encode("utf-8")).hexdigest()

    # 2. Transaction & client identity
    waf_txn_id = txn.get("unique_id") or txn.get("transaction_id")
    req = txn.get("request", {}) or {}
    headers = req.get("headers", {}) or {}

    # Correlation key: X-Request-ID, header names are case-insensitive
    correlation_id = None
    for k, v in headers.items():
        if k.lower() == "x-request-id":
            correlation_id = str(v).strip() or None
            break

    # 3. Engine mode and enforcement
    # producer.secrules_engine is "Enabled" (Blocking), "DetectionOnly" or "Disabled"
    producer = txn.get("producer", {}) or {}
    engine_mode = producer.get("secrules_engine")
    waf_http_code = (txn.get("response", {}) or {}).get("http_code")
    legacy_action = str(producer.get("action", "")).lower()

    # A DetectionOnly engine never interrupts; a 403 in that mode comes from the application
    if engine_mode == "DetectionOnly":
        disruptive_action = "allow" if waf_http_code is not None else "none"
    elif waf_http_code == 403 or legacy_action in ("interrupted", "block", "deny"):
        disruptive_action = "block"
    elif waf_http_code is not None:
        disruptive_action = "allow"
    else:
        disruptive_action = "none"
    interrupt_phase = producer.get("phase", 2) if disruptive_action == "block" else None

    # 4. Rules and anomaly scores
    messages = txn.get("messages", []) or []
    matched_rule_ids = []
    for msg in messages:
        rid = _rule_id(msg)
        if rid is not None and rid not in matched_rule_ids:
            matched_rule_ids.append(rid)

    root_id, root_name, payload_snippet, matched_var = identify_root_rule(messages)
    inbound_score, outbound_score = extract_scores(messages)

    return {
        "waf_txn_id": waf_txn_id,
        "correlation_id": correlation_id,
        "matched_rule_ids": matched_rule_ids,
        "root_rule_id": root_id,
        "root_rule_name": root_name,
        "inbound_score": inbound_score,
        "outbound_score": outbound_score,
        "disruptive_action": disruptive_action,
        "interrupt_phase": interrupt_phase,
        "waf_engine_mode": engine_mode,
        "waf_http_code": waf_http_code,
        "waf_payload_snippet": payload_snippet,
        "waf_matched_variable": matched_var,
        "raw_log_ref": raw_log_ref,
        "client_ip": txn.get("client_ip"),
        "method": req.get("method"),
        "uri": req.get("uri"),
        "status_code": waf_http_code,
    }


def get_sample_audit_log_sqli() -> str:
    """Representative ModSecurity v3 serial JSON record for an SQLi attack blocked in Blocking mode."""
    return json.dumps({
        "transaction": {
            "client_ip": "127.0.0.1",
            "time_stamp": "Mon Nov  2 14:32:05 2026",
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
            "response": {"http_code": 403},
            "producer": {
                "modsecurity": "ModSecurity v3.0.12 (Linux)",
                "connector": "ModSecurity-nginx v1.0.3",
                "secrules_engine": "Enabled",
                "components": ["OWASP_CRS/4.0.0"]
            },
            "messages": [
                {
                    "message": "SQL Injection Attack Detected via libinjection",
                    "details": {
                        "match": "detected SQLi using libinjection.",
                        "ruleId": "942100",
                        "file": "/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
                        "lineNumber": "46",
                        "data": "Matched Data: s&1c found within ARGS:json.username: admin'-- ",
                        "severity": "2"
                    }
                },
                {
                    "message": "Inbound Anomaly Score Exceeded (Total Score: 10)",
                    "details": {
                        "match": "Matched \"Operator `Ge' with parameter `5' against variable `TX:BLOCKING_INBOUND_ANOMALY_SCORE' (Value: `10' )",
                        "ruleId": "949110",
                        "file": "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf",
                        "lineNumber": "222",
                        "data": "",
                        "severity": "0"
                    }
                }
            ]
        }
    })


def get_sample_audit_log_benign() -> str:
    """Representative record for a benign request that touched no rule set to block."""
    return json.dumps({
        "transaction": {
            "client_ip": "127.0.0.1",
            "unique_id": "172753392512.928175",
            "request": {
                "method": "GET",
                "uri": "/search?q=hello",
                "http_version": 1.1,
                "headers": {
                    "Host": "localhost:8080",
                    "x-request-id": "b1234567-89ab-cdef-0123-456789abcdef"
                }
            },
            "response": {"http_code": 200},
            "producer": {"secrules_engine": "DetectionOnly"},
            "messages": []
        }
    })


def get_sample_audit_log_detection_only_xss() -> str:
    """XSS detected in DetectionOnly: 949110 fired, the request still reached the app (200)."""
    return json.dumps({
        "transaction": {
            "unique_id": "172753392512.928176",
            "request": {
                "method": "GET",
                "uri": "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
                "headers": {"X-Request-ID": "c0ffee00-0000-4000-8000-000000000001"}
            },
            "response": {"http_code": 200},
            "producer": {"secrules_engine": "DetectionOnly"},
            "messages": [
                {"message": "XSS Attack Detected via libinjection",
                 "details": {"ruleId": "941100", "data": "Matched Data: XSS data found within ARGS:q: <script>alert(1)</script>"}},
                {"message": "Inbound Anomaly Score Exceeded (Total Score: 15)",
                 "details": {"ruleId": "949110", "data": ""}},
                {"message": "Outbound Anomaly Score Exceeded (Total Score: 4)",
                 "details": {"ruleId": "959100", "data": ""}}
            ]
        }
    })


def run_tests():
    """Runs automated verification on sample ModSecurity audit records."""
    print("=" * 78)
    print("           WAFBench ModSecurity Log Parser Verification Suite")
    print("=" * 78)

    # The values below are fixtures for checking the parser only

    print("\n[Test 1] SQL Injection record (Blocking mode)...")
    p = parse_audit_record(get_sample_audit_log_sqli())
    assert p is not None, "Failed to parse valid SQLi record"
    assert p["correlation_id"] == "f47ac10b-58cc-4372-a567-0e02b2c3d479"
    assert p["matched_rule_ids"] == [942100, 949110]
    assert p["inbound_score"] == 10 and p["outbound_score"] == 0
    assert p["disruptive_action"] == "block"
    assert p["waf_engine_mode"] == "Enabled"
    assert p["root_rule_id"] == 942100
    assert p["waf_matched_variable"] == "ARGS:json.username"
    assert p["waf_http_code"] == 403
    print("[+] Test 1 passed")

    print("\n[Test 2] Benign record (lower-case header name)...")
    p = parse_audit_record(get_sample_audit_log_benign())
    assert p is not None
    assert p["correlation_id"] == "b1234567-89ab-cdef-0123-456789abcdef"
    assert p["inbound_score"] == 0
    assert p["disruptive_action"] == "allow"
    assert p["root_rule_id"] is None
    print("[+] Test 2 passed")

    print("\n[Test 3] DetectionOnly XSS: inbound and outbound scores kept apart...")
    p = parse_audit_record(get_sample_audit_log_detection_only_xss())
    assert p["inbound_score"] == 15 and p["outbound_score"] == 4
    assert p["disruptive_action"] == "allow", "DetectionOnly never blocks"
    assert p["root_rule_id"] == 941100 and p["waf_matched_variable"] == "ARGS:q"
    print("[+] Test 3 passed")

    print("\n[Test 4] Malformed and non-transaction input...")
    assert parse_audit_record("{ this is not valid json }") is None
    assert parse_audit_record('{"something": "else"}') is None
    assert parse_audit_record("[1, 2]") is None
    assert parse_audit_record("   ") is None
    print("[+] Test 4 passed")

    print("\n" + "=" * 78)
    print("[SUCCESS] All log-parser tests passed cleanly!")
    print("=" * 78)


if __name__ == "__main__":
    if "--test" in sys.argv or len(sys.argv) == 1:
        run_tests()
    elif len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        res = parse_audit_record(sys.argv[1])
        print(json.dumps(res, indent=2))
