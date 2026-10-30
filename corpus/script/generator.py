#!/usr/bin/env python3
"""
Corpus Generator: Standardizes and generates raw HTTP request test cases
with placeholders for dynamic Host and X-Request-ID according to Table 4.4.
Author: Tran Quoc Bao
"""

import os
import json

BASE_CASES = [
    {
        "case_id": "SQLI-001",
        "family": "SQL Injection",
        "label": "malicious",
        "endpoint": "/login",
        "method": "POST",
        "headers": {
            "Content-Type": "application/json",
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": json.dumps({"username": "admin'-- ", "password": "x"})
    },
    {
        "case_id": "SQLI-001-B1",
        "family": "SQL Injection",
        "label": "benign",
        "endpoint": "/login",
        "method": "POST",
        "headers": {
            "Content-Type": "application/json",
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": json.dumps({"username": "alice", "password": "alice_pass_secret"})
    },
    {
        "case_id": "SQLI-001-B2",
        "family": "SQL Injection",
        "label": "edge",
        "endpoint": "/login",
        "method": "POST",
        "headers": {
            "Content-Type": "application/json",
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": json.dumps({"username": "o'brien", "password": "password123"})
    },
    {
        "case_id": "XSS-001",
        "family": "Reflected XSS",
        "label": "malicious",
        "endpoint": "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "method": "GET",
        "headers": {
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": ""
    },
    {
        "case_id": "XSS-001-B1",
        "family": "Reflected XSS",
        "label": "benign",
        "endpoint": "/search?q=web+application+security",
        "method": "GET",
        "headers": {
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": ""
    },
    {
        "case_id": "XSS-001-B2",
        "family": "Reflected XSS",
        "label": "edge",
        "endpoint": "/search?q=O'Reilly+Learning+Platform",
        "method": "GET",
        "headers": {
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": ""
    },
    {
        "case_id": "PATH-001",
        "family": "Path Traversal",
        "label": "malicious",
        "endpoint": "/file?filename=../../../../etc/passwd",
        "method": "GET",
        "headers": {
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": ""
    },
    {
        "case_id": "PATH-001-B1",
        "family": "Path Traversal",
        "label": "benign",
        "endpoint": "/file?filename=report_2023.pdf",
        "method": "GET",
        "headers": {
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": ""
    },
    {
        "case_id": "SSRF-001",
        "family": "SSRF",
        "label": "malicious",
        "endpoint": "/fetch",
        "method": "POST",
        "headers": {
            "Content-Type": "application/json",
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": json.dumps({"url": "http://mock-internal:8080/metadata"})
    },
    {
        "case_id": "SSRF-001-B1",
        "family": "SSRF",
        "label": "benign",
        "endpoint": "/fetch",
        "method": "POST",
        "headers": {
            "Content-Type": "application/json",
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": json.dumps({"url": "http://mock-internal:8080/public/avatar.png"})
    }
]

def generate_cases():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cases_dir = os.path.join(base_dir, "cases")
    
    for case in BASE_CASES:
        sub_dir = "malicious" if case["label"] == "malicious" else "benign"
        target_path = os.path.join(cases_dir, sub_dir, f"{case['case_id']}.json")
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(case, f, indent=2)
        print(f"[+] Generated: {target_path}")

if __name__ == "__main__":
    generate_cases()
