#!/usr/bin/env python3
"""
Corpus Generator: Standardizes and generates raw HTTP request test cases
with placeholders for dynamic Host and X-Request-ID according to Table 4.4.
Includes base corpus, extended evasion variants, and holdout regression suite.
Author: Tran Quoc Bao
"""

import os
import json

# ==============================================================================
# 1. BASE & EXTENDED CORPUS (cases/malicious & cases/benign)
# ==============================================================================
BASE_AND_EXTENDED_CASES = [
    # --- SQL Injection Suite ---
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
        "body": json.dumps({"username": "admin'-- ", "password": "x"}),
        "target_dir": "malicious"
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
        "body": json.dumps({"username": "alice", "password": "alice_pass_secret"}),
        "target_dir": "benign"
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
        "body": json.dumps({"username": "o'brien", "password": "password123"}),
        "target_dir": "benign"
    },
    {
        "case_id": "SQLI-002",
        "family": "SQL Injection",
        "label": "malicious",
        "endpoint": "/login",
        "method": "POST",
        "headers": {
            "Content-Type": "application/json",
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": json.dumps({"username": "' OR '1'='1' -- ", "password": "x"}),
        "target_dir": "malicious"
    },
    {
        "case_id": "SQLI-002-B1",
        "family": "SQL Injection",
        "label": "benign",
        "endpoint": "/login",
        "method": "POST",
        "headers": {
            "Content-Type": "application/json",
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": json.dumps({"username": "bob", "password": "bob_pass_secret"}),
        "target_dir": "benign"
    },
    {
        "case_id": "SQLI-002-B2",
        "family": "SQL Injection",
        "label": "edge",
        "endpoint": "/login",
        "method": "POST",
        "headers": {
            "Content-Type": "application/json",
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": json.dumps({"username": "d'angelo", "password": "secure_pass_123"}),
        "target_dir": "benign"
    },
    {
        "case_id": "SQLI-003",
        "family": "SQL Injection",
        "label": "malicious",
        "endpoint": "/login",
        "method": "POST",
        "headers": {
            "Content-Type": "application/json",
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": json.dumps({"username": "admin'/**/OR/**/'1'='1", "password": "x"}),
        "target_dir": "malicious"
    },
    {
        "case_id": "SQLI-003-B1",
        "family": "SQL Injection",
        "label": "benign",
        "endpoint": "/login",
        "method": "POST",
        "headers": {
            "Content-Type": "application/json",
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": json.dumps({"username": "carol_user", "password": "standard_pass"}),
        "target_dir": "benign"
    },

    # --- Reflected XSS Suite ---
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
        "body": "",
        "target_dir": "malicious"
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
        "body": "",
        "target_dir": "benign"
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
        "body": "",
        "target_dir": "benign"
    },
    {
        "case_id": "XSS-002",
        "family": "Reflected XSS",
        "label": "malicious",
        "endpoint": "/search?q=%3Cimg%20src=x%20onerror=alert(1)%3E",
        "method": "GET",
        "headers": {
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": "",
        "target_dir": "malicious"
    },
    {
        "case_id": "XSS-002-B1",
        "family": "Reflected XSS",
        "label": "benign",
        "endpoint": "/search?q=machine+learning+and+artificial+intelligence",
        "method": "GET",
        "headers": {
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": "",
        "target_dir": "benign"
    },
    {
        "case_id": "XSS-003",
        "family": "Reflected XSS",
        "label": "malicious",
        "endpoint": "/search?q=%3Csvg/onload=alert(1)%3E",
        "method": "GET",
        "headers": {
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": "",
        "target_dir": "malicious"
    },
    {
        "case_id": "XSS-003-B1",
        "family": "Reflected XSS",
        "label": "benign",
        "endpoint": "/search?q=scalable+vector+graphics+guide",
        "method": "GET",
        "headers": {
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": "",
        "target_dir": "benign"
    },

    # --- Path Traversal Suite ---
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
        "body": "",
        "target_dir": "malicious"
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
        "body": "",
        "target_dir": "benign"
    },
    {
        "case_id": "PATH-002",
        "family": "Path Traversal",
        "label": "malicious",
        "endpoint": "/file?filename=..%2f..%2f..%2f..%2fetc%2fpasswd",
        "method": "GET",
        "headers": {
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": "",
        "target_dir": "malicious"
    },
    {
        "case_id": "PATH-002-B1",
        "family": "Path Traversal",
        "label": "benign",
        "endpoint": "/file?filename=whitepaper_2024.pdf",
        "method": "GET",
        "headers": {
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": "",
        "target_dir": "benign"
    },

    # --- SSRF Suite ---
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
        "body": json.dumps({"url": "http://mock-internal:8080/metadata"}),
        "target_dir": "malicious"
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
        "body": json.dumps({"url": "http://mock-internal:8080/public/avatar.png"}),
        "target_dir": "benign"
    },
    {
        "case_id": "SSRF-002",
        "family": "SSRF",
        "label": "malicious",
        "endpoint": "/fetch",
        "method": "POST",
        "headers": {
            "Content-Type": "application/json",
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": json.dumps({"url": "http://127.0.0.1:8080/metadata"}),
        "target_dir": "malicious"
    },
    {
        "case_id": "SSRF-002-B1",
        "family": "SSRF",
        "label": "benign",
        "endpoint": "/fetch",
        "method": "POST",
        "headers": {
            "Content-Type": "application/json",
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": json.dumps({"url": "http://mock-internal:8080/public/logo.png"}),
        "target_dir": "benign"
    }
]

# ==============================================================================
# 2. HOLDOUT REGRESSION SUITE (cases/holdout)
# Reserved specifically for evaluating Regression Pass Rate (RPR) post C0 -> C1 tuning
# ==============================================================================
HOLDOUT_CASES = [
    # Holdout SQLi
    {
        "case_id": "HOLD-SQLI-001",
        "family": "SQL Injection",
        "label": "malicious",
        "endpoint": "/login",
        "method": "POST",
        "headers": {
            "Content-Type": "application/json",
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": json.dumps({"username": "admin' UNION SELECT 1, 'admin', 'admin' -- ", "password": "x"}),
        "target_dir": "holdout"
    },
    {
        "case_id": "HOLD-SQLI-001-B1",
        "family": "SQL Injection",
        "label": "benign",
        "endpoint": "/login",
        "method": "POST",
        "headers": {
            "Content-Type": "application/json",
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": json.dumps({"username": "david_miller", "password": "valid_user_pass"}),
        "target_dir": "holdout"
    },
    {
        "case_id": "HOLD-SQLI-001-B2",
        "family": "SQL Injection",
        "label": "edge",
        "endpoint": "/login",
        "method": "POST",
        "headers": {
            "Content-Type": "application/json",
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": json.dumps({"username": "mcdonald's_corp", "password": "corp_pwd_secure"}),
        "target_dir": "holdout"
    },

    # Holdout XSS
    {
        "case_id": "HOLD-XSS-001",
        "family": "Reflected XSS",
        "label": "malicious",
        "endpoint": "/search?q=%3Ciframe%20src=%22javascript:alert(1)%22%3E",
        "method": "GET",
        "headers": {
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": "",
        "target_dir": "holdout"
    },
    {
        "case_id": "HOLD-XSS-001-B1",
        "family": "Reflected XSS",
        "label": "benign",
        "endpoint": "/search?q=modern+html5+responsive+design",
        "method": "GET",
        "headers": {
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": "",
        "target_dir": "holdout"
    },

    # Holdout Path Traversal
    {
        "case_id": "HOLD-PATH-001",
        "family": "Path Traversal",
        "label": "malicious",
        "endpoint": "/file?filename=....//....//....//....//etc/passwd",
        "method": "GET",
        "headers": {
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": "",
        "target_dir": "holdout"
    },
    {
        "case_id": "HOLD-PATH-001-B1",
        "family": "Path Traversal",
        "label": "benign",
        "endpoint": "/file?filename=company_guidelines.pdf",
        "method": "GET",
        "headers": {
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": "",
        "target_dir": "holdout"
    },

    # Holdout SSRF
    {
        "case_id": "HOLD-SSRF-001",
        "family": "SSRF",
        "label": "malicious",
        "endpoint": "/fetch",
        "method": "POST",
        "headers": {
            "Content-Type": "application/json",
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": json.dumps({"url": "http://localhost:8080/metadata"}),
        "target_dir": "holdout"
    },
    {
        "case_id": "HOLD-SSRF-001-B1",
        "family": "SSRF",
        "label": "benign",
        "endpoint": "/fetch",
        "method": "POST",
        "headers": {
            "Content-Type": "application/json",
            "X-Request-ID": "{correlation_id}",
            "Host": "{host}"
        },
        "body": json.dumps({"url": "http://mock-internal:8080/public/favicon.ico"}),
        "target_dir": "holdout"
    }
]

def generate_cases():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cases_dir = os.path.join(base_dir, "cases")
    
    all_cases = BASE_AND_EXTENDED_CASES + HOLDOUT_CASES
    generated_counts = {"malicious": 0, "benign": 0, "holdout": 0}

    for item in all_cases:
        target_dir = item.pop("target_dir")
        target_path = os.path.join(cases_dir, target_dir, f"{item['case_id']}.json")
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(item, f, indent=2)
            
        generated_counts[target_dir] += 1
        print(f"[+] Generated: [{target_dir}] {item['case_id']}.json")

    print("\n" + "=" * 60)
    print(f"Total Test Cases Generated: {len(all_cases)}")
    print(f"  • Base & Extended Malicious : {generated_counts['malicious']} cases")
    print(f"  • Base & Extended Benign/Edge: {generated_counts['benign']} cases")
    print(f"  • Holdout Regression Suite  : {generated_counts['holdout']} cases")
    print("=" * 60)

if __name__ == "__main__":
    generate_cases()
