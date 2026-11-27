#!/usr/bin/env python3
"""
Corpus Generator: Standardizes and generates raw HTTP request test cases
with placeholders for dynamic Host and X-Request-ID according to Table 4.4.
Generates 220 main benchmark cases (55 per family: 25 malicious, 25 paired benign,
5 edge cases) + 9 holdout regression cases = 229 total test cases.
"""

import os
import json
import urllib.parse


def _json_headers():
    return {
        "Content-Type": "application/json",
        "X-Request-ID": "{correlation_id}",
        "Host": "{host}",
    }


def _get_headers():
    return {
        "X-Request-ID": "{correlation_id}",
        "Host": "{host}",
    }


# ==============================================================================
# 1. SQL INJECTION SUITE (25 malicious + 25 paired benign + 5 edge = 55 cases)
# ==============================================================================
SQLI_MALICIOUS = [
    ("SQLI-001", "admin'-- ", "x"),
    ("SQLI-002", "' OR '1'='1' -- ", "x"),
    ("SQLI-003", "admin'/**/OR/**/'1'='1", "x"),
    ("SQLI-004", "' OR 1=1-- ", "x"),
    ("SQLI-005", "admin'/*", "*/-- "),
    ("SQLI-006", "' OR TRUE-- ", "x"),
    ("SQLI-007", "alice'-- ", "wrong"),
    ("SQLI-008", "bob'-- ", "wrong"),
    ("SQLI-009", "' OR 'a'='a'-- ", "x"),
    ("SQLI-010", "' OR ('1'='1')-- ", "x"),
    ("SQLI-011", "' OR 2>1-- ", "x"),
    ("SQLI-012", "' OR 'x'='x'/*", "*/-- "),
    ("SQLI-013", "admin' OR 1=1 LIMIT 1-- ", "x"),
    ("SQLI-014", "' UNION SELECT 1,'admin','administrator'-- ", "x"),
    ("SQLI-015", "' UNION ALL SELECT 1,'admin','administrator'-- ", "x"),
    ("SQLI-016", "'/**/oR/**/1=1-- ", "x"),
    ("SQLI-017", "admin' OR '1'='1' OFFSET 0-- ", "x"),
    ("SQLI-018", "' OR 100=100-- ", "x"),
    ("SQLI-019", "' OR NOT FALSE-- ", "x"),
    ("SQLI-020", "admin' AND 1=1-- ", "x"),
    ("SQLI-021", "' OR username='admin'-- ", "x"),
    ("SQLI-022", "' OR role='administrator'-- ", "x"),
    ("SQLI-023", "' OR LENGTH(username)>0-- ", "x"),
    ("SQLI-024", "' OR 1=1 ORDER BY 1-- ", "x"),
    ("SQLI-025", "admin'/**/AND/**/'a'='a'-- ", "x"),
]

SQLI_PAIRED_BENIGN = [
    ("SQLI-001-B1", "alice", "alice_pass_secret", None),
    ("SQLI-002-B1", "bob", "bob_pass_simple", None),
    ("SQLI-003-B1", "carol_user", "standard_pass", 401),
    ("SQLI-004-B1", "admin", "admin_pass_2024!", None),
    ("SQLI-005-B1", "alice", "alice_pass_secret", None),
    ("SQLI-006-B1", "bob", "bob_pass_simple", None),
    ("SQLI-007-B1", "alice", "wrong_password_1", 401),
    ("SQLI-008-B1", "bob", "wrong_password_2", 401),
    ("SQLI-009-B1", "admin", "wrong_admin_pass", 401),
    ("SQLI-010-B1", "alice", "alice_pass_secret", None),
    ("SQLI-011-B1", "bob", "bob_pass_simple", None),
    ("SQLI-012-B1", "admin", "admin_pass_2024!", None),
    ("SQLI-013-B1", "editor_01", "pass_editor_2026", 401),
    ("SQLI-014-B1", "viewer_02", "pass_viewer_2026", 401),
    ("SQLI-015-B1", "alice", "alice_pass_secret", None),
    ("SQLI-016-B1", "bob", "bob_pass_simple", None),
    ("SQLI-017-B1", "admin", "admin_pass_2024!", None),
    ("SQLI-018-B1", "student_usth", "usth_pass_2026", 401),
    ("SQLI-019-B1", "tester_lab", "lab_secret_01", 401),
    ("SQLI-020-B1", "alice", "alice_pass_secret", None),
    ("SQLI-021-B1", "bob", "bob_pass_simple", None),
    ("SQLI-022-B1", "admin", "admin_pass_2024!", None),
    ("SQLI-023-B1", "guest_user", "guest_pass_123", 401),
    ("SQLI-024-B1", "alice", "alice_pass_secret", None),
    ("SQLI-025-B1", "bob", "bob_pass_simple", None),
]

SQLI_EDGE = [
    ("SQLI-001-B2", "o'brien", "password123", 401),
    ("SQLI-002-B2", "d'angelo", "secure_pass_123", 401),
    ("SQLI-003-B2", "john.o'connor", "user_pass_2026", 401),
    ("SQLI-004-B2", "jean-luc", "starfleet_pass", 401),
    ("SQLI-005-B2", "user_2026", "normal_pass_99", 401),
]

# ==============================================================================
# 2. REFLECTED XSS SUITE (25 malicious + 25 paired benign + 5 edge = 55 cases)
# ==============================================================================
XSS_MALICIOUS = [
    ("XSS-001", "<script>alert(1)</script>"),
    ("XSS-002", "<img src=x onerror=alert(1)>"),
    ("XSS-003", "<svg/onload=alert(1)>"),
    ("XSS-004", "<ScRiPt>alert(1)</ScRiPt>"),
    ("XSS-005", "<script>alert('xss')</script>"),
    ("XSS-006", "<body onload=alert(1)>"),
    ("XSS-007", "<svg onload=alert(1)>"),
    ("XSS-008", "<img/src=x/onerror=alert(1)>"),
    ("XSS-009", "<details open ontoggle=alert(1)>"),
    ("XSS-010", "<input autofocus onfocus=alert(1)>"),
    ("XSS-011", "<iframe src=\"javascript:alert(1)\"></iframe>"),
    ("XSS-012", "<a href=\"javascript:alert(1)\">click</a>"),
    ("XSS-013", "<marquee onstart=alert(1)>test</marquee>"),
    ("XSS-014", "<video><source onerror=alert(1)></video>"),
    ("XSS-015", "<audio src=x onerror=alert(1)>"),
    ("XSS-016", "<object data=\"javascript:alert(1)\"></object>"),
    ("XSS-017", "<embed src=\"javascript:alert(1)\">"),
    ("XSS-018", "<math><mtext></mtext><script>alert(1)</script></math>"),
    ("XSS-019", "<form><button formaction=\"javascript:alert(1)\">go</button></form>"),
    ("XSS-020", "<select autofocus onfocus=alert(1)></select>"),
    ("XSS-021", "<textarea autofocus onfocus=alert(1)></textarea>"),
    ("XSS-022", "<div onmouseover=alert(1)>hover</div>"),
    ("XSS-023", "<style>@import 'javascript:alert(1)';</style>"),
    ("XSS-024", "\"><script>alert(1)</script>"),
    ("XSS-025", "'><img src=x onerror=alert(1)>"),
]

XSS_PAIRED_BENIGN = [
    ("XSS-001-B1", "web application security"),
    ("XSS-002-B1", "machine learning and artificial intelligence"),
    ("XSS-003-B1", "scalable vector graphics guide"),
    ("XSS-004-B1", "owasp core rule set documentation"),
    ("XSS-005-B1", "nginx reverse proxy tuning"),
    ("XSS-006-B1", "modsecurity v3 architecture"),
    ("XSS-007-B1", "postgresql indexing best practices"),
    ("XSS-008-B1", "docker bridge network isolation"),
    ("XSS-009-B1", "http response status codes"),
    ("XSS-010-B1", "automated benchmark methodology"),
    ("XSS-011-B1", "rest api json validation"),
    ("XSS-012-B1", "session token hmac sha256"),
    ("XSS-013-B1", "anomaly scoring threshold pl1"),
    ("XSS-014-B1", "telemetry log normalization ecs"),
    ("XSS-015-B1", "streamlit forensic dashboard"),
    ("XSS-016-B1", "false positive rate analysis"),
    ("XSS-017-B1", "waf detection only mode"),
    ("XSS-018-B1", "waf blocking enforcement mode"),
    ("XSS-019-B1", "direct to app baseline oracle"),
    ("XSS-020-B1", "correlation id request tracing"),
    ("XSS-021-B1", "nodejs express middleware guide"),
    ("XSS-022-B1", "alpine linux container hardening"),
    ("XSS-023-B1", "cybersecurity thesis usth 2026"),
    ("XSS-024-B1", "clean search query example"),
    ("XSS-025-B1", "application firewall evaluation"),
]

XSS_EDGE = [
    ("XSS-001-B2", "O'Reilly Learning Platform"),
    ("XSS-002-B2", "C++ and Python programming"),
    ("XSS-003-B2", "100 percent secure web guide"),
    ("XSS-004-B2", "price equals 50 USD discount"),
    ("XSS-005-B2", "book title: Alice's Adventures"),
]

# ==============================================================================
# 3. PATH TRAVERSAL SUITE (25 malicious + 25 paired benign + 5 edge = 55 cases)
# ==============================================================================
PATH_MALICIOUS = [
    ("PATH-001", "../../../../etc/passwd"),
    ("PATH-002", "..%2f..%2f..%2f..%2fetc%2fpasswd"),
    ("PATH-003", "../../../etc/passwd"),
    ("PATH-004", "../../../../../etc/passwd"),
    ("PATH-005", "../../../../../../etc/passwd"),
    ("PATH-006", "./../../../../etc/passwd"),
    ("PATH-007", ".././.././.././../etc/passwd"),
    ("PATH-008", "..//..//..//..//etc/passwd"),
    ("PATH-009", "downloads/../../../../../etc/passwd"),
    ("PATH-010", "public/../../../../../etc/passwd"),
    ("PATH-011", "....//....//....//etc/passwd"),
    ("PATH-012", "....//....//....//....//etc/passwd"),
    ("PATH-013", "..%2F..%2F..%2F..%2Fetc%2Fpasswd"),
    ("PATH-014", "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"),
    ("PATH-015", "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
    ("PATH-016", "..%2f..%2f..%2fetc%2fpasswd"),
    ("PATH-017", "../../.././../etc/passwd"),
    ("PATH-018", "../../../.././etc/passwd"),
    ("PATH-019", "../../../../etc/./passwd"),
    ("PATH-020", "../../../../etc//passwd"),
    ("PATH-021", "a/b/../../../../../../etc/passwd"),
    ("PATH-022", "report/../../../../../etc/passwd"),
    ("PATH-023", "..//..//..//etc//passwd"),
    ("PATH-024", "%2e%2e/..%2f..%2f..%2fetc/passwd"),
    ("PATH-025", "../../../../../../../etc/passwd"),
]

VALID_PDFS = ["report_2023.pdf", "whitepaper_2024.pdf", "company_guidelines.pdf"]

PATH_PAIRED_BENIGN = [
    (f"PATH-{i:03d}-B1", VALID_PDFS[(i - 1) % len(VALID_PDFS)])
    for i in range(1, 26)
]

PATH_EDGE = [
    ("PATH-001-B2", "./report_2023.pdf", None),
    ("PATH-002-B2", "./whitepaper_2024.pdf", None),
    ("PATH-003-B2", "./company_guidelines.pdf", None),
    ("PATH-004-B2", "report.2023.v1.pdf", 404),
    ("PATH-005-B2", "summary-final-2026.pdf", 404),
]

# ==============================================================================
# 4. SSRF SUITE (25 malicious + 25 paired benign + 5 edge = 55 cases)
# ==============================================================================
SSRF_MALICIOUS = [
    ("SSRF-001", "http://mock-internal:8080/metadata"),
    ("SSRF-002", "http://127.0.0.1:8080/metadata"),
    ("SSRF-003", "http://localhost:8080/metadata"),
    ("SSRF-004", "http://mock-internal:8080/metadata/"),
    ("SSRF-005", "http://mock-internal:8080/metadata?fmt=json"),
    ("SSRF-006", "http://mock-internal:8080/metadata?v=1"),
    ("SSRF-007", "http://mock-internal:8080/metadata#top"),
    ("SSRF-008", "http://mock-internal:8080/./metadata"),
    ("SSRF-009", "http://mock-internal:8080/public/../metadata"),
    ("SSRF-010", "http://MOCK-INTERNAL:8080/metadata"),
    ("SSRF-011", "http://Mock-Internal:8080/metadata"),
    ("SSRF-012", "http://127.0.0.1:8080/metadata/"),
    ("SSRF-013", "http://127.0.0.1:8080/metadata?token=1"),
    ("SSRF-014", "http://127.0.0.1:8080/./metadata"),
    ("SSRF-015", "http://127.0.0.1:8080/public/../metadata"),
    ("SSRF-016", "http://localhost:8080/metadata/"),
    ("SSRF-017", "http://localhost:8080/metadata?format=raw"),
    ("SSRF-018", "http://localhost:8080/./metadata"),
    ("SSRF-019", "http://localhost:8080/public/../metadata"),
    ("SSRF-020", "http://127.0.0.1:8080/a/../metadata"),
    ("SSRF-021", "http://mock-internal:8080/metadata?debug=true"),
    ("SSRF-022", "http://mock-internal:8080/metadata?fields=iam_role"),
    ("SSRF-023", "http://127.0.0.1:8080/metadata?source=probe"),
    ("SSRF-024", "http://localhost:8080/metadata#sec"),
    ("SSRF-025", "http://mock-internal:8080/a/../metadata"),
]

VALID_MOCK_PUBLIC = [
    "http://mock-internal:8080/public/avatar.png",
    "http://mock-internal:8080/public/logo.png",
    "http://mock-internal:8080/public/favicon.ico",
]

SSRF_PAIRED_BENIGN = [
    (f"SSRF-{i:03d}-B1", VALID_MOCK_PUBLIC[(i - 1) % len(VALID_MOCK_PUBLIC)])
    for i in range(1, 26)
]

SSRF_EDGE = [
    ("SSRF-001-B2", "http://mock-internal:8080/health"),
    ("SSRF-002-B2", "http://mock-internal:8080/public/avatar.png?v=1"),
    ("SSRF-003-B2", "http://mock-internal:8080/public/logo.png?size=small"),
    ("SSRF-004-B2", "http://mock-internal:8080/public/avatar.png#preview"),
    ("SSRF-005-B2", "http://mock-internal:8080/public/favicon.ico?cache=0"),
]

# ==============================================================================
# 5. HOLDOUT REGRESSION SUITE (9 cases preserved for RPR evaluation)
# ==============================================================================
HOLDOUT_CASES = [
    {
        "case_id": "HOLD-SQLI-001",
        "family": "SQL Injection",
        "label": "malicious",
        "endpoint": "/login",
        "method": "POST",
        "headers": _json_headers(),
        "body": json.dumps({"username": "admin' UNION SELECT 1, 'admin', 'admin' -- ", "password": "x"}),
        "target_dir": "holdout",
    },
    {
        "case_id": "HOLD-SQLI-001-B1",
        "family": "SQL Injection",
        "label": "benign",
        "endpoint": "/login",
        "method": "POST",
        "headers": _json_headers(),
        "body": json.dumps({"username": "david_miller", "password": "valid_user_pass"}),
        "expected_status": 401,
        "target_dir": "holdout",
    },
    {
        "case_id": "HOLD-SQLI-001-B2",
        "family": "SQL Injection",
        "label": "edge",
        "endpoint": "/login",
        "method": "POST",
        "headers": _json_headers(),
        "body": json.dumps({"username": "mcdonald's_corp", "password": "corp_pwd_secure"}),
        "expected_status": 401,
        "target_dir": "holdout",
    },
    {
        "case_id": "HOLD-XSS-001",
        "family": "Reflected XSS",
        "label": "malicious",
        "endpoint": "/search?q=%3Ciframe%20src=%22javascript:alert(1)%22%3E",
        "method": "GET",
        "headers": _get_headers(),
        "body": "",
        "target_dir": "holdout",
    },
    {
        "case_id": "HOLD-XSS-001-B1",
        "family": "Reflected XSS",
        "label": "benign",
        "endpoint": "/search?q=modern+html5+responsive+design",
        "method": "GET",
        "headers": _get_headers(),
        "body": "",
        "target_dir": "holdout",
    },
    {
        "case_id": "HOLD-PATH-001",
        "family": "Path Traversal",
        "label": "malicious",
        "endpoint": "/file?filename=....//....//....//....//etc/passwd",
        "method": "GET",
        "headers": _get_headers(),
        "body": "",
        "target_dir": "holdout",
    },
    {
        "case_id": "HOLD-PATH-001-B1",
        "family": "Path Traversal",
        "label": "benign",
        "endpoint": "/file?filename=company_guidelines.pdf",
        "method": "GET",
        "headers": _get_headers(),
        "body": "",
        "target_dir": "holdout",
    },
    {
        "case_id": "HOLD-SSRF-001",
        "family": "SSRF",
        "label": "malicious",
        "endpoint": "/fetch",
        "method": "POST",
        "headers": _json_headers(),
        "body": json.dumps({"url": "http://localhost:8080/metadata"}),
        "target_dir": "holdout",
    },
    {
        "case_id": "HOLD-SSRF-001-B1",
        "family": "SSRF",
        "label": "benign",
        "endpoint": "/fetch",
        "method": "POST",
        "headers": _json_headers(),
        "body": json.dumps({"url": "http://mock-internal:8080/public/favicon.ico"}),
        "target_dir": "holdout",
    },
]


def build_all_cases() -> list:
    cases = []

    # 1. SQLi
    for cid, user, pwd in SQLI_MALICIOUS:
        cases.append({
            "case_id": cid, "family": "SQL Injection", "label": "malicious",
            "endpoint": "/login", "method": "POST", "headers": _json_headers(),
            "body": json.dumps({"username": user, "password": pwd}),
            "target_dir": "malicious",
        })
    for cid, user, pwd, exp in SQLI_PAIRED_BENIGN:
        item = {
            "case_id": cid, "family": "SQL Injection", "label": "benign",
            "endpoint": "/login", "method": "POST", "headers": _json_headers(),
            "body": json.dumps({"username": user, "password": pwd}),
            "target_dir": "benign",
        }
        if exp is not None:
            item["expected_status"] = exp
        cases.append(item)
    for cid, user, pwd, exp in SQLI_EDGE:
        cases.append({
            "case_id": cid, "family": "SQL Injection", "label": "edge",
            "endpoint": "/login", "method": "POST", "headers": _json_headers(),
            "body": json.dumps({"username": user, "password": pwd}),
            "expected_status": exp,
            "target_dir": "benign",
        })

    # 2. XSS
    for cid, payload in XSS_MALICIOUS:
        encoded = urllib.parse.quote(payload, safe="/:=()")
        cases.append({
            "case_id": cid, "family": "Reflected XSS", "label": "malicious",
            "endpoint": f"/search?q={encoded}", "method": "GET", "headers": _get_headers(),
            "body": "", "target_dir": "malicious",
        })
    for cid, text in XSS_PAIRED_BENIGN:
        encoded = urllib.parse.quote_plus(text)
        cases.append({
            "case_id": cid, "family": "Reflected XSS", "label": "benign",
            "endpoint": f"/search?q={encoded}", "method": "GET", "headers": _get_headers(),
            "body": "", "target_dir": "benign",
        })
    for cid, text in XSS_EDGE:
        encoded = urllib.parse.quote_plus(text, safe="'")
        cases.append({
            "case_id": cid, "family": "Reflected XSS", "label": "edge",
            "endpoint": f"/search?q={encoded}", "method": "GET", "headers": _get_headers(),
            "body": "", "target_dir": "benign",
        })

    # 3. Path Traversal
    for cid, fname in PATH_MALICIOUS:
        cases.append({
            "case_id": cid, "family": "Path Traversal", "label": "malicious",
            "endpoint": f"/file?filename={fname}", "method": "GET", "headers": _get_headers(),
            "body": "", "target_dir": "malicious",
        })
    for cid, fname in PATH_PAIRED_BENIGN:
        cases.append({
            "case_id": cid, "family": "Path Traversal", "label": "benign",
            "endpoint": f"/file?filename={fname}", "method": "GET", "headers": _get_headers(),
            "body": "", "target_dir": "benign",
        })
    for cid, fname, exp in PATH_EDGE:
        item = {
            "case_id": cid, "family": "Path Traversal", "label": "edge",
            "endpoint": f"/file?filename={fname}", "method": "GET", "headers": _get_headers(),
            "body": "", "target_dir": "benign",
        }
        if exp is not None:
            item["expected_status"] = exp
        cases.append(item)

    # 4. SSRF
    for cid, url in SSRF_MALICIOUS:
        cases.append({
            "case_id": cid, "family": "SSRF", "label": "malicious",
            "endpoint": "/fetch", "method": "POST", "headers": _json_headers(),
            "body": json.dumps({"url": url}), "target_dir": "malicious",
        })
    for cid, url in SSRF_PAIRED_BENIGN:
        cases.append({
            "case_id": cid, "family": "SSRF", "label": "benign",
            "endpoint": "/fetch", "method": "POST", "headers": _json_headers(),
            "body": json.dumps({"url": url}), "target_dir": "benign",
        })
    for cid, url in SSRF_EDGE:
        cases.append({
            "case_id": cid, "family": "SSRF", "label": "edge",
            "endpoint": "/fetch", "method": "POST", "headers": _json_headers(),
            "body": json.dumps({"url": url}), "target_dir": "benign",
        })

    # 5. Holdout
    for h in HOLDOUT_CASES:
        cases.append(dict(h))

    return cases


def generate_cases():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cases_dir = os.path.join(base_dir, "cases")

    all_cases = build_all_cases()
    generated_counts = {"malicious": 0, "benign": 0, "holdout": 0}

    for item in all_cases:
        target_dir = item.pop("target_dir")
        target_path = os.path.join(cases_dir, target_dir, f"{item['case_id']}.json")
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(item, f, indent=2)
        generated_counts[target_dir] += 1

    print("=" * 60)
    print(f"Total Test Cases Generated: {len(all_cases)}")
    print(f"  - Main Corpus Malicious   : {generated_counts['malicious']} cases")
    print(f"  - Main Corpus Benign/Edge : {generated_counts['benign']} cases")
    print(f"  - Holdout Regression Suite: {generated_counts['holdout']} cases")
    print("=" * 60)


if __name__ == "__main__":
    generate_cases()
