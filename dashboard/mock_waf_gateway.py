#!/usr/bin/env python3
"""
WAFBench Local Mock Gateway & Telemetry Emulator (:8080)
Emulates Nginx 1.26 + ModSecurity v3 + OWASP CRS v4.0.0
for local testing when Docker stack is not running.
"""

import os
import sys
import json
import time
import uuid
import re
import hashlib
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import urllib.request

PORT = 8080
EVENTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_events.json")

# Core CRS Detection Patterns
SQLI_PATTERN = re.compile(
    r"(\b(UNION(\s+ALL)?|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|BENCHMARK|SLEEP)\b)|('.*--)|(--\s*$)|(\bOR\b\s+['\d\w]+=['\d\w]+)|(\bAND\b\s+['\d\w]+=['\d\w]+)|(/\*.*?\*/)",
    re.IGNORECASE
)

XSS_PATTERN = re.compile(
    r"(<script.*?>.*?</script>)|(<.*?on\w+\s*=)|(javascript:)|(<svg.*?>)|(<img.*?src=.*?onerror=)|(alert\(.*?\))|(document\.cookie)",
    re.IGNORECASE
)

TRAVERSAL_PATTERN = re.compile(
    r"(\.\./|\.\.\\|\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e/|\.\.\.\.//|etc/passwd|windows/win\.ini)",
    re.IGNORECASE
)

SSRF_PATTERN = re.compile(
    r"(127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.|mock-internal|metadata|10\.\d+\.\d+\.\d+|file://|gopher://|dict://)",
    re.IGNORECASE
)


def record_telemetry(event):
    """Appends evaluated event into sample_events.json for UI reflection."""
    try:
        events = []
        if os.path.exists(EVENTS_FILE):
            with open(EVENTS_FILE, "r", encoding="utf-8") as f:
                events = json.load(f)
        event["id"] = len(events) + 1
        events.insert(0, event)  # Insert at front for latest display
        # Keep recent 200 events
        events = events[:200]
        with open(EVENTS_FILE, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2)
    except Exception as e:
        print(f"[ERROR] Failed to save telemetry: {e}", file=sys.stderr)


class MockWAFHandler(BaseHTTPRequestHandler):
    server_version = "nginx/1.26.1 (ModSecurity-v3/OWASP-CRS-v4.0.0)"
    sys_version = ""

    def log_message(self, format, *args):
        # Single-line structured log to stdout
        corr_id = self.headers.get("X-Request-ID", "N/A")
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [{corr_id}] {self.command} {self.path} - {format % args}")

    def _read_body(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            return self.rfile.read(content_length).decode("utf-8", errors="replace")
        return ""

    def _evaluate_security(self, endpoint, method, query, body):
        """
        Simulates ModSecurity v3 Phase 1 & Phase 2 Anomaly Scoring.
        Returns: (blocked, rule_id, rule_name, score, family_id, variable, snippet)
        """
        combined = f"{query} {body}"
        
        # 1. SSRF Check
        if endpoint == "/fetch" or "url=" in query or "url" in body:
            m = SSRF_PATTERN.search(combined)
            if m:
                return (True, 1000001, "Custom SSRF Mitigation - Restricted loopback and metadata access", 5, "SSRF", "ARGS:url", m.group(0))

        # 2. SQL Injection Check
        if endpoint == "/login" or SQLI_PATTERN.search(combined):
            m = SQLI_PATTERN.search(combined)
            if m:
                return (True, 942100, "SQL Injection Attack Detected via libinjection / regex", 10, "SQL Injection", "ARGS:username", m.group(0))

        # 3. Path Traversal Check
        if endpoint == "/file" or TRAVERSAL_PATTERN.search(combined):
            m = TRAVERSAL_PATTERN.search(combined)
            if m:
                return (True, 930100, "Path Traversal Attack (/../)", 10, "Path Traversal", "ARGS:filename", m.group(0))

        # 4. Reflected XSS Check
        if endpoint == "/search" or XSS_PATTERN.search(combined):
            m = XSS_PATTERN.search(combined)
            if m:
                return (True, 941100, "XSS Filter - Category 1: Script Tag / Event Handler Vector", 10, "Reflected XSS", "ARGS:q", m.group(0))

        # Benign / Clean
        family_map = {
            "/login": "SQL Injection",
            "/search": "Reflected XSS",
            "/file": "Path Traversal",
            "/fetch": "SSRF"
        }
        return (False, None, "Clean Request", 0, family_map.get(endpoint, "Generic"), None, None)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Request-ID")
        self.end_headers()

    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        self._handle_request("POST")

    def _handle_request(self, method):
        host_header = self.headers.get("Host", "").lower()
        parsed_url = urllib.parse.urlparse(self.path)
        endpoint = parsed_url.path
        query = parsed_url.query
        body = self._read_body()

        corr_id = self.headers.get("X-Request-ID") or str(uuid.uuid4())
        raw_payload = body if method == "POST" else query
        payload_sha256 = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()

        # Route Subdomain: dashboard.wafbench.local -> Streamlit :8501
        if "dashboard" in host_header:
            try:
                target_url = f"http://127.0.0.1:8501{self.path}"
                req_headers = {k: v for k, v in self.headers.items() if k.lower() not in ['host', 'content-length']}
                req = urllib.request.Request(target_url, data=body.encode() if body else None, headers=req_headers, method=method)
                with urllib.request.urlopen(req, timeout=5) as proxy_resp:
                    self.send_response(proxy_resp.status)
                    for k, v in proxy_resp.headers.items():
                        if k.lower() not in ['transfer-encoding', 'content-encoding', 'connection']:
                            self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(proxy_resp.read())
                    return
            except Exception as e:
                self.send_response(502)
                self.end_headers()
                self.wfile.write(f"Bad Gateway to Dashboard: {e}".encode())
                return

        # Security Constraint: Forbid /health/reset on Gateway
        if endpoint == "/health/reset":
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Forbidden: Reset is only allowed via direct loopback"}')
            return

        # Health endpoint
        if endpoint == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Request-ID", corr_id)
            self.end_headers()
            self.wfile.write(json.dumps({"status": "UP", "service": "waf-gateway-emulator", "crs": "v4.0.0"}).encode())
            return

        # Security Evaluation
        blocked, rule_id, rule_name, score, family_id, variable, snippet = self._evaluate_security(
            endpoint, method, query, body
        )

        txn_id = f"{int(time.time()*1000)}.{os.getpid()}"

        if blocked:
            # WAF BLOCKED (HTTP 403 Forbidden)
            self.send_response(403)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("X-Request-ID", corr_id)
            self.send_header("X-WAF-Action", "BLOCK")
            self.send_header("X-WAF-Rule-ID", str(rule_id))
            self.send_header("X-WAF-Score", str(score))
            self.send_header("X-WAF-TxID", txn_id)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            html_body = f"""<!DOCTYPE html>
<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.26.1 (ModSecurity v3.0.12 / OWASP CRS v4.0.0)</center>
<!-- WAF Alert: Rule {rule_id} triggered ({rule_name}). Inbound Anomaly Score: {score} >= 5. Action: BLOCK -->
</body>
</html>"""
            self.wfile.write(html_body.encode())

            # Record Telemetry
            telemetry_event = {
                "correlation_id": corr_id,
                "run_id": "run_live_local",
                "batch_id": f"batch_{datetime.now().strftime('%Y%m%d')}",
                "case_id": f"LIVE-{family_id[:4].upper()}-001",
                "family_id": family_id,
                "label": "malicious",
                "state": "Blocking",
                "repetition": 1,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "client_ip": self.client_address[0],
                "method": method,
                "endpoint": endpoint,
                "client_status": 403,
                "request_sha256": payload_sha256,
                "response_body_snippet": html_body[:100],
                "waf_txn_id": txn_id,
                "matched_rule_ids": [rule_id, 949110],
                "root_rule_id": rule_id,
                "root_rule_name": rule_name,
                "inbound_score": score,
                "disruptive_action": "block",
                "interrupt_phase": 2,
                "waf_payload_snippet": snippet or raw_payload[:40],
                "waf_matched_variable": variable or "REQUEST_BODY",
                "raw_log_ref": f"sha256:{payload_sha256}",
                "app_received": False,
                "app_log_ref": None,
                "oracle_observation": "Threat neutralized at WAF perimeter; 0 backend bytes executed.",
                "detected": True,
                "backend_effect": False,
                "validity": "VALID",
                "invalid_reason": None,
                "verdict": "PASS",
                "metric_cell": "TP_B"
            }
            record_telemetry(telemetry_event)

        else:
            # WAF ALLOWED (HTTP 200 OK)
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("X-Request-ID", corr_id)
            self.send_header("X-WAF-Action", "ALLOW")
            self.send_header("X-WAF-Score", "0")
            self.send_header("X-WAF-TxID", txn_id)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            # Mock backend response
            if endpoint == "/login":
                resp_data = {"status": "success", "authenticated": True, "user": "guest", "msg": "Login verified"}
            elif endpoint == "/search":
                resp_data = {"query": query or body, "results": ["Document 1", "Product Specifications"]}
            elif endpoint == "/file":
                resp_data = {"status": "ok", "file": "sample_document.pdf", "size_bytes": 1024}
            elif endpoint == "/fetch":
                resp_data = {"status": "ok", "url": "https://example.com/logo.png", "bytes_received": 2048}
            else:
                resp_data = {"status": "ok", "endpoint": endpoint, "message": "Request processed successfully"}

            self.wfile.write(json.dumps(resp_data, indent=2).encode())

            # Record Telemetry
            telemetry_event = {
                "correlation_id": corr_id,
                "run_id": "run_live_local",
                "batch_id": f"batch_{datetime.now().strftime('%Y%m%d')}",
                "case_id": f"LIVE-BENIGN-001",
                "family_id": family_id,
                "label": "benign",
                "state": "Blocking",
                "repetition": 1,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "client_ip": self.client_address[0],
                "method": method,
                "endpoint": endpoint,
                "client_status": 200,
                "request_sha256": payload_sha256,
                "response_body_snippet": json.dumps(resp_data)[:100],
                "waf_txn_id": txn_id,
                "matched_rule_ids": [],
                "root_rule_id": None,
                "root_rule_name": "Clean Request",
                "inbound_score": 0,
                "disruptive_action": "none",
                "interrupt_phase": None,
                "waf_payload_snippet": None,
                "waf_matched_variable": None,
                "raw_log_ref": f"sha256:{payload_sha256}",
                "app_received": True,
                "app_log_ref": f"app_{corr_id[:8]}",
                "oracle_observation": "Legitimate request delivered to backend application without interference.",
                "detected": False,
                "backend_effect": True,
                "validity": "VALID",
                "invalid_reason": None,
                "verdict": "PASS",
                "metric_cell": "TN_B"
            }
            record_telemetry(telemetry_event)


def run_server():
    server = HTTPServer(("0.0.0.0", PORT), MockWAFHandler)
    print(f"[*] WAFBench Mock Gateway & CRS Emulator active on http://0.0.0.0:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down emulator.")
        server.server_close()


if __name__ == "__main__":
    run_server()
