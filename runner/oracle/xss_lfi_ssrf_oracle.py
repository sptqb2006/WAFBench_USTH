#!/usr/bin/env python3
"""
Application Oracles for XSS, Path Traversal / LFI, and SSRF (Table 4.2)
Author: Kieu Dang Vuong
"""

import json
import subprocess
import requests

def check_xss_reflection(client_response: dict, probe: str) -> dict:
    """
    Checks if the raw probe is reflected unescaped in the HTML body.
    """
    text = client_response.get("text", "")
    content_type = client_response.get("headers", {}).get("Content-Type", "")
    is_html = "text/html" in content_type

    reflected = probe in text
    return {
        "backend_effect": reflected and is_html,
        "observation": "Unescaped HTML reflection confirmed" if reflected else "No reflection"
    }

def check_lfi_file_disclosure(client_response: dict) -> dict:
    """
    Checks if container-local /etc/passwd indicators are present.
    """
    text = client_response.get("text", "")
    has_passwd = "root:x:0:0:" in text or "bin:x:" in text
    return {
        "backend_effect": has_passwd,
        "observation": "Container /etc/passwd content disclosed" if has_passwd else "No disclosure"
    }

def check_ssrf_mock_access(mock_url: str, correlation_id: str) -> dict:
    """
    Queries mock-internal to verify if the sensitive /metadata path was requested.
    Supports direct HTTP query with fallback to docker exec for isolated networks.
    """
    logs = []
    try:
        resp = requests.get(f"{mock_url}/logs?correlation_id={correlation_id}", timeout=2.0)
        if resp.status_code == 200:
            logs = resp.json()
    except Exception:
        # Fallback to docker exec if mock-internal is isolated on backend-net
        try:
            cmd = ["docker", "exec", "wb-mock", "wget", "-qO-", f"http://127.0.0.1:8080/logs?correlation_id={correlation_id}"]
            out = subprocess.check_output(cmd, timeout=3).decode("utf-8")
            logs = json.loads(out)
        except Exception as e:
            return {
                "backend_effect": False,
                "observation": f"Could not query mock logs: {e}"
            }

    sensitive_hit = any("/metadata" in entry.get("path", "") for entry in logs)
    return {
        "backend_effect": sensitive_hit,
        "observation": "Mock /metadata accessed" if sensitive_hit else "No sensitive mock access"
    }
