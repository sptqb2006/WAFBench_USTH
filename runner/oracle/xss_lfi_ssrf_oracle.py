#!/usr/bin/env python3
"""
Application Oracles for XSS, Path Traversal / LFI, and SSRF (Table 4.2)
Author: Kieu Dang Vuong
"""

import json
from urllib.parse import urlparse, parse_qs, unquote_plus
import requests


def extract_xss_probe(case_data: dict) -> str:
    """
    Extracts and URL-decodes the XSS probe dynamically from a test case JSON object.
    Checks explicit 'probe'/'payload' keys first, then query parameters in 'endpoint', then 'body'.
    """
    for key in ("probe", "payload"):
        if case_data.get(key):
            return str(case_data[key])

    endpoint = case_data.get("endpoint", "")
    parsed = urlparse(endpoint)
    if parsed.query:
        params = parse_qs(parsed.query, keep_blank_values=True)
        for values in params.values():
            if values and values[0]:
                return values[0]

    body = case_data.get("body", "")
    if body:
        try:
            body_json = json.loads(body) if isinstance(body, str) else body
            if isinstance(body_json, dict):
                for val in body_json.values():
                    if val:
                        return str(val)
        except Exception:
            return unquote_plus(str(body))

    return ""


def check_xss_reflection(client_response: dict, probe: str) -> dict:
    """
    Checks if the raw probe is reflected unescaped in the HTML body.
    """
    if not probe:
        return {
            "backend_effect": False,
            "observation": "No XSS probe extracted from test case"
        }

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
    """
    try:
        resp = requests.get(f"{mock_url}/logs?correlation_id={correlation_id}", timeout=2.0)
        logs = resp.json() if resp.status_code == 200 else []
        sensitive_hit = any("/metadata" in entry.get("path", "") for entry in logs)
        return {
            "backend_effect": sensitive_hit,
            "observation": "Mock /metadata accessed" if sensitive_hit else "No sensitive mock access"
        }
    except Exception as e:
        return {
            "backend_effect": False,
            "observation": f"Could not query mock logs: {e}"
        }
