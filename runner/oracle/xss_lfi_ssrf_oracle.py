#!/usr/bin/env python3
"""
Application Oracles for XSS, Path Traversal / LFI, and SSRF (Table 4.2)
Author: Kieu Dang Vuong
"""

import os
import json
import urllib.parse

from manager import docker_exec

MOCK_CONTAINER = os.getenv("MOCK_CONTAINER", "wb-mock")
MOCK_INTERNAL_URL = os.getenv("MOCK_INTERNAL_URL", "http://127.0.0.1:8080")


def xss_probe_for(case: dict) -> str:
    """Probe = explicit "probe" field if the case has one, else the decoded q parameter."""
    if case.get("probe"):
        return case["probe"]
    query = urllib.parse.urlparse(case.get("endpoint", "")).query
    return urllib.parse.parse_qs(query).get("q", [""])[0]


def check_xss_reflection(client_response: dict, probe: str) -> dict:
    """
    Checks if the raw probe is reflected unescaped in an HTML body.
    A probe without markup (e.g. "O'Reilly") cannot execute, so it is never an effect.
    """
    if not probe or not any(c in probe for c in "<>"):
        return {"backend_effect": False, "observation": "Probe contains no markup"}

    text = client_response.get("text", "")
    content_type = client_response.get("headers", {}).get("Content-Type", "")
    reflected = probe in text
    if reflected and "text/html" in content_type:
        return {"backend_effect": True, "observation": "Unescaped HTML reflection confirmed"}
    if reflected:
        return {"backend_effect": False, "observation": f"Reflected but Content-Type is {content_type or 'missing'}"}
    return {"backend_effect": False, "observation": "No reflection"}


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


def get_mock_logs(correlation_id: str = None) -> list:
    """Reads mock-internal access logs from inside its container (backend network is isolated)."""
    url = f"{MOCK_INTERNAL_URL}/logs"
    if correlation_id:
        url += f"?correlation_id={correlation_id}"
    rc, out, err = docker_exec(MOCK_CONTAINER, ["wget", "-qO-", url])
    if rc != 0:
        raise RuntimeError((err or out).strip() or f"wget exited {rc}")
    # The /logs request itself is logged as "anonymous"; keep only real traffic
    return [e for e in json.loads(out) if not e.get("path", "").startswith("/logs")]


def check_ssrf_mock_access(correlation_id: str) -> dict:
    """
    Queries mock-internal to verify if the sensitive /metadata path was requested.
    """
    try:
        logs = get_mock_logs(correlation_id)
    except Exception as e:
        return {"backend_effect": False, "observation": f"Could not query mock logs: {e}"}

    sensitive_hit = any(entry.get("path", "").startswith("/metadata") for entry in logs)
    return {
        "backend_effect": sensitive_hit,
        "observation": "Mock /metadata accessed" if sensitive_hit else "No sensitive mock access"
    }
