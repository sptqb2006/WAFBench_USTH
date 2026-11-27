#!/usr/bin/env python3
"""
Test Harness Request Manager: request replay, docker exec helpers, WAF mode control
and WAF evidence lookup by correlation ID.
Author: Kieu Dang Vuong
"""

import os
import re
import json
import time
import uuid
import hashlib
import subprocess
import shutil
import shlex

import requests

GATEWAY_CONTAINER = os.getenv("GATEWAY_CONTAINER", "wb-gateway")
APP_CONTAINER = os.getenv("APP_CONTAINER", "wb-app")
REMOTE_DOCKER_HOST = os.getenv("WAF_REMOTE_DOCKER_HOST", "webadmin@100.66.229.98")

# Host header sent to every target. A numeric IP Host triggers CRS 920350 on every request,
# so a name is used instead of the target address.
HOST_HEADER = os.getenv("TARGET_HOST_HEADER", "localhost")

# Headers that change on every replay and are left out of the request fingerprint
VOLATILE_HEADERS = {"x-request-id", "host"}

# Files that may hold SecRuleEngine depending on how the gateway image is configured
MODE_FILES = [
    "/etc/modsecurity.d/modsecurity-override.conf",
    "/etc/modsecurity.d/main.conf",
]

# Audit log source: "auto" reads the file if it exists, else the container stdout
AUDIT_SOURCE = os.getenv("WAF_AUDIT_SOURCE", "auto")
AUDIT_FILE = os.getenv("WAF_AUDIT_FILE", "/var/log/modsec/audit.log")

# 949110/959100 = CRS inbound/outbound anomaly threshold exceeded.
# Custom rule IDs differ between gateway branches, so they are configurable.
DETECTION_RULE_IDS = {"949110", "959100"} | {
    r.strip() for r in os.getenv("WAF_CUSTOM_RULE_IDS", "10001,200001,200010,1000001").split(",") if r.strip()
}

CANARY_ENDPOINT = "/search?q=%3Cscript%3Ealert(1)%3C/script%3E"


def _run_docker_cmd(cmd: list, timeout: float = 10.0) -> subprocess.CompletedProcess:
    """Runs docker locally or transparently over SSH if docker is not in local PATH."""
    if shutil.which("docker"):
        return subprocess.run(cmd, capture_output=True, timeout=timeout)
    ssh_cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", REMOTE_DOCKER_HOST, shlex.join(cmd)]
    return subprocess.run(ssh_cmd, capture_output=True, timeout=timeout)


def docker_exec(container: str, args: list, timeout: float = 10.0, user: str = None) -> tuple:
    """Runs a command inside a container without a TTY. Returns (returncode, stdout, stderr)."""
    cmd = ["docker", "exec"]
    if user:
        cmd += ["-u", user]
    cmd += [container] + args
    try:
        p = _run_docker_cmd(cmd, timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    except Exception as e:
        return -1, "", str(e)


def docker_logs(container: str, tail: int = 500, timeout: float = 10.0) -> str:
    try:
        p = _run_docker_cmd(["docker", "logs", "--tail", str(tail), container], timeout=timeout)
        return p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace")
    except Exception:
        return ""


def request_fingerprint(case_data: dict) -> str:
    """SHA256 over method, endpoint, static headers and body: equal across states and repetitions."""
    headers = sorted(
        (k.lower(), v) for k, v in case_data.get("headers", {}).items() if k.lower() not in VOLATILE_HEADERS
    )
    parts = [case_data.get("method", "GET").upper(), case_data.get("endpoint", "")]
    parts += [f"{k}:{v}" for k, v in headers]
    parts.append(case_data.get("body", "") or "")
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


class RequestManager:
    def __init__(self, timeout: float = 5.0):
        self.session = requests.Session()
        self.timeout = timeout

    def send_request(self, target_base_url: str, case_data: dict, correlation_id: str = None) -> dict:
        if not correlation_id:
            correlation_id = str(uuid.uuid4())

        endpoint = case_data.get("endpoint", "")
        method = case_data.get("method", "GET").upper()
        raw_body = case_data.get("body", "")

        headers = {}
        for k, v in case_data.get("headers", {}).items():
            headers[k] = v.replace("{correlation_id}", correlation_id).replace("{host}", HOST_HEADER)
        headers["X-Request-ID"] = correlation_id
        headers["Host"] = HOST_HEADER

        # No state may leak between replays (e.g. a session cookie from a SQLi login)
        self.session.cookies.clear()

        request_sha256 = request_fingerprint(case_data)
        try:
            t0 = time.perf_counter()
            resp = self.session.request(
                method=method,
                url=f"{target_base_url}{endpoint}",
                headers=headers,
                data=raw_body.encode("utf-8") if raw_body else None,
                timeout=self.timeout,
                allow_redirects=False,
            )
            latency_ms = (time.perf_counter() - t0) * 1000
            return {
                "success": True,
                "correlation_id": correlation_id,
                "request_sha256": request_sha256,
                "status_code": resp.status_code,
                "headers": resp.headers,
                "text": resp.text,
                "latency_ms": latency_ms,
                "error": None,
            }
        except Exception as e:
            return {
                "success": False,
                "correlation_id": correlation_id,
                "request_sha256": request_sha256,
                "status_code": None,
                "headers": {},
                "text": "",
                "latency_ms": None,
                "error": str(e),
            }


# ---------------------------------------------------------------------------
# WAF mode control
# ---------------------------------------------------------------------------

def set_waf_mode(engine: str) -> tuple:
    """Sets SecRuleEngine (DetectionOnly | On) inside the gateway and reloads nginx."""
    script = (
        f"for f in {' '.join(MODE_FILES)}; do "
        f"[ -f \"$f\" ] && sed -i 's/^SecRuleEngine .*/SecRuleEngine {engine}/' \"$f\"; "
        "done; nginx -s reload"
    )
    rc, out, err = docker_exec(GATEWAY_CONTAINER, ["sh", "-c", script], user="root")
    if rc != 0:
        return False, (err or out).strip()
    return True, ""


def wait_gateway_ready(gateway_url: str, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{gateway_url}/health", headers={"Host": HOST_HEADER}, timeout=2.0)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.3)
    return False


def mode_canary(gateway_url: str, state: str) -> tuple:
    """
    Sends a known XSS request through the gateway.
    DetectionOnly: must pass (200) and be detected in the audit log. Blocking: must get 403.
    """
    cid = str(uuid.uuid4())
    try:
        r = requests.get(
            f"{gateway_url}{CANARY_ENDPOINT}",
            headers={"X-Request-ID": cid, "Host": HOST_HEADER},
            timeout=5.0,
        )
        status = r.status_code
    except Exception as e:
        return False, f"canary request failed: {e}"

    expected = 403 if state == "Blocking" else 200
    if status != expected:
        return False, f"canary got HTTP {status}, expected {expected}"

    ev = find_waf_evidence(cid)
    if not ev["detected"]:
        return False, f"canary not detected in audit log (source: {ev['source']})"
    return True, f"canary HTTP {status}, rules {','.join(ev['matched_rule_ids'])}"


# ---------------------------------------------------------------------------
# WAF evidence
# ---------------------------------------------------------------------------

def _audit_file_exists() -> bool:
    rc, _, _ = docker_exec(GATEWAY_CONTAINER, ["test", "-s", AUDIT_FILE])
    return rc == 0


def resolve_audit_source() -> str:
    if AUDIT_SOURCE in ("file", "stdout"):
        return AUDIT_SOURCE
    return "file" if _audit_file_exists() else "stdout"


def _audit_lines(correlation_id: str, source: str) -> list:
    if source == "file":
        _, out, _ = docker_exec(GATEWAY_CONTAINER, ["grep", "-F", correlation_id, AUDIT_FILE])
        lines = out.splitlines()
    else:
        lines = [l for l in docker_logs(GATEWAY_CONTAINER).splitlines() if correlation_id in l]
    return [l for l in lines if l.lstrip().startswith("{")]


def _parse_transaction(line: str, correlation_id: str):
    try:
        tx = json.loads(line).get("transaction", {})
    except ValueError:
        return None
    headers = {k.lower(): v for k, v in tx.get("request", {}).get("headers", {}).items()}
    if headers.get("x-request-id") != correlation_id:
        return None
    return tx


def find_waf_evidence(correlation_id: str, timeout: float = 2.0, source: str = None) -> dict:
    """
    Looks up the ModSecurity audit record for a correlation ID.
    No record is normal for a request that matched no rule (SecAuditEngine RelevantOnly).
    """
    source = source or resolve_audit_source()
    deadline = time.time() + timeout
    tx = None
    while True:
        for line in _audit_lines(correlation_id, source):
            tx = _parse_transaction(line, correlation_id)
            if tx:
                break
        if tx or time.time() >= deadline:
            break
        time.sleep(0.25)

    if not tx:
        return {"found": False, "detected": False, "matched_rule_ids": [], "anomaly_score": None,
                "waf_http_code": None, "source": source}

    rule_ids, score = [], None
    for m in tx.get("messages", []):
        rid = str(m.get("details", {}).get("ruleId", ""))
        if rid and rid not in rule_ids:
            rule_ids.append(rid)
        hit = re.search(r"Total Score: (\d+)", m.get("details", {}).get("data", "") + m.get("message", ""))
        if hit:
            score = int(hit.group(1))

    return {
        "found": True,
        "detected": any(r in DETECTION_RULE_IDS for r in rule_ids),
        "matched_rule_ids": rule_ids,
        "anomaly_score": score,
        "waf_http_code": tx.get("response", {}).get("http_code"),
        "source": source,
    }


def seen_by_app(correlation_id: str, timeout: float = 2.0) -> bool:
    """True if the vulnerable app logged a request with this correlation ID."""
    deadline = time.time() + timeout
    while True:
        for line in docker_logs(APP_CONTAINER, tail=300).splitlines():
            if correlation_id in line and line.lstrip().startswith("{"):
                try:
                    if json.loads(line).get("correlation_id") == correlation_id:
                        return True
                except ValueError:
                    pass
        if time.time() >= deadline:
            return False
        time.sleep(0.25)
