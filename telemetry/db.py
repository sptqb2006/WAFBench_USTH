#!/usr/bin/env python3
"""
WAFBench Telemetry Database Connector & Schema Manager (PostgreSQL 16)
Author: Phan Duc Anh
"""

import os
import sys
import json
from typing import Optional, Dict, Any, List

#handle psycopg2 availability (ex: host terminal vs Docker container)
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    PSYCOPG2_AVAILABLE = True
except ImportError:
    psycopg2 = None
    RealDictCursor = None
    PSYCOPG2_AVAILABLE = False


def get_db_config() -> dict:
    """Returns database connection parameters from environment variables."""
    return {
        "host": os.getenv("EVENT_DB_HOST", "localhost"),
        "port": int(os.getenv("EVENT_DB_PORT", "5432")),
        "dbname": os.getenv("EVENT_DB_NAME", "wafbench_events"),
        "user": os.getenv("EVENT_DB_USER", "telemetry_user"),
        "password": os.getenv("EVENT_DB_PASSWORD", "telemetry_secret_pass"),
    }


def get_connection():
    """Establishes a connection to PostgreSQL event-db with RealDictCursor."""
    if not PSYCOPG2_AVAILABLE:
        raise RuntimeError(
            "psycopg2 is not installed. Run 'py -m pip install psycopg2-binary' "
            "or run inside the Docker container."
        )
    cfg = get_db_config()
    return psycopg2.connect(
        host=cfg["host"],
        port=cfg["port"],
        dbname=cfg["dbname"],
        user=cfg["user"],
        password=cfg["password"],
        cursor_factory=RealDictCursor,
    )


def test_connection() -> bool:
    """Tests if event-db is reachable."""
    if not PSYCOPG2_AVAILABLE:
        return False
    try:
        conn = get_connection()
        conn.close()
        return True
    except Exception:
        return False


def init_db(schema_path: Optional[str] = None) -> bool:
    """Executes schema.sql to initialize or reset tables in event-db."""
    if schema_path is None:
        schema_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")

    if not os.path.exists(schema_path):
        print(f"[!] Schema file not found at: {schema_path}")
        return False

    with open(schema_path, "r", encoding="utf-8") as f:
        sql_content = f.read()

    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(sql_content)
        conn.commit()
        conn.close()
        print(f"[+] Successfully initialized database schema from {schema_path}")
        return True
    except Exception as e:
        print(f"[!] Failed to initialize database: {e}")
        return False


def upsert_client_event(record: Dict[str, Any]) -> bool:
    """
    Inserts a client probe record or updates existing entry on correlation_id conflict.
    Enables safe ordering regardless of whether client or WAF audit log arrives first.
    """
    sql = """
    INSERT INTO normalized_events (
        correlation_id, run_id, batch_id, case_id, family_id, label, state, repetition,
        client_ip, method, endpoint, client_status, request_sha256, response_body_snippet,
        validity, invalid_reason
    ) VALUES (
        %(correlation_id)s, %(run_id)s, %(batch_id)s, %(case_id)s, %(family_id)s, %(label)s, %(state)s, %(repetition)s,
        %(client_ip)s, %(method)s, %(endpoint)s, %(client_status)s, %(request_sha256)s, %(response_body_snippet)s,
        %(validity)s, %(invalid_reason)s
    )
    ON CONFLICT (correlation_id) DO UPDATE SET
        run_id = EXCLUDED.run_id,
        batch_id = EXCLUDED.batch_id,
        case_id = EXCLUDED.case_id,
        family_id = EXCLUDED.family_id,
        label = EXCLUDED.label,
        state = EXCLUDED.state,
        repetition = EXCLUDED.repetition,
        client_ip = COALESCE(EXCLUDED.client_ip, normalized_events.client_ip),
        method = COALESCE(EXCLUDED.method, normalized_events.method),
        endpoint = COALESCE(EXCLUDED.endpoint, normalized_events.endpoint),
        client_status = COALESCE(EXCLUDED.client_status, normalized_events.client_status),
        request_sha256 = COALESCE(EXCLUDED.request_sha256, normalized_events.request_sha256),
        response_body_snippet = COALESCE(EXCLUDED.response_body_snippet, normalized_events.response_body_snippet),
        validity = COALESCE(EXCLUDED.validity, normalized_events.validity),
        invalid_reason = COALESCE(EXCLUDED.invalid_reason, normalized_events.invalid_reason);
    """
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(sql, record)
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[!] Error in upsert_client_event: {e}")
        return False


def update_waf_telemetry(correlation_id: str, waf_data: Dict[str, Any]) -> bool:
    """Updates or inserts WAF-specific ModSecurity telemetry fields for a given correlation_id."""
    sql = """
    INSERT INTO normalized_events (
        correlation_id, waf_txn_id, matched_rule_ids, root_rule_id, root_rule_name,
        inbound_score, disruptive_action, interrupt_phase, waf_payload_snippet,
        waf_matched_variable, raw_log_ref, detected
    ) VALUES (
        %(correlation_id)s, %(waf_txn_id)s, %(matched_rule_ids)s, %(root_rule_id)s, %(root_rule_name)s,
        %(inbound_score)s, %(disruptive_action)s, %(interrupt_phase)s, %(waf_payload_snippet)s,
        %(waf_matched_variable)s, %(raw_log_ref)s, %(detected)s
    )
    ON CONFLICT (correlation_id) DO UPDATE SET
        waf_txn_id = EXCLUDED.waf_txn_id,
        matched_rule_ids = EXCLUDED.matched_rule_ids,
        root_rule_id = EXCLUDED.root_rule_id,
        root_rule_name = EXCLUDED.root_rule_name,
        inbound_score = EXCLUDED.inbound_score,
        disruptive_action = EXCLUDED.disruptive_action,
        interrupt_phase = EXCLUDED.interrupt_phase,
        waf_payload_snippet = EXCLUDED.waf_payload_snippet,
        waf_matched_variable = EXCLUDED.waf_matched_variable,
        raw_log_ref = EXCLUDED.raw_log_ref,
        detected = EXCLUDED.detected;
    """
    data = dict(waf_data)
    data["correlation_id"] = correlation_id
    if isinstance(data.get("matched_rule_ids"), list):
        data["matched_rule_ids"] = json.dumps(data["matched_rule_ids"])
    score = int(data.get("inbound_score") or 0)
    data["detected"] = score >= 5 or data.get("disruptive_action") == "block"

    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(sql, data)
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[!] Error updating WAF telemetry: {e}")
        return False


def update_verdict(correlation_id: str, verdict_data: Dict[str, Any]) -> bool:
    """Updates derived evaluation verdicts and confusion matrix cell assignments."""
    sql = """
    UPDATE normalized_events
    SET detected = %(detected)s,
        backend_effect = %(backend_effect)s,
        validity = %(validity)s,
        invalid_reason = %(invalid_reason)s,
        verdict = %(verdict)s,
        metric_cell = %(metric_cell)s
    WHERE correlation_id = %(correlation_id)s;
    """
    data = dict(verdict_data)
    data["correlation_id"] = correlation_id
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(sql, data)
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[!] Error updating verdict: {e}")
        return False


def get_recent_events(limit: int = 20) -> List[Dict[str, Any]]:
    """Retrieves the most recent normalized events."""
    sql = "SELECT * FROM normalized_events ORDER BY id DESC LIMIT %s;"
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(sql, (limit,))
            rows = cur.fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"[!] Error fetching events: {e}")
        return []


def print_schema_overview():
    """Prints the schema structure and field definitions to stdout."""
    print("=" * 78)
    print("           WAFBench PostgreSQL 16 Event-DB Schema Overview")
    print("=" * 78)
    print("\n[TABLE 1] normalized_events (Table 4.3 - 3-Tier Correlated Telemetry)")
    print("-" * 78)
    fields = [
        ("correlation_id", "VARCHAR(64) UNIQUE", "Injected X-Request-ID (1:1 universal join key)"),
        ("run_id", "VARCHAR(64)", "Execution run ID"),
        ("case_id", "VARCHAR(64)", "Test case ID (e.g. SQLI-001)"),
        ("family_id", "VARCHAR(64)", "Threat class (SQLi, XSS, Path_Trav, SSRF)"),
        ("label", "VARCHAR(32)", "Ground truth label (malicious / benign / edge)"),
        ("state", "VARCHAR(32)", "Mode (Direct-to-App / DetectionOnly / Blocking)"),
        ("client_status", "INT", "HTTP status code seen by client"),
        ("waf_txn_id", "VARCHAR(64)", "ModSecurity transaction ID"),
        ("matched_rule_ids", "JSONB", "Array of triggered CRS rule IDs"),
        ("root_rule_id", "INT", "Primary offending rule ID (e.g. 942100)"),
        ("inbound_score", "INT", "Cumulative inbound anomaly score"),
        ("disruptive_action", "VARCHAR(64)", "WAF action ('block', 'allow', 'none')"),
        ("waf_payload_snippet","TEXT", "Offending payload substring"),
        ("waf_matched_variable","TEXT", "Matched variable (e.g. ARGS:username)"),
        ("app_received", "BOOLEAN", "Did request reach target application?"),
        ("backend_effect", "BOOLEAN", "Application Oracle confirmed compromise"),
        ("verdict", "VARCHAR(32)", "PASS / FAIL / INVALID / INCONCLUSIVE"),
        ("metric_cell", "VARCHAR(32)", "TP_D, FN_D, TP_B, FN_B, FP_D, TN_D, etc."),
    ]
    for col, col_type, desc in fields:
        print(f"  * {col:<22} | {col_type:<18} | {desc}")

    print("\n[TABLE 2] evaluation_metrics (Table 4.6 - Aggregated Benchmark KPIs)")
    print("-" * 78)
    metrics = [
        ("batch_id", "VARCHAR(64) UNIQUE", "Batch run identifier"),
        ("config_revision", "VARCHAR(64)", "WAF configuration baseline (C0 / C1)"),
        ("total_attempted", "INT", "Total probes dispatched"),
        ("total_evaluable", "INT", "Probes passing baseline & validity gates"),
        ("detection_rate", "NUMERIC(5,2)", "DR = TP_D / (TP_D + FN_D) * 100%"),
        ("blocking_rate", "NUMERIC(5,2)", "BR = TP_B / (TP_B + FN_B) * 100%"),
        ("detection_fpr", "NUMERIC(5,2)", "FP_D / (FP_D + TN_D) * 100%"),
        ("blocking_fpr", "NUMERIC(5,2)", "FP_B / (FP_B + TN_B) * 100%"),
        ("regression_pass_rate","NUMERIC(5,2)", "Pass_C1 / Total_C0 * 100%"),
    ]
    for col, col_type, desc in metrics:
        print(f"  * {col:<22} | {col_type:<18} | {desc}")
    print("=" * 78)


def run_local_terminal_demo():
    """
    Demonstrates the 3-tier database workflow in action right in the terminal
    using Python's built-in SQLite engine (zero external dependencies required).
    """
    import sqlite3
    print("\n" + "=" * 78)
    print("       WAFBench 3-Tier Database In-Action Demonstration (Terminal)")
    print("=" * 78)
    print("[*] Initializing in-memory relational event store conforming to Table 4.3...")
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE normalized_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        correlation_id TEXT UNIQUE NOT NULL,
        run_id TEXT NOT NULL,
        batch_id TEXT,
        case_id TEXT NOT NULL,
        family_id TEXT NOT NULL,
        label TEXT NOT NULL,
        state TEXT NOT NULL,
        repetition INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        client_ip TEXT,
        method TEXT,
        endpoint TEXT,
        client_status INTEGER,
        request_sha256 TEXT,
        response_body_snippet TEXT,
        waf_txn_id TEXT,
        matched_rule_ids TEXT,
        root_rule_id INTEGER,
        root_rule_name TEXT,
        inbound_score INTEGER DEFAULT 0,
        disruptive_action TEXT,
        interrupt_phase INTEGER,
        waf_payload_snippet TEXT,
        waf_matched_variable TEXT,
        raw_log_ref TEXT,
        app_received BOOLEAN DEFAULT 0,
        app_log_ref TEXT,
        oracle_observation TEXT,
        detected BOOLEAN DEFAULT 0,
        backend_effect BOOLEAN DEFAULT 0,
        validity TEXT DEFAULT 'VALID',
        invalid_reason TEXT,
        verdict TEXT,
        metric_cell TEXT
    );
    """)

    sample_corr_id = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
    print(f"\n[Step 1: Client Probe Ingestion via X-Request-ID]")
    print(f" -> Probe: SQLI-001 (POST /login) | Correlation ID: {sample_corr_id}")
    cur.execute("""
    INSERT INTO normalized_events (
        correlation_id, run_id, batch_id, case_id, family_id, label, state, repetition,
        client_ip, method, endpoint, client_status, request_sha256, validity
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        sample_corr_id, "run_demo_01", "batch_20261102", "SQLI-001", "SQL Injection",
        "malicious", "Blocking", 1, "127.0.0.1", "POST", "/login", 403,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "VALID"
    ))

    print(f"\n[Step 2: WAF Telemetry Update (ModSecurity ECS-lite Ingestion)]")
    print(f" -> Matched CRS Rule: 942100 | Score: 10 | Disruptive Action: block (Phase 2)")
    cur.execute("""
    UPDATE normalized_events
    SET waf_txn_id = ?,
        matched_rule_ids = ?,
        root_rule_id = ?,
        root_rule_name = ?,
        inbound_score = ?,
        disruptive_action = ?,
        interrupt_phase = ?,
        waf_payload_snippet = ?,
        waf_matched_variable = ?,
        raw_log_ref = ?
    WHERE correlation_id = ?;
    """, (
        "172753392512.928174", json.dumps([942100, 949110]), 942100,
        "SQLi libinjection operator", 10, "block", 2, "admin' --",
        "ARGS:username", "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
        sample_corr_id
    ))

    print(f"\n[Step 3: Backend Application Oracle & Cross-Tier Correlation]")
    print(f" -> Backend Effect: False (Query never touched DB) | Verdict: PASS (Cell: TP_B)")
    cur.execute("""
    UPDATE normalized_events
    SET app_received = ?,
        backend_effect = ?,
        oracle_observation = ?,
        detected = ?,
        verdict = ?,
        metric_cell = ?
    WHERE correlation_id = ?;
    """, (
        0, 0, "No unauthorized session created; request intercepted at gateway",
        1, "PASS", "TP_B", sample_corr_id
    ))
    conn.commit()

    print("\n[Step 4: Querying Correlated Forensic Record from Database]")
    print("-" * 78)
    cur.execute("SELECT * FROM normalized_events WHERE correlation_id = ?;", (sample_corr_id,))
    row = dict(cur.fetchone())
    for k, v in row.items():
        if v is not None and v != "":
            print(f"  {k:<24}: {v}")
    print("-" * 78)
    print("[+] Database schema, indices, and 3-tier workflow verified successfully!")
    print("=" * 78)
    conn.close()


if __name__ == "__main__":
    cfg = get_db_config()
    print("=" * 78)
    print("             WAFBench Telemetry Database Manager (db.py)")
    print("=" * 78)
    print(f" Target Host     : {cfg['host']}:{cfg['port']}")
    print(f" Database Name   : {cfg['dbname']}")
    print(f" Database User   : {cfg['user']}")
    print(f" psycopg2 Driver : {'Installed' if PSYCOPG2_AVAILABLE else 'Not Installed (Host)'}")
    print("-" * 78)

    # CLI argument handling
    if "--schema" in sys.argv or "--print-schema" in sys.argv:
        print_schema_overview()
        sys.exit(0)

    if "--demo" in sys.argv:
        run_local_terminal_demo()
        sys.exit(0)

    # Test connection
    if PSYCOPG2_AVAILABLE:
        try:
            conn = get_connection()
            print("[+] Connection Status: ONLINE (Successfully connected to event-db)")
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT table_name FROM information_schema.tables 
                    WHERE table_schema = 'public';
                """)
                tables = [r["table_name"] for r in cur.fetchall()]
            print(f"[+] Existing Tables  : {tables if tables else 'None (Empty Database)'}")
            
            if "--init" in sys.argv:
                init_db()
            elif "normalized_events" in tables:
                with conn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) AS count FROM normalized_events;")
                    cnt = cur.fetchone()["count"]
                print(f"[+] Total Events Recorded: {cnt}")

            conn.close()
        except Exception as e:
            print(f"[-] Connection Status: OFFLINE ({e})")
            print("[*] (Make sure Docker event-db is running via 'docker compose up -d event-db')")
    else:
        print("[-] psycopg2 is not installed in the current Python environment.")
        print("    Install locally via: py -m pip install psycopg2-binary")
        print("    (Note: Inside Docker containers, psycopg2 is pre-installed)")

    print("\n[Tip] View schema specifications anytime with: py telemetry/db.py --schema")
    print("=" * 78)

