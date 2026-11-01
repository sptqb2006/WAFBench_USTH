#!/usr/bin/env python3
"""
Telemetry Worker Daemon: Monitors ModSecurity audit log, parses JSON, and writes to event-db.
Author: Phan Duc Anh
"""

import time
import os
import json
from log_parser import parse_audit_record
from db import get_connection
from correlation import correlate_event

LOG_FILE = os.getenv("LOG_FILE_PATH", "/var/log/modsec/audit.log")

def tail_audit_log():
    print(f"[*] Telemetry Worker starting. Monitoring {LOG_FILE}...")
    
    # Wait until file exists
    while not os.path.exists(LOG_FILE):
        print(f"[*] Waiting for {LOG_FILE} to be created by WAF Gateway...")
        time.sleep(2)

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        # Start from beginning to catch any existing records
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            parsed = parse_audit_record(line)
            if not parsed or not parsed.get("correlation_id"):
                continue

            try:
                conn = get_connection()
                with conn.cursor() as cur:
                    cur.execute("""
                        UPDATE normalized_events
                        SET waf_txn_id = %s,
                            matched_rule_ids = %s,
                            inbound_score = %s,
                            disruptive_action = %s,
                            audit_ref = %s
                        WHERE correlation_id = %s
                        RETURNING id, label, state, backend_effect, validity
                    """, (
                        parsed["waf_txn_id"],
                        json.dumps(parsed["matched_rule_ids"]),
                        parsed["inbound_score"],
                        parsed["disruptive_action"],
                        parsed["audit_raw"],
                        parsed["correlation_id"]
                    ))
                    row = cur.fetchone()
                    if row:
                        client_data = {"correlation_id": parsed["correlation_id"], "label": row["label"]}
                        waf_data = {"inbound_score": parsed["inbound_score"], "disruptive_action": parsed["disruptive_action"]}
                        oracle_data = {"backend_effect": row["backend_effect"]}
                        correlated = correlate_event(client_data, waf_data, oracle_data, row["state"])
                        cur.execute("""
                            UPDATE normalized_events
                            SET verdict = %s, metric_cell = %s
                            WHERE id = %s
                        """, (correlated.get("verdict"), correlated.get("metric_cell"), row["id"]))
                conn.commit()
                conn.close()
                print(f"[+] Processed WAF Audit for Correlation-ID: {parsed['correlation_id']}")
            except Exception as e:
                print(f"[!] DB write error: {e}")

if __name__ == "__main__":
    tail_audit_log()
