#!/usr/bin/env python3
"""
Sync Runner Benchmark Results to Event-DB (PostgreSQL)
Author: Kieu Dang Vuong
"""

import os
import sys
import subprocess
import pandas as pd

def sync_csv_to_event_db(csv_file: str) -> bool:
    if not os.path.exists(csv_file):
        print(f"[!] CSV file not found: {csv_file}")
        return False

    df = pd.read_csv(csv_file)
    if df.empty:
        print("[!] CSV file is empty.")
        return False

    values = []
    for _, r in df.iterrows():
        def esc(val):
            if pd.isna(val) or val is None:
                return "NULL"
            return "'" + str(val).replace("'", "''") + "'"

        client_status = "NULL" if pd.isna(r.get("client_status")) else str(int(r.get("client_status")))
        backend_effect = "true" if r.get("backend_effect") is True or str(r.get("backend_effect")).lower() == "true" else "false"

        state = str(r.get('state', ''))
        validity = str(r.get('validity', 'VALID'))
        verdict = "'PASS'" if validity == "VALID" else esc(validity)
        metric_cell = "'BASELINE_OK'" if state == "Direct-to-App" and validity == "VALID" else "'PENDING_TELEMETRY'"

        row_tuple = (
            f"({esc(r.get('batch_id'))}, {esc(r.get('batch_id'))}, {esc(r.get('case_id'))}, "
            f"{esc(r.get('family'))}, {esc(r.get('label'))}, {esc(r.get('state'))}, "
            f"{int(r.get('repetition', 1))}, {esc(r.get('correlation_id'))}, {client_status}, "
            f"{esc(r.get('request_sha256'))}, {backend_effect}, {esc(r.get('oracle_observation'))}, "
            f"{esc(validity)}, {esc(r.get('invalid_reason'))}, {verdict}, {metric_cell})"
        )
        values.append(row_tuple)

    sql = f"""
    INSERT INTO normalized_events (
        run_id, batch_id, case_id, family_id, label, state, repetition, correlation_id,
        client_status, request_sha256, backend_effect, oracle_observation, validity, invalid_reason, verdict, metric_cell
    ) VALUES {','.join(values)};
    """

    try:
        proc = subprocess.run(
            ["docker", "exec", "-i", "wb-event-db", "psql", "-U", "telemetry_user", "-d", "wafbench_events"],
            input=sql.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        print(f"[+] Synchronized {len(values)} test records to event-db.")
        return True
    except Exception as e:
        print(f"[-] Warning: Failed to sync to event-db: {e}")
        return False

if __name__ == "__main__":
    target_csv = sys.argv[1] if len(sys.argv) > 1 else None
    if not target_csv:
        results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
        csv_files = [os.path.join(results_dir, f) for f in os.listdir(results_dir) if f.endswith(".csv")]
        if not csv_files:
            print("[!] No CSV results found.")
            sys.exit(1)
        target_csv = max(csv_files, key=os.path.getmtime)

    print(f"[*] Syncing {target_csv} to event-db...")
    sync_csv_to_event_db(target_csv)
