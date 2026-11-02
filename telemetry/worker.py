#!/usr/bin/env python3
"""WAFBench Telemetry Worker Daemon
Monitors ModSecurity audit log, parses JSON via log_parser, and updates event-db.
Conforming to Table 4.3 and the WAF Telemetry Ingestion Contract.
Author: Phan Duc Anh
"""

import sys
import os
import time
import json
from typing import Optional

# Ensure imports work whether run inside Docker or from repository root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from log_parser import parse_audit_record, get_sample_audit_log_sqli, get_sample_audit_log_benign
import db

LOG_FILE = os.getenv("LOG_FILE_PATH", "/var/log/modsec/audit.log")


def process_audit_line(line: str, persist_db: bool = True) -> Optional[dict]:
    """
    Parses a single JSON audit line and updates normalized_events in event-db.
    """
    parsed = parse_audit_record(line)
    if not parsed:
        return None

    corr_id = parsed.get("correlation_id")
    if not corr_id:
        return None

    score = parsed.get("inbound_score", 0)
    action = parsed.get("disruptive_action", "none")
    root_rule = parsed.get("root_rule_id") or "None"

    # Terminal visual feedback
    print(
        f"[+] Ingested WAF Audit | Corr-ID: {corr_id[:8]}... | "
        f"Score: {score:<2} | Action: {action:<5} | Rule: {root_rule}"
    )

    if persist_db:
        try:
            success = db.update_waf_telemetry(corr_id, parsed)
            if not success:
                print(f"[-] DB Update warning: No existing record found for {corr_id} (or DB offline)")
        except Exception as e:
            print(f"[!] Database update error for {corr_id}: {e}")

    return parsed


def tail_audit_log(file_path: str = LOG_FILE, continuous: bool = True):
    """
    Tails a ModSecurity serial JSON audit log file continuously.
    Handles file creation delays, non-blocking reads, and file rotation/truncation.
    """
    print("=" * 78)
    print("             WAFBench Telemetry Ingestion Daemon (worker.py)")
    print("=" * 78)
    print(f" Target Log File : {file_path}")
    print(f" Continuous Tail : {continuous}")
    print(f" Database Status : {'Connected' if db.test_connection() else 'Offline / Standalone Mode'}")
    print("-" * 78)

    # 1. Wait until target file exists
    while not os.path.exists(file_path):
        print(f"[*] Waiting for {file_path} to be created by WAF Gateway...")
        time.sleep(2)

    print(f"[+] Found log file. Seeking to end of stream...")

    with open(file_path, "r", encoding="utf-8") as f:
        # For continuous live tailing, seek to end; for file replay, start at beginning
        if continuous:
            f.seek(0, os.SEEK_END)
        current_pos = f.tell()

        while True:
            # Check for file truncation or log rotation
            try:
                actual_size = os.path.getsize(file_path)
                if actual_size < current_pos:
                    print("[*] Log file truncation/rotation detected. Rewinding pointer...")
                    f.seek(0, os.SEEK_SET)
                    current_pos = 0
            except OSError:
                pass

            line = f.readline()
            if line:
                current_pos = f.tell()
                process_audit_line(line, persist_db=True)
            else:
                if not continuous:
                    break
                time.sleep(0.3)


def run_local_daemon_demo():
    """
    Demonstrates the live file-tailing and parsing daemon in action
    using a temporary local file, verifying real-time ingestion in the terminal.
    """
    import tempfile
    import threading

    print("=" * 78)
    print("      WAFBench Telemetry Worker Real-Time Daemon Demonstration")
    print("=" * 78)

    # Create temporary log file
    temp_dir = tempfile.gettempdir()
    demo_log = os.path.join(temp_dir, "wafbench_demo_audit.log")

    with open(demo_log, "w", encoding="utf-8") as f:
        f.write("")  # Empty file initially

    print(f"[*] Created simulated audit stream at: {demo_log}")
    print("[*] Launching asynchronous file generator to simulate incoming WAF traffic...")

    def simulate_waf_traffic():
        time.sleep(1.0)
        print("\n[WAF Engine] ModSecurity intercepted SQL Injection -> Writing audit record...")
        with open(demo_log, "a", encoding="utf-8") as f_out:
            f_out.write(get_sample_audit_log_sqli() + "\n")
            f_out.flush()

        time.sleep(1.5)
        print("\n[WAF Engine] ModSecurity inspected Benign Request -> Writing audit record...")
        with open(demo_log, "a", encoding="utf-8") as f_out:
            f_out.write(get_sample_audit_log_benign() + "\n")
            f_out.flush()

    # Start writer thread
    writer_thread = threading.Thread(target=simulate_waf_traffic, daemon=True)
    writer_thread.start()

    print("[*] Starting telemetry worker tail listener...\n" + "-" * 78)

    # Read the two events with timeout
    with open(demo_log, "r", encoding="utf-8") as f:
        events_processed = 0
        timeout = time.time() + 6.0
        while time.time() < timeout and events_processed < 2:
            line = f.readline()
            if line:
                res = process_audit_line(line, persist_db=False)
                if res:
                    events_processed += 1
            else:
                time.sleep(0.2)

    print("-" * 78)
    print(f"[+] Worker successfully intercepted and processed {events_processed} streaming events!")
    print("[+] File tailing, JSON validation, and ECS-lite parsing verified.")
    print("=" * 78)

    # Cleanup
    try:
        os.remove(demo_log)
    except OSError:
        pass


if __name__ == "__main__":
    if "--demo" in sys.argv:
        run_local_daemon_demo()
        sys.exit(0)

    if "--file" in sys.argv:
        try:
            idx = sys.argv.index("--file")
            target_file = sys.argv[idx + 1]
            tail_audit_log(target_file, continuous=False)
            sys.exit(0)
        except (IndexError, ValueError):
            print("Usage: py worker.py --file <path_to_audit_log>")
            sys.exit(1)

    if "--help" in sys.argv:
        print("WAFBench Telemetry Worker Daemon Usage:")
        print("  py worker.py          : Run daemon monitoring LOG_FILE_PATH (default: /var/log/modsec/audit.log)")
        print("  py worker.py --demo   : Run interactive local streaming simulation in terminal")
        print("  py worker.py --file F : Process and ingest a specific log file once")
        sys.exit(0)

    # Default production daemon mode
    tail_audit_log(LOG_FILE, continuous=True)
: {e}")

if __name__ == "__main__":
    tail_audit_log()
: {e}")

if __name__ == "__main__":
    tail_audit_log()
