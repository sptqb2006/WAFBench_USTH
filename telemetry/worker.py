#!/usr/bin/env python3
"""WAFBench Telemetry Worker Daemon (Stage 2 Evidence Collection -> Stage 3 Correlation Engine)

Reads the ModSecurity audit log line by line, stages each record in event-db, joins it with the
runner's row on X-Request-ID and classifies the row. A periodic pass classifies rows whose
audit record never came (a clean request is not logged under SecAuditEngine RelevantOnly).

Reading position:
  The byte offset after the last fully processed line is stored in event-db (ingest_offsets),
  so records written while the worker was down or starting are read on the next start.
  A new inode or a file smaller than the offset means rotation/truncation: read from byte 0.
  A line without its trailing newline is still being written: wait instead of parsing half a record.
"""

import sys
import os
import time
from typing import Optional, Tuple

# Ensure imports work whether run inside Docker or from repository root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from log_parser import parse_audit_record, get_sample_audit_log_sqli, get_sample_audit_log_benign
import db
import correlation

LOG_FILE = os.getenv("LOG_FILE_PATH", "/var/log/modsec/audit.log")
POLL_INTERVAL_S = 0.3
SWEEP_INTERVAL_S = float(os.getenv("CORRELATION_SWEEP_S", "1"))
OFFSET_SAVE_INTERVAL_S = 1.0
DB_RETRY_S = 2.0


def process_audit_line(line: str, persist_db: bool = True) -> Tuple[Optional[dict], bool]:
    """
    Parses one audit line and, with persist_db, stages it and correlates its row.
    Returns (parsed or None, ok). ok is False only when the database write failed,
    in which case the caller must not move past this line.
    """
    parsed = parse_audit_record(line)
    if not parsed or not parsed.get("correlation_id"):
        return None, True   # not JSON, or traffic without X-Request-ID (not ours)

    corr_id = parsed["correlation_id"]
    print(
        f"[+] Audit | Corr-ID: {corr_id[:8]}... | Engine: {parsed.get('waf_engine_mode') or '?':<13} | "
        f"Score: {parsed.get('inbound_score', 0):<3} | Action: {parsed.get('disruptive_action'):<5} | "
        f"Rules: {parsed.get('matched_rule_ids')}"
    )
    if not persist_db:
        return parsed, True

    if not db.stage_waf_audit(parsed):
        return parsed, False
    try:
        if db.update_waf_telemetry(corr_id, parsed):
            result = correlation.correlate_one(corr_id)
            if result:
                print(f"    -> {result['state']}: {result['metric_cell'] or '-'} ({result['validity']})")
        else:
            print("    -> staged; runner row not inserted yet, it will be joined on arrival")
    except Exception as e:
        # The record is staged, so the periodic pass will classify the row later
        print(f"    -> staged; correlation deferred ({e})")
    return parsed, True


class OffsetStore:
    """Durable read position in event-db. Without a database it only lives in memory."""

    def __init__(self, path: str, persist: bool):
        self.path = path
        self.persist = persist

    def load(self, inode: int, size: int) -> int:
        if not self.persist:
            return 0
        saved = db.get_offset(self.path)
        if saved and saved.get("inode") == inode and 0 <= saved.get("file_offset", 0) <= size:
            return int(saved["file_offset"])
        return 0   # first run, rotated file or truncated file: start from the beginning

    def save(self, inode: int, offset: int) -> None:
        if self.persist:
            db.save_offset(self.path, inode, offset)


def wait_for_database():
    while not db.test_connection():
        print(f"[*] Waiting for event-db at {db.get_db_config()['host']}...")
        time.sleep(DB_RETRY_S)
    db.ensure_schema()


def tail_audit_log(file_path: str = LOG_FILE, continuous: bool = True, persist_db: bool = True):
    """
    Follows the audit log. continuous=False reads a file once from byte 0 and exits (replay).
    """
    print("=" * 78)
    print("             WAFBench Telemetry Ingestion Daemon (worker.py)")
    print("=" * 78)
    print(f" Target Log File : {file_path}")
    print(f" Continuous Tail : {continuous}")
    print(f" Timeout / Sweep : {correlation.CORRELATION_TIMEOUT_S}s / {SWEEP_INTERVAL_S}s")
    print(f" Thresholds      : inbound {correlation.INBOUND_THRESHOLD}, outbound {correlation.OUTBOUND_THRESHOLD}")
    print("-" * 78)

    if persist_db:
        wait_for_database()
    store = OffsetStore(file_path, persist=persist_db and continuous)

    while not os.path.exists(file_path):
        print(f"[*] Waiting for {file_path} to be created by WAF Gateway...")
        time.sleep(2)

    f = open(file_path, "rb")
    inode = os.fstat(f.fileno()).st_ino
    offset = store.load(inode, os.fstat(f.fileno()).st_size)
    f.seek(offset)
    print(f"[+] Reading from byte {offset} (inode {inode})")

    last_saved, last_save_t, last_sweep_t = offset, time.time(), 0.0
    try:
        while True:
            pos = f.tell()
            raw = f.readline()

            if raw.endswith(b"\n") or (raw and not continuous):
                _, ok = process_audit_line(raw.decode("utf-8", "replace"), persist_db)
                if not ok:
                    f.seek(pos)   # database unavailable: retry the same record later
                    time.sleep(DB_RETRY_S)
                    continue
                offset = f.tell()
            elif raw:
                f.seek(pos)       # partial line: the WAF is still writing it
            elif not continuous:
                break

            now = time.time()
            if offset != last_saved and (now - last_save_t >= OFFSET_SAVE_INTERVAL_S or not raw):
                store.save(inode, offset)
                last_saved, last_save_t = offset, now
            if persist_db and now - last_sweep_t >= SWEEP_INTERVAL_S:
                try:
                    n = correlation.run_correlation_pass()
                    if n:
                        print(f"[*] Correlation pass classified {n} row(s)")
                except Exception as e:
                    print(f"[!] Correlation pass failed, retrying next interval: {e}")
                last_sweep_t = now

            if raw.endswith(b"\n"):
                continue

            # Idle or waiting on a partial line: check for rotation/truncation, then sleep
            try:
                st = os.stat(file_path)
                if st.st_ino != inode or st.st_size < offset:
                    print("[*] Log rotation/truncation detected. Reading the new file from byte 0...")
                    f.close()
                    f = open(file_path, "rb")
                    inode, offset, last_saved = os.fstat(f.fileno()).st_ino, 0, -1
                    continue
            except OSError:
                pass   # file briefly missing during rotation
            time.sleep(POLL_INTERVAL_S)
    finally:
        f.close()
        if persist_db and not continuous:
            correlation.run_correlation_pass(timeout_s=0, limit=100000)


def run_local_daemon_demo():
    """
    Streams two records, one of them written in two parts, through the reader without a database.
    Shows that a half-written line is not parsed until its newline arrives.
    """
    import tempfile
    import threading

    print("=" * 78)
    print("      WAFBench Telemetry Worker Real-Time Daemon Demonstration")
    print("=" * 78)
    demo_log = os.path.join(tempfile.gettempdir(), "wafbench_demo_audit.log")
    open(demo_log, "wb").close()
    print(f"[*] Simulated audit stream: {demo_log}")

    def simulate_waf_traffic():
        time.sleep(0.5)
        print("\n[WAF] Writing an SQLi record in two parts...")
        rec = get_sample_audit_log_sqli().encode()
        with open(demo_log, "ab") as out:
            out.write(rec[:40])
            out.flush()
            time.sleep(0.8)
            out.write(rec[40:] + b"\n")
        time.sleep(0.5)
        print("\n[WAF] Writing a benign record...")
        with open(demo_log, "ab") as out:
            out.write(get_sample_audit_log_benign().encode() + b"\n")

    threading.Thread(target=simulate_waf_traffic, daemon=True).start()

    events, deadline = 0, time.time() + 6.0
    with open(demo_log, "rb") as f:
        while time.time() < deadline and events < 2:
            pos = f.tell()
            raw = f.readline()
            if raw.endswith(b"\n"):
                parsed, _ = process_audit_line(raw.decode(), persist_db=False)
                events += 1 if parsed else 0
            else:
                f.seek(pos)
                time.sleep(0.1)

    print("-" * 78)
    print(f"[+] Processed {events} records; the half-written record was parsed only once complete.")
    print("=" * 78)
    try:
        os.remove(demo_log)
    except OSError:
        pass


if __name__ == "__main__":
    if "--demo" in sys.argv:
        run_local_daemon_demo()
        sys.exit(0)

    if "--help" in sys.argv:
        print("WAFBench Telemetry Worker Daemon Usage:")
        print("  python worker.py            : follow LOG_FILE_PATH (default: /var/log/modsec/audit.log)")
        print("  python worker.py --demo     : local streaming simulation, no database")
        print("  python worker.py --file F   : ingest file F once from the start, then classify pending rows")
        print("  add --no-db to --file to only parse and print")
        sys.exit(0)

    if "--file" in sys.argv:
        try:
            target_file = sys.argv[sys.argv.index("--file") + 1]
        except IndexError:
            sys.exit("Usage: python worker.py --file <path_to_audit_log> [--no-db]")
        tail_audit_log(target_file, continuous=False, persist_db="--no-db" not in sys.argv)
        sys.exit(0)

    tail_audit_log(LOG_FILE, continuous=True)
