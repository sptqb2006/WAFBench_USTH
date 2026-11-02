# WAFBench: Changes & Explanations

> **Module:** Telemetry Pipeline & Database  
> **Date:** November 2, 2026  

---

## 1. Overview
Implemented and verified the core telemetry ingestion pipeline, database layer, and cross-tier correlation engine (`schema.sql`, `db.py`, `log_parser.py`, `worker.py`, `correlation.py`) as specified in `notes/working_files.txt`.

### Modified Files
* [`telemetry/schema.sql`](file:///D:/Documents/learning%20resources/usth%20B3/grp_prj/WAFBench_USTH/telemetry/schema.sql)
* [`telemetry/db.py`](file:///D:/Documents/learning%20resources/usth%20B3/grp_prj/WAFBench_USTH/telemetry/db.py)
* [`telemetry/log_parser.py`](file:///D:/Documents/learning%20resources/usth%20B3/grp_prj/WAFBench_USTH/telemetry/log_parser.py)
* [`telemetry/worker.py`](file:///D:/Documents/learning%20resources/usth%20B3/grp_prj/WAFBench_USTH/telemetry/worker.py)
* [`telemetry/correlation.py`](file:///D:/Documents/learning%20resources/usth%20B3/grp_prj/WAFBench_USTH/telemetry/correlation.py)

---

## 2. Summary of Changes

### `telemetry/schema.sql`
Defines the relational tables for cross-tier event logging and benchmark metrics:
* **`normalized_events` (Table 4.3):**
  * `correlation_id UNIQUE`: Added unique constraint to enable atomic `UPSERT` (`ON CONFLICT DO UPDATE`), preventing race conditions between the test runner and WAF worker.
  * Added Forensic Drawer fields: `waf_payload_snippet`, `waf_matched_variable`, `root_rule_id`, `root_rule_name`, `raw_log_ref`, and `oracle_observation`.
  * Full 3-tier structure: Stores Client observation, ModSecurity WAF telemetry, and Backend App Oracle results.
* **`evaluation_metrics` (Table 4.6):**
  * Stores batch KPIs: `detection_rate` (DR), `blocking_rate` (BR), `detection_fpr`, `blocking_fpr`, and `regression_pass_rate` (RPR).
* **Indexes:**
  * Added B-Tree indexes on `correlation_id`, `batch_id`, `run_id`, `case_id`, `state`, `verdict`, and `metric_cell` for fast querying.

---

### `telemetry/db.py`
Provides connection management, schema initialization, and data operations:
* **Resilient Driver Import:** Wrapped `psycopg2` in a `try/except` guard so CLI viewers run on host machines even if PostgreSQL drivers are not installed locally.
* **Schema Management (`init_db`):** Executes `schema.sql` to provision or reset tables automatically.
* **Data Access Helpers:**
  * `upsert_client_event()`: Safely inserts client probes via `ON CONFLICT DO UPDATE`.
  * `update_waf_telemetry()`: Ingests ModSecurity rule matches, anomaly scores, and payload snippets.
  * `update_verdict()`: Updates final verdicts (`PASS`, `FAIL`) and confusion matrix cells (`TP_B`, `FP_D`, etc.).
  * `get_recent_events()`: Fetches recent records for dashboard and CLI views.
* **Built-in CLI Viewers:**
  * `--schema`: Prints Table 4.3 & 4.6 definitions directly in the terminal.
  * `--demo`: Runs an in-memory SQLite simulation of the full 3-tier lifecycle without needing Docker.

---

### `telemetry/log_parser.py`
Parses native ModSecurity v3 serial JSON audit logs into the ECS-lite schema:
* **Field Extraction:**
  * Captures `correlation_id` from `X-Request-ID` headers (case-insensitive).
  * Distinguishes root attack rules (e.g., SQLi `942100`) from CRS scoring meta-rules (`949110`).
  * Extracts forensic snippets (`waf_payload_snippet`, `waf_matched_variable`), cumulative `inbound_score`, and disruptive actions (`block` vs. `allow`).
  * Generates `raw_log_ref`: SHA-256 cryptographic fingerprint of the raw line for audit proof.
* **Error Resilience:** Returns `None` on malformed or partial JSON without throwing unhandled exceptions.
* **Built-in Test Suite:** Running `py log_parser.py` executes automated tests against sample SQLi and benign audit logs.

---

### `telemetry/worker.py`
Asynchronous background daemon monitoring `/var/log/modsec/audit.log` from the read-only volume (`:ro`):
* **Tailing Engine:** Continuously tails the audit log stream with non-blocking reads and file rotation/truncation detection.
* **Database Ingestion:** Automatically calls `db.update_waf_telemetry()` to populate `normalized_events` in PostgreSQL.
* **Streaming Demo Mode:** Includes `--demo` mode simulating live ModSecurity traffic and real-time worker ingestion in the terminal.

---

### `telemetry/correlation.py`
Scientific correlation engine combining Client Observation, WAF Telemetry, and Backend Application Oracle data:
* **Mode-Specific Triad Logic:**
  * `Direct-to-App`: Absence of WAF log is expected by design; verifies baseline exploitability (`backend_effect == True`).
  * `DetectionOnly`: Classifies outcomes against the anomaly threshold ($5$) into `TP_D`, `FN_D`, `FP_D` (False Alarm), or `TN_D`.
  * `Blocking`: Evaluates gateway enforcement vs. backend compromise into `TP_B`, `FN_B` (Bypass), `FP_B` (Erroneous Block), or `TN_B`.
* **HTTP Status Fallacy & Inconclusive Handling:**
  * Traps HTTP 403 responses lacking WAF audit evidence as `I_UNATTRIBUTED` / `INCONCLUSIVE`.
  * Strictly excludes inconclusive events from the Blocking Rate ($BR$) denominator.
* **Batch Roll-up Metrics:** Computes batch-level evaluation rates ($DR, BR, FPR_D, FPR_B$) conforming to Table 4.6.
* **Database Pipeline:** Integrates `correlate_and_save()` to commit verdicts directly via `db.update_verdict()`.

---

## 3. Terminal Verification Commands

You can test and view each component using these commands:

```powershell
# 1. View Schema Specifications (Tables 4.3 & 4.6):
py WAFBench_USTH/telemetry/db.py --schema

# 2. View 3-Tier Database Lifecycle in Action:
py WAFBench_USTH/telemetry/db.py --demo

# 3. Test ModSecurity JSON Log Parser (Automated Test Suite):
py WAFBench_USTH/telemetry/log_parser.py

# 4. View Telemetry Worker Live Streaming Simulation:
py WAFBench_USTH/telemetry/worker.py --demo

# 5. Run Cross-Tier Correlation Engine Test Suite (9 Scenarios):
py WAFBench_USTH/telemetry/correlation.py
```
