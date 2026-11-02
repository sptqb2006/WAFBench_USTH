# WAFBench: Changes & Explanations

# **Module:** Telemetry & Database (`schema.sql` & `db.py`)  

## 1. Overview
Implemented the database schema and connection manager for `event-db` (PostgreSQL 16) as specified in `notes/working_files.txt`.

### Modified Files
* [`telemetry/schema.sql`](file:///D:/Documents/learning%20resources/usth%20B3/grp_prj/WAFBench_USTH/telemetry/schema.sql)
* [`telemetry/db.py`](file:///D:/Documents/learning%20resources/usth%20B3/grp_prj/WAFBench_USTH/telemetry/db.py)

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

## 3. Terminal Verification Commands

You can test and view the implementation using these commands:

```powershell
# 1. View Schema Specifications (Tables 4.3 & 4.6):
py WAFBench_USTH/telemetry/db.py --schema

# 2. View 3-Tier Workflow in Action (Local Demo):
py WAFBench_USTH/telemetry/db.py --demo

# 3. Check Live PostgreSQL Connection:
py WAFBench_USTH/telemetry/db.py
```
