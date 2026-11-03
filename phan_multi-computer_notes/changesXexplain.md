# WAFBench: Changes & Explanations

> **Module:** Telemetry Pipeline, Database & Evaluation Dashboard  
> **Date:** November 3, 2026  

---

## 1. Overview
Implemented and verified the core telemetry ingestion pipeline, database layer, cross-tier correlation engine, and forensic evaluation dashboard (`schema.sql`, `db.py`, `log_parser.py`, `worker.py`, `correlation.py`, `dashboard/app.py`, `dashboard/styles.py`, `dashboard/pages/*`) as specified in `notes/working_files.txt`.

### Modified & Added Files
* [`telemetry/schema.sql`](file: WAFBench_USTH/telemetry/schema.sql)
* [`telemetry/db.py`](file: WAFBench_USTH/telemetry/db.py)
* [`telemetry/log_parser.py`](file: WAFBench_USTH/telemetry/log_parser.py)
* [`telemetry/worker.py`](file: WAFBench_USTH/telemetry/worker.py)
* [`telemetry/correlation.py`](file: WAFBench_USTH/telemetry/correlation.py)
* [`dashboard/app.py`](file: WAFBench_USTH/dashboard/app.py)
* [`dashboard/styles.py`](file: WAFBench_USTH/dashboard/styles.py)
* [`dashboard/sample_events.json`](file: WAFBench_USTH/dashboard/sample_events.json)
* [`dashboard/.streamlit/config.toml`](file: WAFBench_USTH/dashboard/.streamlit/config.toml)
* [`dashboard/pages/1_Overview.py`](file: WAFBench_USTH/dashboard/pages/1_Overview.py)
* [`dashboard/pages/2_Case_Explorer.py`](file: WAFBench_USTH/dashboard/pages/2_Case_Explorer.py)
* [`dashboard/pages/3_Evidence_Viewer.py`](file: WAFBench_USTH/dashboard/pages/3_Evidence_Viewer.py)
* [`dashboard/pages/4_Live_Demo.py`](file: WAFBench_USTH/dashboard/pages/4_Live_Demo.py)

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

### `dashboard/app.py`
Main Streamlit analytics console (`:8501`) providing real-time forensic monitoring and benchmark visualization:
* **Dual-Mode Data Source (Live Stream & Resilient Fallback):**
  * Attempts direct connection to PostgreSQL `event-db` on the internal network.
  * Automatically switches to `sample_events.json` (Demo Mode) when running without database containers or during offline development.
* **Academic Evaluation Header:**
  * Displays experiment run metadata badges: connection state (`[LIVE STREAM]` vs. `[DEMO MODE]`), CRS baseline (`C0 Baseline`, `PL1`), anomaly threshold (`5`), and evaluation modes (`Blocking` / `DetectionOnly`).
* **KPI Metric Cards:**
  * Computes total dispatched probes, evaluable vs. inconclusive counts, client-observed perimeter denials (HTTP 403), WAF-verified blocks, and empirical Blocking Rate ($BR$).
* **Multi-Dimensional Case Slicing:**
  * Interactive filters across Target Endpoint, Threat Class (`family_id`), Disruptive Action, HTTP Status Code, and Root/Matched CRS Rule ID search.
* **Normalized Event Stream & Forensic Inspection Drawer:**
  * Side-by-side layout: left table renders normalized event streams; right drawer provides comprehensive 3-tier forensic breakdown (Block A: Client Observation, Block B: WAF ModSecurity Evidence with score coloring, Block C: Backend Oracle Outcome).

---

### `dashboard/styles.py`
Modular styling component enforcing academic visual hierarchy and navigation usability:
* **Compact & Pinned Sidebar Rail:**
  * Constrains sidebar width to a sleek, compact rail with clean spacing, avoiding screen bloat.
  * Hides the manual collapse button while preserving expand triggers so the sidebar stays neatly anchored and accessible.
  * Replaces default script filename labels with clean, human-readable titles (`WAFBench Console`).
* **Streamlit Main Menu (`#MainMenu` / `...` Controls):**
  * Retains essential developer and evaluation utilities in the top-right toolbar: **Rerun** (refreshing event queries without full browser reloads), **Settings** (runtime display options), **Record a screencast** (in-browser capture of attack traffic simulations for lab demos), **Clear cache** (re-querying PostgreSQL from scratch), and **Print** (PDF report exports).
* **Pure Light Theme (Dark Mode & Theme Switching Removed):**
  * Locks base theme to clean, high-contrast Light styling (`#ffffff`, `#f8f9fa`, `#dadce0`, `#202124`, `#1a73e8`) in `config.toml`, completely removing fragile theme-switching variables to eliminate contrast and UI layout glitches.

---

### `dashboard/sample_events.json`
Rich offline mock dataset conforming to Table 4.3 `normalized_events`:
* Contains 10 diverse benchmark test cases covering SQL Injection, Cross-Site Scripting (XSS), Remote Code Execution (RCE), Path Traversal, Edge-Case Benign queries, False Alarms (`FP_B`), Baseline Bypasses (`FN_B`), and Unattributed Perimeters (`I_UNATTRIBUTED`).

---

### `dashboard/pages/` (Multi-Page Specialized Views)
Specialized analytics modules accessible via the sidebar navigation:
* **`1_Overview.py` (Executive KPI & Benchmark Overview):**
  * Computes Table 4.6 and Table 5.2 quantitative metrics: Empirical Blocking Rate ($BR$), Detection Rate ($DR$), Detection FPR ($FPR_D$), Blocking FPR ($FPR_B$).
  * Generates separate confusion matrices for Blocking Mode and DetectionOnly Mode alongside validity breakdown tables.
* **`2_Case_Explorer.py` (Multi-Dimensional Case Explorer):**
  * Interactive data explorer allowing deep-dive filtering by threat category, execution state (`PASS`, `FAIL`, `INCONCLUSIVE`), and evaluation verdict.
* **`3_Evidence_Viewer.py` (3-Tier Raw Evidence Viewer):**
  * Side-by-side comparative inspection console displaying Tier 1 (Client probe request/response), Tier 2 (WAF anomaly score, disruptive action, and raw log SHA-256 fingerprint), and Tier 3 (Backend Oracle mutation and diagnostic).
* **`4_Live_Demo.py` (Interactive Verification Sandbox):**
  * Real-time probe generator dispatching live payloads (`POST`/`GET`) with custom `X-Request-ID` headers against the WAF Gateway (`:8080`) with latency measurements and response header inspection.

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

# 6-1. Build & Launch Evaluation Dashboard Container:
docker compose -f WAFBench_USTH/docker-compose.yml up -d --build dashboard
# 6-2. Build & Launch Dashboard when already accessing the directory:
docker compose up -d --build dashboard
# Access via browser at: http://localhost:8501
```
