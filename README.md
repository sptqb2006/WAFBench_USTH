# WAFBench: A Reproducible Evaluation Framework for Web Application Firewalls

**WAFBench** is an automated, self-hosted, and reproducible laboratory for the empirical evaluation of Web Application Firewalls (**Nginx 1.26 + ModSecurity v3 + OWASP Core Rule Set v4.0.0**).

---

## Architectural Overview

- **`gateway/`**: Ingress Reverse Proxy powered by Nginx 1.26 + ModSecurity v3 + OWASP Core Rule Set (CRS v4.0.0). Serial JSON audit logging to `/var/log/modsec/audit.log`.
- **`app/`**: Vulnerable target web application (Node.js 20 / Express) exposing four deterministic test endpoints: SQLi (`/login`), Reflected XSS (`/search`), Path Traversal (`/file`), and SSRF (`/fetch`).
- **`mock-internal/`**: Private internal HTTP responder for SSRF testing (`/metadata` sensitive endpoint; `/public/avatar.png` benign asset).
- **`corpus/`**: Standardized test corpus (malicious probes strictly paired with benign/edge cases) and validation scripts.
- **`telemetry/`**: Asynchronous ingestion pipeline tailing ModSecurity audit logs, normalizing to ECS-lite format, and recording to PostgreSQL `event-db`.
- **`dashboard/`**: Streamlit Analytics Dashboard (:8501) visualizing Detection Rate (DR), Blocking Rate (BR), False Positive Rates (FPR), and 3-tier raw evidence.
- **`runner/`**: Automated CLI test harness orchestrating 3-state evaluation (`Direct-to-App`, `DetectionOnly`, `Blocking`) with independent application oracles.

---

## Subsystem Details: Telemetry, Database & Evaluation Dashboard

### Telemetry Pipeline & Database (`telemetry/`)
- **`telemetry/schema.sql`**: Relational schema provisioning for PostgreSQL 16 `event-db`:
  - `normalized_events` (Table 4.3): Stores cross-tier data across Client probes, WAF telemetry, and Backend Oracle results. Includes a `UNIQUE` constraint on `correlation_id` enabling atomic `UPSERT` (`ON CONFLICT DO UPDATE`) to eliminate ingestion race conditions. Includes forensic drawer attributes (`waf_payload_snippet`, `waf_matched_variable`, `root_rule_id`, `root_rule_name`, `raw_log_ref`, `oracle_observation`).
  - `evaluation_metrics` (Table 4.6): Aggregated batch metrics storage for Detection Rate (DR), Blocking Rate (BR), Detection FPR, Blocking FPR, and Regression Pass Rate (RPR).
  - B-Tree indexes on query keys (`correlation_id`, `batch_id`, `run_id`, `case_id`, `state`, `verdict`, `metric_cell`).
- **`telemetry/db.py`**: Resilient PostgreSQL connector, schema manager, and data access layer:
  - Guarded `psycopg2` driver import with graceful fallback for host machines without local PostgreSQL drivers.
  - CRUD operations: `init_db()`, `upsert_client_event()`, `update_waf_telemetry()`, `update_verdict()`, and `get_recent_events()`.
  - CLI capabilities: `--schema` prints Table 4.3 and 4.6 specifications; `--demo` executes an in-memory SQLite simulation of the full 3-tier data lifecycle without requiring Docker.
- **`telemetry/log_parser.py`**: Native ModSecurity v3 serial JSON audit log parser converting raw logs to ECS-lite normalized events:
  - Extracts `correlation_id` from incoming `X-Request-ID` headers.
  - Distinguishes root attack rules (e.g., SQLi `942100`) from CRS scoring meta-rules (`949110`).
  - Extracts anomaly scores, disruptive actions (`block` vs. `allow`), matched variables, and payload snippets.
  - Computes `raw_log_ref` (SHA-256 cryptographic digest of the raw log entry) for forensic integrity.
  - Built-in test suite verifying SQLi, benign, and malformed JSON parsing resilience.
- **`telemetry/worker.py`**: Asynchronous background daemon:
  - Continuously monitors `/var/log/modsec/audit.log` from the read-only volume (`:ro`) with file rotation/truncation detection.
  - Invokes `log_parser.py` and ingests records directly into PostgreSQL via `db.update_waf_telemetry()`.
  - Built-in `--demo` mode simulating live ModSecurity traffic and real-time database ingestion directly in the terminal.
- **`telemetry/correlation.py`**: 3-tier scientific correlation engine linking Client Observation, WAF Telemetry, and Backend Application Oracle:
  - Mode-specific evaluation logic for `Direct-to-App`, `DetectionOnly`, and `Blocking` states.
  - Solves the HTTP Status Fallacy: detects HTTP 403 responses lacking WAF audit records, classifying them as `I_UNATTRIBUTED` / `INCONCLUSIVE` and strictly excluding them from Blocking Rate (BR) denominators.
  - Computes batch benchmark metrics conforming to Table 4.6 (DR, BR, Detection FPR, Blocking FPR).
  - Built-in automated test suite covering 9 distinct verification scenarios.

### Evaluation Dashboard (`dashboard/`)
- **`dashboard/app.py`**: Multi-page Streamlit analytics console (`:8501`):
  - Dual-mode data source: connects to PostgreSQL `event-db` live stream with automatic fallback to `sample_events.json` (Demo Mode) when offline.
  - Academic evaluation header with run metadata badges (CRS baseline, anomaly threshold, active evaluation mode).
  - High-level KPI metric cards (Total Probes, Evaluable vs. Inconclusive, Perimeter Denials, WAF Blocks, Empirical Blocking Rate).
  - Multi-dimensional case filtering (Target Endpoint, Threat Class, Disruptive Action, HTTP Status, CRS Rule ID).
  - Side-by-side layout: Normalized Event Stream table paired with a 3-tier forensic inspection drawer (Client Observation, WAF Evidence, Backend Oracle).
- **`dashboard/styles.py`**: Styling layer enforcing an academic visual hierarchy:
  - Constrains sidebar to a sleek 200px rail with hidden collapse button to keep navigation anchored.
  - Enforces a high-contrast Light Theme palette (`#ffffff`, `#f8f9fa`, `#dadce0`, `#202124`, `#1a73e8`) for reliability across displays.
  - Configures top-right `#MainMenu` controls for developer operations (Rerun, Settings, Screencast recording, Clear cache).
- **`dashboard/sample_events.json`**: Offline fixture containing 10 representative Table 4.3 test records (SQLi, XSS, RCE, Path Traversal, Benign, False Alarms, Bypasses, and Unattributed Perimeters).
- **`dashboard/pages/`**: Specialized multi-page views:
  - **`1_Overview.py`**: Quantitative benchmarks (DR, BR, Detection FPR, Blocking FPR), dual confusion matrices (Blocking & DetectionOnly), and validity breakdown.
  - **`2_Case_Explorer.py`**: Multi-dimensional filtering and drill-down across test cases, execution states, and verdicts.
  - **`3_Evidence_Viewer.py`**: Raw artifact inspector comparing Client probe data, WAF audit evidence with SHA-256 fingerprint, and Backend Oracle mutations.
  - **`4_Live_Demo.py`**: Interactive sandbox dispatching live HTTP payloads with custom `X-Request-ID` headers to `:8080` with latency measurement.

---

## Terminal Verification Commands

Verify each telemetry, database, and dashboard component locally or inside containers:

### 1. Telemetry & Database Verification
```bash
# View Table 4.3 and 4.6 relational schema definitions:
python3 telemetry/db.py --schema
# (Windows: py telemetry/db.py --schema)

# Run in-memory SQLite 3-tier lifecycle simulation:
python3 telemetry/db.py --demo
# (Windows: py telemetry/db.py --demo)

# Run ModSecurity JSON log parser automated test suite:
python3 telemetry/log_parser.py
# (Windows: py telemetry/log_parser.py)

# Run telemetry worker streaming simulation:
python3 telemetry/worker.py --demo
# (Windows: py telemetry/worker.py --demo)

# Run 3-tier cross-correlation engine test suite (9 scenarios):
python3 telemetry/correlation.py
# (Windows: py telemetry/correlation.py)
```

### 2. Standalone Subsystem Container Launch
To start only the telemetry database, ingestion worker, and Streamlit dashboard:
```bash
docker compose up -d --build event-db dashboard telemetry-worker
```
- Access the Streamlit Dashboard at: `http://localhost:8501`
- PostgreSQL `event-db` is accessible at: `localhost:5432` (User: `wafbench`, DB: `wafbench_events`)

---

## Quick-Start Deployment Guide

### 1. Prerequisites
- Docker Engine & Docker Compose plugin (`docker compose`).
- Recommended Environment: Linux (Ubuntu/Debian) or dedicated VM (2 vCPU, 4–6 GB RAM, 25+ GB SSD).

Create your environment configuration from the template:
```bash
cp .env.example .env
```

### 2. Launch the Entire Laboratory
```bash
make up
# or: docker compose up -d --build
```

### 3. Verify System & Health Status
```bash
make status
```
- **WAF Ingress Route**: `http://localhost:8080`
- **Direct Baseline (Loopback Bypass)**: `http://127.0.0.1:8001`
- **Streamlit Analytics Dashboard**: `http://localhost:8501`

### 4. Switch WAF Operating Profiles
```bash
make mode-detection   # Switches ModSecurity to DetectionOnly and reloads Nginx
make mode-blocking    # Switches ModSecurity to Blocking (On) and reloads Nginx
```

### 5. Trigger Fast Fixture Reset
```bash
make reset
# Truncates sessions/articles and re-seeds Fixture F1 in <= 5 seconds
```

### 6. Execute Test Runner Suite
```bash
make test
# Runs 3-state evaluation with 3 repetitions per case and exports CSV results
```
