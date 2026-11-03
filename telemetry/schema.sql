-- ==============================================================================
-- WAFBench Normalized Event Store Schema (PostgreSQL 16)
-- Conforming to Table 4.3 (Normalized Events) & Table 4.6 (Evaluation Metrics)
-- ==============================================================================

DROP TABLE IF EXISTS evaluation_metrics CASCADE;
DROP TABLE IF EXISTS normalized_events CASCADE;

-- ------------------------------------------------------------------------------
-- Table 4.3: Normalized Events (3-Tier Correlated Telemetry Records)
-- ------------------------------------------------------------------------------
CREATE TABLE normalized_events (
    id SERIAL PRIMARY KEY,

    -- Identity & Correlation Fields
    correlation_id VARCHAR(64) UNIQUE NOT NULL,    -- Injected X-Request-ID (1:1 universal join key)
    run_id VARCHAR(64) NOT NULL,                    -- Execution run identifier
    batch_id VARCHAR(64),                           -- Evaluation batch identifier
    case_id VARCHAR(64) NOT NULL,                   -- Test case ID (e.g., SQLI-001)
    family_id VARCHAR(64) NOT NULL,                 -- Threat category (SQLi, XSS, Path_Trav, SSRF)
    label VARCHAR(32) NOT NULL,                     -- Ground truth label: malicious | benign | edge
    state VARCHAR(32) NOT NULL,                     -- WAF mode: Direct-to-App | DetectionOnly | Blocking
    repetition INT DEFAULT 1,                       -- Repetition sequence index (1..3)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Tier 1: Client Observation Fields (Test Runner Capture)
    client_ip VARCHAR(45),                          -- Origin IP of the test runner
    method VARCHAR(16),                             -- HTTP method (GET, POST)
    endpoint TEXT,                                  -- Target URI path (/login, /search, etc.)
    client_status INT,                              -- HTTP status code observed by client (200, 403, etc.)
    request_sha256 VARCHAR(64),                     -- SHA-256 fingerprint of request payload
    response_body_snippet TEXT,                     -- Snippet of HTTP response body received by client

    -- Tier 2: WAF Telemetry Fields (ModSecurity v3 Native JSON Audit Log -> ECS-lite)
    waf_txn_id VARCHAR(64),                         -- ModSecurity internal transaction unique_id
    matched_rule_ids JSONB DEFAULT '[]'::jsonb,     -- Array of all triggered CRS Rule IDs
    root_rule_id INT,                               -- Primary offending CRS Rule ID (e.g., 942100)
    root_rule_name TEXT,                            -- Descriptive label of primary CRS rule
    inbound_score INT DEFAULT 0,                    -- Cumulative inbound anomaly score (e.g., from 949110)
    disruptive_action VARCHAR(64),                  -- WAF action outcome: 'block' | 'allow' | 'none'
    interrupt_phase INT,                            -- ModSecurity evaluation phase of disruptive action (e.g., 2)
    waf_payload_snippet TEXT,                       -- Offending substring triggering the rule (messages.data)
    waf_matched_variable TEXT,                      -- Variable/parameter inspected (e.g., ARGS:username)
    raw_log_ref TEXT,                               -- Pointer or SHA-256 reference to raw audit.log entry

    -- Tier 3: Application Oracle Fields (Target App / Mock Internal State)
    app_received BOOLEAN DEFAULT FALSE,             -- Did the HTTP request reach the backend app?
    app_log_ref TEXT,                               -- Backend app log transaction trace ID
    oracle_observation TEXT,                        -- Oracle state diagnosis (e.g., unauthorized_session)

    -- Derived Evaluation Fields & Verdicts
    detected BOOLEAN DEFAULT FALSE,                 -- True if inbound_score >= threshold (default: 5)
    backend_effect BOOLEAN DEFAULT FALSE,           -- True if application oracle confirmed compromise
    validity VARCHAR(32) DEFAULT 'VALID',           -- VALID | E_HEALTH | E_FIXTURE | E_MODE | E_CORRELATION
    invalid_reason TEXT,                            -- Explanation if validity != 'VALID'
    verdict VARCHAR(32),                            -- PASS | FAIL | INVALID | INCONCLUSIVE
    metric_cell VARCHAR(32)                         -- TP_D, FN_D, TP_B, FN_B, FP_D, TN_D, FP_B, TN_B
);

-- ------------------------------------------------------------------------------
-- Table 4.6: Evaluation Metrics (Batch-level Aggregated Benchmark Results)
-- ------------------------------------------------------------------------------
CREATE TABLE evaluation_metrics (
    id SERIAL PRIMARY KEY,
    batch_id VARCHAR(64) UNIQUE NOT NULL,           -- Batch run identifier
    config_revision VARCHAR(64) NOT NULL DEFAULT 'C0', -- WAF config baseline: C0 (Default) or C1 (Tuned)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Pre-filtering & Sample Accounting
    total_attempted INT DEFAULT 0,                  -- Total probes dispatched
    total_evaluable INT DEFAULT 0,                  -- Cases passing baseline and validity gates
    total_invalid INT DEFAULT 0,                    -- Discarded due to environment/fixture fault
    total_inconclusive INT DEFAULT 0,               -- Undetermined state (excluded from BR denominator)

    -- Core Quantitative Benchmark KPIs
    detection_rate NUMERIC(5,2),                    -- DR = TP_D / (TP_D + FN_D) * 100%
    blocking_rate NUMERIC(5,2),                     -- BR = TP_B / (TP_B + FN_B) * 100%
    detection_fpr NUMERIC(5,2),                     -- Detection FPR = FP_D / (FP_D + TN_D) * 100%
    blocking_fpr NUMERIC(5,2),                      -- Blocking FPR = FP_B / (FP_B + TN_B) * 100%
    regression_pass_rate NUMERIC(5,2)               -- RPR = Pass_C1 / Total_C0 * 100%
);

-- ------------------------------------------------------------------------------
-- Performance & Query Optimization Indexes
-- ------------------------------------------------------------------------------
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_correlation_id ON normalized_events(correlation_id);
CREATE INDEX IF NOT EXISTS idx_events_batch_id ON normalized_events(batch_id);
CREATE INDEX IF NOT EXISTS idx_events_run_id ON normalized_events(run_id);
CREATE INDEX IF NOT EXISTS idx_events_case_id ON normalized_events(case_id);
CREATE INDEX IF NOT EXISTS idx_events_state ON normalized_events(state);
CREATE INDEX IF NOT EXISTS idx_events_verdict ON normalized_events(verdict);
CREATE INDEX IF NOT EXISTS idx_events_metric_cell ON normalized_events(metric_cell);
