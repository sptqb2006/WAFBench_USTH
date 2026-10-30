-- ==============================================================================
-- Normalized WAFBench Event Schema (PostgreSQL 16) - Bảng 4.3 & 4.6
-- ==============================================================================

DROP TABLE IF EXISTS evaluation_metrics;
DROP TABLE IF EXISTS normalized_events;

CREATE TABLE normalized_events (
    id SERIAL PRIMARY KEY,
    
    -- Identity Fields
    run_id VARCHAR(64) NOT NULL,
    batch_id VARCHAR(64),
    case_id VARCHAR(64) NOT NULL,
    family_id VARCHAR(64) NOT NULL,
    label VARCHAR(32) NOT NULL,              -- malicious / benign / edge
    state VARCHAR(32) NOT NULL,              -- Direct-to-App / DetectionOnly / Blocking
    repetition INT DEFAULT 1,
    correlation_id VARCHAR(64) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- WAF Telemetry Fields (from ModSecurity Audit Log)
    waf_txn_id VARCHAR(64),
    matched_rule_ids JSONB DEFAULT '[]'::jsonb,
    inbound_score INT DEFAULT 0,
    disruptive_action VARCHAR(64),           -- e.g., 'block', 'allow', 'none'
    interrupt_phase INT,
    audit_ref TEXT,

    -- Client Observation Fields (from Test Runner Capture)
    method VARCHAR(16),
    endpoint TEXT,
    client_status INT,
    request_sha256 VARCHAR(64),
    response_body_snippet TEXT,

    -- Application Oracle Fields (from Express app / mock-internal)
    app_received BOOLEAN DEFAULT FALSE,
    app_log_ref TEXT,
    oracle_observation TEXT,                 -- e.g., 'unauthorized_session_issued', 'etc_passwd_disclosed'

    -- Derived Evaluation Fields
    detected BOOLEAN DEFAULT FALSE,
    backend_effect BOOLEAN DEFAULT FALSE,
    validity VARCHAR(32) DEFAULT 'VALID',    -- VALID / E_HEALTH / E_FIXTURE / E_MODE / E_CORRELATION, etc.
    invalid_reason TEXT,
    verdict VARCHAR(32),                     -- PASS / FAIL / INVALID / INCONCLUSIVE
    metric_cell VARCHAR(32)                  -- TP_D, FN_D, TP_B, FN_B, FP_D, TN_D, FP_B, TN_B
);

-- Bảng lưu trữ chỉ số tổng hợp theo từng batch chạy
CREATE TABLE evaluation_metrics (
    id SERIAL PRIMARY KEY,
    batch_id VARCHAR(64) NOT NULL,
    config_revision VARCHAR(64) NOT NULL,    -- C0 or C1
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    total_attempted INT DEFAULT 0,
    total_evaluable INT DEFAULT 0,
    total_invalid INT DEFAULT 0,
    total_inconclusive INT DEFAULT 0,
    
    detection_rate NUMERIC(5,2),             -- DR = TP_D / (TP_D + FN_D)
    blocking_rate NUMERIC(5,2),              -- BR = TP_B / (TP_B + FN_B)
    detection_fpr NUMERIC(5,2),              -- Detection FPR = FP_D / (FP_D + TN_D)
    blocking_fpr NUMERIC(5,2),               -- Blocking FPR = FP_B / (FP_B + TN_B)
    regression_pass_rate NUMERIC(5,2)        -- RPR (nếu có C1)
);

-- Đánh Index tối ưu hóa truy vấn
CREATE INDEX idx_events_correlation_id ON normalized_events(correlation_id);
CREATE INDEX idx_events_run_id ON normalized_events(run_id);
CREATE INDEX idx_events_case_id ON normalized_events(case_id);
CREATE INDEX idx_events_state ON normalized_events(state);
CREATE INDEX idx_events_verdict ON normalized_events(verdict);
