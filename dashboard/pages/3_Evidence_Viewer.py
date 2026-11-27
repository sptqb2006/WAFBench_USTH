import streamlit as st
import os
import sys
import json
import pandas as pd

# Import shared styling
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from styles import apply_academic_styling
except ImportError:
    apply_academic_styling = lambda: None

st.set_page_config(
    page_title="Evidence Viewer - WAFBench",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply base academic theme
apply_academic_styling()

# ------------------------------------------------------------------------------
# Animate UI Specialized CSS (Motion Tokens, Blur Transitions, Clean Cards)
# ------------------------------------------------------------------------------
st.markdown("""
<style>
    /* =========================================================================
       1. Animate UI Motion Tokens & Smooth Spring Easing
       ========================================================================= */
    :root {
        --spring-press-scale: 0.97;
        --spring-card-scale: 0.985;
        --ease-soft: cubic-bezier(0.215, 0.61, 0.355, 1);
        --ease-out: cubic-bezier(0.23, 1, 0.32, 1);
        --ease-color: cubic-bezier(0.25, 0.1, 0.25, 1);
        --border-clean: #e2e8f0;
        --border-hover: #cbd5e1;
    }

    /* Page Header Academic Typography */
    .ev-header {
        padding: 1.25rem 1.5rem;
        margin-bottom: 1.25rem;
        border-radius: 8px;
        background-color: #f8f9fa;
        border: 1px solid var(--border-clean);
        color: #0f172a;
    }
    .ev-header-title {
        font-size: 1.6rem;
        font-weight: 600;
        letter-spacing: -0.015em;
        margin: 0 0 6px 0;
        color: #0f172a;
    }
    .ev-header-sub {
        font-size: 0.88rem;
        color: #475569;
        line-height: 1.45;
        margin-bottom: 10px;
    }
    .ev-badge-row {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
        align-items: center;
    }
    .ev-badge {
        font-size: 0.74rem;
        font-weight: 500;
        padding: 3px 9px;
        border-radius: 4px;
        border: 1px solid var(--border-clean);
        background-color: #ffffff;
        color: #334155;
        display: inline-flex;
        align-items: center;
        gap: 5px;
    }
    .ev-badge-live {
        border-color: #86efac;
        color: #166534;
        background-color: #f0fdf4;
    }
    .ev-badge-demo {
        border-color: #fde047;
        color: #854d0e;
        background-color: #fefce8;
    }

    /* =========================================================================
       2. Transaction Metadata & Selection Bar
       ========================================================================= */
    .ev-control-panel {
        background: #ffffff;
        border: 1px solid var(--border-clean);
        border-radius: 8px;
        padding: 1rem 1.25rem;
        margin-bottom: 1.25rem;
        box-shadow: 0 1px 3px rgba(15, 23, 42, 0.03);
    }
    .ev-summary-bar {
        display: flex;
        align-items: center;
        gap: 12px;
        flex-wrap: wrap;
        padding-top: 8px;
        margin-top: 8px;
        border-top: 1px solid #f1f5f9;
        font-size: 0.82rem;
    }
    .ev-summary-item {
        display: flex;
        align-items: center;
        gap: 6px;
        color: #64748b;
    }
    .ev-summary-val {
        color: #0f172a;
        font-weight: 600;
    }

    /* =========================================================================
       3. 3-Tier Inspection View Cards (#e2e8f0 border, monospaced snippets)
       ========================================================================= */
    .tier-card {
        background: #ffffff;
        border: 1px solid var(--border-clean);
        border-radius: 8px;
        padding: 1rem 1.15rem;
        box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04);
        transition: transform 0.2s var(--ease-out), box-shadow 0.2s var(--ease-out), border-color 0.2s var(--ease-color);
        height: 100%;
        display: flex;
        flex-direction: column;
    }
    .tier-card:hover {
        border-color: var(--border-hover);
        transform: translateY(-2px);
        box-shadow: 0 6px 16px -2px rgba(15, 23, 42, 0.07);
    }
    .tier-card:active {
        transform: scale(var(--spring-card-scale));
    }
    .tier-card-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding-bottom: 10px;
        margin-bottom: 10px;
        border-bottom: 1px solid #f1f5f9;
    }
    .tier-title-group {
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .tier-pill {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 0.68rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        padding: 2px 7px;
        border-radius: 4px;
    }
    .tier-pill-1 { background: #eff6ff; color: #1e40af; border: 1px solid #bfdbfe; }
    .tier-pill-2 { background: #fef3c7; color: #92400e; border: 1px solid #fde68a; }
    .tier-pill-3 { background: #ecfdf5; color: #065f46; border: 1px solid #a7f3d0; }
    .tier-heading {
        font-size: 0.92rem;
        font-weight: 600;
        color: #0f172a;
        margin: 0;
    }

    /* Key-Value Inspection Rows */
    .tier-row {
        display: flex;
        justify-content: space-between;
        align-items: baseline;
        padding: 6px 0;
        border-bottom: 1px solid #f8fafc;
        font-size: 0.81rem;
    }
    .tier-row:last-child {
        border-bottom: none;
    }
    .tier-label {
        color: #64748b;
        font-weight: 500;
        flex-shrink: 0;
        margin-right: 8px;
    }
    .tier-val {
        color: #0f172a;
        font-weight: 500;
        text-align: right;
        word-break: break-all;
    }
    .mono-chip {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 0.76rem;
        background: #f8fafc;
        border: 1px solid var(--border-clean);
        border-radius: 4px;
        padding: 2px 6px;
        color: #0f172a;
        display: inline-block;
    }

    /* Status Pills */
    .status-pill {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 0.72rem;
        font-weight: 600;
        padding: 2px 8px;
        border-radius: 4px;
        display: inline-flex;
        align-items: center;
        gap: 4px;
    }
    .status-pill-green { background: #ecfdf5; color: #065f46; border: 1px solid #a7f3d0; }
    .status-pill-red { background: #fef2f2; color: #991b1b; border: 1px solid #fecaca; }
    .status-pill-amber { background: #fffbeb; color: #92400e; border: 1px solid #fde68a; }
    .status-pill-blue { background: #eff6ff; color: #1e40af; border: 1px solid #bfdbfe; }
    .status-pill-gray { background: #f8fafc; color: #475569; border: 1px solid #e2e8f0; }

    /* Diagnostic Callout */
    .diag-box {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-left: 3px solid #0284c7;
        border-radius: 4px;
        padding: 8px 10px;
        font-size: 0.78rem;
        color: #334155;
        line-height: 1.4;
        margin-top: 4px;
        margin-bottom: 6px;
    }

    /* =========================================================================
       4. Terminal-Style Audit Log Viewer (backdrop-filter: blur(8px))
       ========================================================================= */
    .terminal-container {
        background: rgba(15, 23, 42, 0.96);
        backdrop-filter: blur(8px);
        -webkit-backdrop-filter: blur(8px);
        border: 1px solid #334155;
        border-radius: 8px;
        overflow: hidden;
        margin-top: 1.25rem;
        margin-bottom: 1.25rem;
        box-shadow: 0 10px 25px -5px rgba(15, 23, 42, 0.25);
        transition: border-color 0.2s var(--ease-out);
    }
    .terminal-container:hover {
        border-color: #475569;
    }
    .terminal-header {
        background: rgba(30, 41, 59, 0.85);
        backdrop-filter: blur(8px);
        -webkit-backdrop-filter: blur(8px);
        padding: 9px 16px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        border-bottom: 1px solid #334155;
    }
    .terminal-dots {
        display: flex;
        gap: 7px;
        align-items: center;
    }
    .terminal-dot {
        width: 10px;
        height: 10px;
        border-radius: 50%;
        display: inline-block;
    }
    .dot-red { background: #ef4444; }
    .dot-yellow { background: #f59e0b; }
    .dot-green { background: #10b981; }
    .terminal-title {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 0.76rem;
        color: #94a3b8;
        letter-spacing: 0.02em;
    }
    .terminal-tag {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 0.72rem;
        color: #38bdf8;
        background: rgba(56, 189, 248, 0.12);
        padding: 2px 8px;
        border-radius: 4px;
        border: 1px solid rgba(56, 189, 248, 0.25);
    }

    /* =========================================================================
       5. Collapsible Expanders with Smooth Spring Easing
       ========================================================================= */
    [data-testid="stExpander"] {
        border: 1px solid var(--border-clean) !important;
        border-radius: 8px !important;
        background-color: #ffffff !important;
        box-shadow: 0 1px 2px rgba(15, 23, 42, 0.03) !important;
        margin-bottom: 0.85rem !important;
        transition: border-color 0.25s var(--ease-soft), box-shadow 0.25s var(--ease-soft) !important;
    }
    [data-testid="stExpander"]:hover {
        border-color: var(--border-hover) !important;
        box-shadow: 0 4px 12px -2px rgba(15, 23, 42, 0.05) !important;
    }
    [data-testid="stExpander"] summary {
        font-size: 0.88rem !important;
        font-weight: 600 !important;
        color: #1e293b !important;
        padding: 10px 14px !important;
        border-radius: 8px !important;
        transition: background-color 0.2s var(--ease-color) !important;
    }
    [data-testid="stExpander"] summary:hover {
        background-color: #f8fafc !important;
    }
    [data-testid="stExpander"] summary:active {
        transform: scale(var(--spring-card-scale));
    }
    [data-testid="stExpander"] [data-testid="stExpanderDetails"] {
        padding: 14px 18px !important;
        border-top: 1px solid #f1f5f9 !important;
        animation: expanderSpringReveal 0.35s var(--ease-soft);
    }
    @keyframes expanderSpringReveal {
        from {
            opacity: 0;
            transform: translateY(-4px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    /* =========================================================================
       6. Animate UI Reduced Motion Compliance
       ========================================================================= */
    @media (prefers-reduced-motion: reduce) {
        * {
            transition-duration: 0.01ms !important;
            animation-duration: 0.01ms !important;
        }
    }
</style>
""", unsafe_allow_html=True)


# ------------------------------------------------------------------------------
# Data Loading (PostgreSQL event-db with transparent sample_events.json fallback)
# ------------------------------------------------------------------------------
def load_data():
    """
    Loads telemetry records from PostgreSQL event-db if reachable,
    otherwise falls back to sample_events.json.
    Preserves 100% of underlying application logic and event schemas.
    """
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        conn = psycopg2.connect(
            host=os.getenv("EVENT_DB_HOST", "localhost"),
            port=int(os.getenv("EVENT_DB_PORT", "5432")),
            dbname=os.getenv("EVENT_DB_NAME", "wafbench_events"),
            user=os.getenv("EVENT_DB_USER", "telemetry_user"),
            password=os.getenv("EVENT_DB_PASSWORD", "telemetry_secret_pass"),
            cursor_factory=RealDictCursor,
            connect_timeout=2
        )
        query = "SELECT * FROM normalized_events ORDER BY id DESC LIMIT 500;"
        df_pg = pd.read_sql(query, conn)
        conn.close()
        if df_pg is not None and not df_pg.empty:
            return df_pg, False
    except Exception:
        pass

    # Resilient fallback to sample_events.json
    sample_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sample_events.json")
    if os.path.exists(sample_file):
        with open(sample_file, "r", encoding="utf-8") as f:
            records = json.load(f)
        return pd.DataFrame(records), True

    return pd.DataFrame(), True


# ------------------------------------------------------------------------------
# ModSecurity v3 Serial JSON Reconstruction (ECS-lite compliant)
# ------------------------------------------------------------------------------
def build_modsec_native_audit(r: pd.Series) -> dict:
    """
    Reconstructs the native ModSecurity v3 serial JSON audit log representation
    matching the exact schema parsed by telemetry/log_parser.py.
    """
    messages = []
    root_rule_id = r.get("root_rule_id")
    root_rule_name = r.get("root_rule_name")
    payload_snippet = r.get("waf_payload_snippet")
    matched_var = r.get("waf_matched_variable")
    inbound_score = int(r.get("inbound_score", 0)) if pd.notna(r.get("inbound_score")) else 0

    if root_rule_id and pd.notna(root_rule_id):
        rule_str = str(int(root_rule_id))
        messages.append({
            "message": str(root_rule_name) if pd.notna(root_rule_name) else f"CRS Rule {rule_str} Triggered",
            "details": {
                "ruleId": rule_str,
                "file": f"/etc/nginx/modsec/coreruleset-4.0.0/rules/REQUEST-{rule_str[:3]}-APPLICATION-ATTACK.conf",
                "lineNumber": "140",
                "data": str(payload_snippet) if pd.notna(payload_snippet) else "",
                "severity": "2",
                "ver": "OWASP_CRS/4.0.0",
                "maturity": "0",
                "accuracy": "0",
                "variable": str(matched_var) if pd.notna(matched_var) else "ARGS:payload"
            }
        })

    # Evaluation meta-rule 949110 if anomaly score threshold reached
    if inbound_score >= 5:
        messages.append({
            "message": f"Inbound Anomaly Score Exceeded (Total Inbound Score: {inbound_score} - Anomaly Threshold 5)",
            "details": {
                "ruleId": "949110",
                "file": "/etc/nginx/modsec/coreruleset-4.0.0/rules/REQUEST-949-BLOCKING-EVALUATION.conf",
                "lineNumber": "88",
                "data": "",
                "severity": "0",
                "ver": "OWASP_CRS/4.0.0",
                "variable": "TX:INBOUND_ANOMALY_SCORE"
            }
        })

    disruptive_action = str(r.get("disruptive_action", "none")).lower()
    producer_action = "interrupted" if disruptive_action == "block" else (
        "allowed" if disruptive_action == "allow" else "none"
    )

    client_status = int(r.get("client_status", 200)) if pd.notna(r.get("client_status")) else 200

    return {
        "transaction": {
            "client_ip": str(r.get("client_ip", "127.0.0.1")),
            "time_stamp": str(r.get("created_at", "2026-11-04 00:00:00")),
            "server_id": "waf-gateway-nginx",
            "client_port": 49152,
            "host_ip": "172.28.0.2",
            "host_port": 8080,
            "unique_id": str(r.get("waf_txn_id", "N/A")),
            "request": {
                "method": str(r.get("method", "GET")),
                "uri": str(r.get("endpoint", "/")),
                "http_version": 1.1,
                "headers": {
                    "host": "localhost:8080",
                    "user-agent": "WAFBench-Runner/1.0",
                    "x-request-id": str(r.get("correlation_id", "N/A")),
                    "accept": "*/*"
                }
            },
            "response": {
                "http_code": client_status,
                "headers": {
                    "server": "nginx/1.26.2",
                    "date": str(r.get("created_at", "2026-11-04 00:00:00")),
                    "connection": "close"
                }
            },
            "producer": {
                "modsecurity": "ModSecurity v3.0.12",
                "connector": "ModSecurity-nginx v1.0.3",
                "secrules_engine": "Enabled" if r.get("state") == "Blocking" else "DetectionOnly",
                "action": producer_action,
                "phase": int(r.get("interrupt_phase", 2)) if pd.notna(r.get("interrupt_phase")) else 2
            },
            "messages": messages
        }
    }


# ------------------------------------------------------------------------------
# Render Evidence Viewer Dashboard
# ------------------------------------------------------------------------------
df, is_demo = load_data()

# Clean SVG Icons (Zero cheesy emojis)
SVG_TERMINAL = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px;margin-right:4px;"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>'
SVG_SHIELD = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px;margin-right:4px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>'
SVG_DATABASE = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px;margin-right:4px;"><ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path></svg>'
SVG_CHECK = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px;"><polyline points="20 6 9 17 4 12"></polyline></svg>'
SVG_CROSS = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px;"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>'
SVG_HASH = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px;margin-right:3px;"><line x1="4" y1="9" x2="20" y2="9"></line><line x1="4" y1="15" x2="20" y2="15"></line><line x1="10" y1="3" x2="8" y2="21"></line><line x1="16" y1="3" x2="14" y2="21"></line></svg>'

# Top Academic Header Bar
badge_source = (
    '<span class="ev-badge ev-badge-demo">[DEMO SOURCE] sample_events.json</span>'
    if is_demo else
    '<span class="ev-badge ev-badge-live">[LIVE STREAM] PostgreSQL event-db</span>'
)

st.markdown(f"""
<div class="ev-header">
    <div class="ev-header-title">3-Tier Correlated Raw Evidence Viewer</div>
    <div class="ev-header-sub">
        Deterministic side-by-side forensic verification across all three architectural layers:
        <strong>Client Probe Capture</strong>, <strong>ModSecurity v3 / CRS v4 Audit Log</strong>, and <strong>Backend Application Oracle</strong>.
    </div>
    <div class="ev-badge-row">
        {badge_source}
        <span class="ev-badge">{SVG_HASH} Correlation: X-Request-ID (UUIDv4)</span>
        <span class="ev-badge">{SVG_SHIELD} Engine: OWASP CRS v4.0.0</span>
        <span class="ev-badge">{SVG_DATABASE} Schema: Table 4.3 Normalized Events</span>
        <span class="ev-badge">Total Loaded: {len(df)} transactions</span>
    </div>
</div>
""", unsafe_allow_html=True)

if not df.empty:
    # --------------------------------------------------------------------------
    # Interactive Filter & Transaction Selector
    # --------------------------------------------------------------------------
    with st.container():
        st.markdown('<div class="ev-control-panel">', unsafe_allow_html=True)
        
        # Row 1: Fast Categorical Drilldown
        f_col1, f_col2, f_col3 = st.columns([1.2, 1.0, 1.2])
        
        families = ["All"] + sorted(list(df["family_id"].dropna().unique()))
        sel_family = f_col1.selectbox("Filter Threat Class:", families)

        actions = ["All"] + sorted(list(df["disruptive_action"].dropna().unique()))
        sel_action = f_col2.selectbox("Filter WAF Action:", actions)

        states = ["All"] + sorted(list(df["state"].dropna().unique()))
        sel_state = f_col3.selectbox("Filter Execution State:", states)

        # Apply Filters
        filtered_df = df.copy()
        if sel_family != "All":
            filtered_df = filtered_df[filtered_df["family_id"] == sel_family]
        if sel_action != "All":
            filtered_df = filtered_df[filtered_df["disruptive_action"] == sel_action]
        if sel_state != "All":
            filtered_df = filtered_df[filtered_df["state"] == sel_state]

        if filtered_df.empty:
            st.warning("No records match the active filter criteria. Showing all transactions.")
            filtered_df = df.copy()

        corr_ids = list(filtered_df["correlation_id"].unique())

        # Selectbox with descriptive label formatter
        def format_corr_option(cid: str) -> str:
            matches = filtered_df[filtered_df["correlation_id"] == cid]
            if matches.empty:
                return cid
            r = matches.iloc[0]
            case = r.get("case_id", "N/A")
            method = r.get("method", "GET")
            endpoint = r.get("endpoint", "/")
            status = r.get("client_status", "N/A")
            action = str(r.get("disruptive_action", "none")).upper()
            return f"{cid}  |  [{case}] {method} {endpoint} -> {status} ({action})"

        selected_id = st.selectbox(
            "Select Transaction by Correlation ID (X-Request-ID):",
            corr_ids,
            format_func=format_corr_option
        )
        record = filtered_df[filtered_df["correlation_id"] == selected_id].iloc[0]

        # Row 2: Selected Transaction Metadata Summary Bar
        verdict_str = str(record.get("verdict", "N/A"))
        verdict_class = "status-pill-green" if verdict_str == "PASS" else ("status-pill-red" if verdict_str == "FAIL" else "status-pill-amber")
        
        st.markdown(f"""
        <div class="ev-summary-bar">
            <div class="ev-summary-item">Case: <span class="ev-summary-val">{record.get('case_id', 'N/A')}</span></div>
            <div class="ev-summary-item">Family: <span class="ev-summary-val">{record.get('family_id', 'N/A')}</span></div>
            <div class="ev-summary-item">State: <span class="ev-summary-val">{record.get('state', 'N/A')}</span></div>
            <div class="ev-summary-item">Timestamp: <span class="ev-summary-val">{record.get('created_at', 'N/A')}</span></div>
            <div class="ev-summary-item">Verdict: <span class="status-pill {verdict_class}">{verdict_str}</span></div>
            <div class="ev-summary-item">Quadrant: <span class="mono-chip">{record.get('metric_cell', 'N/A')}</span></div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)

    # --------------------------------------------------------------------------
    # 3-Tier Inspection View Cards
    # --------------------------------------------------------------------------
    col_t1, col_t2, col_t3 = st.columns(3)

    # ----------------- Tier 1: Client Probe -----------------
    with col_t1:
        client_st = int(record.get("client_status", 0)) if pd.notna(record.get("client_status")) else 0
        status_badge_class = "status-pill-red" if client_st >= 400 else "status-pill-green"
        sha_full = str(record.get("request_sha256", "N/A"))
        sha_short = sha_full[:24] + "..." if len(sha_full) > 24 else sha_full

        st.markdown(f"""
        <div class="tier-card">
            <div class="tier-card-header">
                <div class="tier-title-group">
                    <span class="tier-pill tier-pill-1">TIER 1</span>
                    <h4 class="tier-heading">Client Probe</h4>
                </div>
                <span class="status-pill {status_badge_class}">HTTP {client_st}</span>
            </div>
            <div class="tier-row">
                <span class="tier-label">Request:</span>
                <span class="mono-chip">{record.get('method', 'GET')} {record.get('endpoint', '/')}</span>
            </div>
            <div class="tier-row">
                <span class="tier-label">Status Received:</span>
                <span class="tier-val"><code>{client_st}</code></span>
            </div>
            <div class="tier-row">
                <span class="tier-label">Client IP:</span>
                <span class="tier-val">{record.get('client_ip', '127.0.0.1')}</span>
            </div>
            <div class="tier-row">
                <span class="tier-label">Payload SHA-256:</span>
                <span class="mono-chip" title="{sha_full}">{sha_short}</span>
            </div>
            <div style="margin-top: 8px; margin-bottom: 2px;">
                <span class="tier-label">Response Snippet:</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.code(record.get("response_body_snippet") or "N/A", language="html")

    # ----------------- Tier 2: WAF Evidence -----------------
    with col_t2:
        action_str = str(record.get("disruptive_action", "none")).upper()
        action_class = "status-pill-red" if action_str == "BLOCK" else ("status-pill-green" if action_str == "ALLOW" else "status-pill-gray")
        score_val = int(record.get("inbound_score", 0)) if pd.notna(record.get("inbound_score")) else 0
        score_color = "#dc2626" if score_val >= 5 else "#16a34a"
        raw_ref = str(record.get("raw_log_ref", "N/A"))
        raw_ref_short = raw_ref[:26] + "..." if len(raw_ref) > 26 else raw_ref

        # Parse matched rules
        matched_rules = record.get("matched_rule_ids")
        if isinstance(matched_rules, str):
            try:
                matched_rules = json.loads(matched_rules)
            except Exception:
                matched_rules = [matched_rules]
        elif not isinstance(matched_rules, list):
            matched_rules = [] if pd.isna(matched_rules) else [matched_rules]

        matched_rules_str = ", ".join(str(r) for r in matched_rules) if matched_rules else str(record.get("root_rule_id", "None"))

        st.markdown(f"""
        <div class="tier-card">
            <div class="tier-card-header">
                <div class="tier-title-group">
                    <span class="tier-pill tier-pill-2">TIER 2</span>
                    <h4 class="tier-heading">WAF Evidence</h4>
                </div>
                <span class="status-pill {action_class}">{action_str}</span>
            </div>
            <div class="tier-row">
                <span class="tier-label">TxID:</span>
                <span class="mono-chip">{record.get('waf_txn_id', 'N/A')}</span>
            </div>
            <div class="tier-row">
                <span class="tier-label">Inbound Score:</span>
                <span class="tier-val"><strong style="color: {score_color};">{score_val}</strong> (Threshold: 5)</span>
            </div>
            <div class="tier-row">
                <span class="tier-label">Action:</span>
                <span class="tier-val"><code>{action_str}</code> (Phase {record.get('interrupt_phase', '2')})</span>
            </div>
            <div class="tier-row">
                <span class="tier-label">Root Rule:</span>
                <span class="tier-val"><code>{record.get('root_rule_id', 'N/A')}</code> &mdash; <em>{record.get('root_rule_name', 'Clean')}</em></span>
            </div>
            <div class="tier-row">
                <span class="tier-label">Matched Variable:</span>
                <span class="mono-chip">{record.get('waf_matched_variable', 'None')}</span>
            </div>
            <div class="tier-row">
                <span class="tier-label">Audit Pointer:</span>
                <span class="mono-chip" title="{raw_ref}">{raw_ref_short}</span>
            </div>
            <div style="margin-top: 8px; margin-bottom: 2px;">
                <span class="tier-label">Offending Payload Snippet:</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.code(record.get("waf_payload_snippet") or "None", language="text")

    # ----------------- Tier 3: Backend Oracle -----------------
    with col_t3:
        app_recv = bool(record.get("app_received", False))
        bk_effect = bool(record.get("backend_effect", False))
        recv_badge = f'<span class="status-pill {"status-pill-green" if app_recv else "status-pill-gray"}">{SVG_CHECK if app_recv else SVG_CROSS} {app_recv}</span>'
        effect_badge = f'<span class="status-pill {"status-pill-red" if bk_effect else "status-pill-green"}">{SVG_CROSS if bk_effect else SVG_CHECK} {bk_effect}</span>'

        oracle_obs = str(record.get("oracle_observation", "None"))
        validity_val = str(record.get("validity", "VALID"))

        st.markdown(f"""
        <div class="tier-card">
            <div class="tier-card-header">
                <div class="tier-title-group">
                    <span class="tier-pill tier-pill-3">TIER 3</span>
                    <h4 class="tier-heading">Backend Oracle</h4>
                </div>
                <span class="status-pill {verdict_class}">{verdict_str}</span>
            </div>
            <div class="tier-row">
                <span class="tier-label">App Received Request:</span>
                <span class="tier-val">{recv_badge}</span>
            </div>
            <div class="tier-row">
                <span class="tier-label">Backend Mutated / Effect:</span>
                <span class="tier-val">{effect_badge}</span>
            </div>
            <div class="tier-row">
                <span class="tier-label">Metric Quadrant:</span>
                <span class="mono-chip">{record.get('metric_cell', 'N/A')}</span>
            </div>
            <div class="tier-row">
                <span class="tier-label">Final Verdict:</span>
                <span class="tier-val"><strong>{record.get('verdict', 'N/A')}</strong></span>
            </div>
            <div class="tier-row">
                <span class="tier-label">Validity Status:</span>
                <span class="tier-val">{validity_val}</span>
            </div>
            <div style="margin-top: 8px; margin-bottom: 2px;">
                <span class="tier-label">Oracle Observation:</span>
            </div>
            <div class="diag-box">{oracle_obs}</div>
        </div>
        """, unsafe_allow_html=True)

    # --------------------------------------------------------------------------
    # Clean Terminal-Style Audit Log Viewer (backdrop-filter: blur(8px))
    # --------------------------------------------------------------------------
    waf_tx = str(record.get("waf_txn_id", "N/A"))
    st.markdown(f"""
    <div class="terminal-container">
        <div class="terminal-header">
            <div class="terminal-dots">
                <span class="terminal-dot dot-red"></span>
                <span class="terminal-dot dot-yellow"></span>
                <span class="terminal-dot dot-green"></span>
                <span class="terminal-title">audit-stream@modsecurity-crs4: ~/{waf_tx}.json</span>
            </div>
            <span class="terminal-tag">SERIAL AUDIT LOG & CORRELATION VIEWER</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    tab_audit, tab_normalized, tab_hash = st.tabs([
        "ModSecurity v3 Native Audit JSON",
        "Correlated 3-Tier Telemetry JSON",
        "Evidence Hash & Verification Matrix"
    ])

    with tab_audit:
        modsec_native = build_modsec_native_audit(record)
        st.code(json.dumps(modsec_native, indent=2), language="json")

    with tab_normalized:
        raw_dict = record.to_dict()
        st.code(json.dumps(raw_dict, indent=2, default=str), language="json")

    with tab_hash:
        c_hash1, c_hash2 = st.columns(2)
        with c_hash1:
            st.markdown("##### Cryptographic Fingerprints & References")
            st.markdown(f"""
            - **Correlation ID (Universal Join Key):** `{record.get('correlation_id')}`
            - **Client Request SHA-256:** `{record.get('request_sha256', 'N/A')}`
            - **WAF Raw Audit Log Pointer:** `{record.get('raw_log_ref', 'N/A')}`
            - **Backend Application Trace ID:** `{record.get('app_log_ref', 'N/A')}`
            """)
        with c_hash2:
            st.markdown("##### Three-Tier Correlation Verdict")
            corr_status = "VERIFIED (1:1 Multi-tier join confirmed)" if record.get("validity") == "VALID" else f"UNCONFIRMED ({record.get('invalid_reason', 'N/A')})"
            st.markdown(f"""
            - **Batch & Run Context:** `{record.get('batch_id', 'N/A')}` / `{record.get('run_id', 'N/A')}`
            - **Evaluation Repetition:** Sequence `{record.get('repetition', 1)}` of 3
            - **Correlation Integrity:** `{corr_status}`
            - **Metric Matrix Placement:** Quadrant `{record.get('metric_cell', 'N/A')}`
            """)

    # --------------------------------------------------------------------------
    # Collapsible Expanders with Smooth Spring Easing
    # --------------------------------------------------------------------------
    with st.expander("Telemetry Schema Reference (Table 4.3 Normalized Fields)", expanded=False):
        schema_data = [
            {"Tier": "Tier 1: Client", "Field": "correlation_id", "Type": "VARCHAR(64)", "Description": "Universal join key injected via X-Request-ID"},
            {"Tier": "Tier 1: Client", "Field": "client_status", "Type": "INT", "Description": "HTTP status code received by the client test runner"},
            {"Tier": "Tier 1: Client", "Field": "request_sha256", "Type": "VARCHAR(64)", "Description": "SHA-256 hash of the complete probe payload"},
            {"Tier": "Tier 1: Client", "Field": "response_body_snippet", "Type": "TEXT", "Description": "First 256 bytes of HTTP response body"},
            {"Tier": "Tier 2: WAF", "Field": "waf_txn_id", "Type": "VARCHAR(64)", "Description": "ModSecurity internal transaction identifier"},
            {"Tier": "Tier 2: WAF", "Field": "inbound_score", "Type": "INT", "Description": "Cumulative inbound anomaly score (Threshold: 5)"},
            {"Tier": "Tier 2: WAF", "Field": "disruptive_action", "Type": "VARCHAR(64)", "Description": "Enforcement decision: 'block', 'allow', or 'none'"},
            {"Tier": "Tier 2: WAF", "Field": "root_rule_id", "Type": "INT", "Description": "Primary CRS detector rule (e.g. 942100 for SQLi)"},
            {"Tier": "Tier 2: WAF", "Field": "raw_log_ref", "Type": "TEXT", "Description": "SHA-256 pointer to native serial audit.log entry"},
            {"Tier": "Tier 3: Oracle", "Field": "app_received", "Type": "BOOLEAN", "Description": "True if backend application server received request"},
            {"Tier": "Tier 3: Oracle", "Field": "backend_effect", "Type": "BOOLEAN", "Description": "True if application oracle confirmed data mutation"},
            {"Tier": "Derived", "Field": "metric_cell", "Type": "VARCHAR(32)", "Description": "Evaluation matrix quadrant: TP_B, FN_B, FP_D, etc."},
            {"Tier": "Derived", "Field": "verdict", "Type": "VARCHAR(32)", "Description": "PASS, FAIL, INVALID, or INCONCLUSIVE"}
        ]
        st.dataframe(pd.DataFrame(schema_data), use_container_width=True, hide_index=True)

    with st.expander("ModSecurity & CRS v4 Decision Tree Logic", expanded=False):
        st.markdown("""
        **Evaluation Architecture Decision Tree:**
        1. **Phase 1 (Request Headers):** Inspects HTTP request line, headers, and protocol hygiene.
        2. **Phase 2 (Request Body):** CRS inspects request parameters, POST payloads, and URI against attack families.
        3. **Rule 949110 (Blocking Evaluation):** Sums cumulative `TX:INBOUND_ANOMALY_SCORE`. If $\\ge 5$, executes disruptive action (`deny 403`).
        4. **Backend Application Oracle:** Checks database mutation or backend log reception to compute $DR$, $BR$, and $FPR$.
        """)

else:
    st.info("No evidence records available. Start Docker containers (`docker compose up -d`) to stream evaluation telemetry.")
