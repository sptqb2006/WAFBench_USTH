#!/usr/bin/env python3
"""
WAFBench Analytics Dashboard (Streamlit :8501)
Academic & Forensic Evaluation Console
"""

import os
import sys
import json

# Ensure telemetry modules can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "telemetry")))

try:
    import streamlit as st
    import pandas as pd
    STREAMLIT_AVAILABLE = True
except ImportError:
    STREAMLIT_AVAILABLE = False

from styles import apply_academic_styling


def load_data():
    """
    Loads telemetry events from PostgreSQL event-db if reachable;
    otherwise falls back automatically to sample_events.json (Demo Mode).
    """
    # 1. Attempt connection to PostgreSQL event-db
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
        import pandas as pd
        df = pd.read_sql(query, conn)
        conn.close()
        if df is not None and not df.empty:
            return df, False  # Live stream from PostgreSQL
    except Exception:
        pass

    # 2. Resilient Fallback to sample_events.json (Demo Mode)
    sample_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_events.json")
    if os.path.exists(sample_file):
        with open(sample_file, "r", encoding="utf-8") as f:
            records = json.load(f)
        if STREAMLIT_AVAILABLE:
            import pandas as pd
            return pd.DataFrame(records), True  # Fallback Demo Data
        return records, True

    return None, False


def render_streamlit_dashboard():
    """Renders the clean, academic evaluation dashboard."""
    st.set_page_config(
        page_title="WAFBench Evaluation Platform",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    apply_academic_styling()
    df, is_demo = load_data()

    # 1. Academic Header Bar
    badge_status = (
        '<span class="academic-badge academic-badge-demo">[DEMO MODE] sample_events.json</span>'
        if is_demo else
        '<span class="academic-badge academic-badge-live">[LIVE STREAM] event-db connected</span>'
    )

    st.markdown(f"""
    <div class="academic-header">
        <div style="font-size: 1.75rem; font-weight: 600; margin: 0 0 4px 0;">
            WAFBench: Empirical WAF Evaluation & Forensic Telemetry Console
        </div>
        <div style="font-size: 0.9rem; opacity: 0.8;">
            Three-tier correlated evaluation framework for Nginx 1.26 + ModSecurity v3 + OWASP Core Rule Set (CRS v4.0.0).
        </div>
        <div class="academic-badge-row">
            {badge_status}
            <span class="academic-badge">Target Profile: C0 Baseline</span>
            <span class="academic-badge">CRS Paranoia: PL1</span>
            <span class="academic-badge">Inbound Anomaly Threshold: 5</span>
            <span class="academic-badge">Evaluation Mode: Blocking / DetectionOnly</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    if df is None or df.empty:
        st.warning("No evaluation events found. Start Docker services (`docker compose up -d`) to begin streaming.")
        return

    # 2. Summary KPI Metric Cards
    total_probes = len(df)
    http_403_count = len(df[df["client_status"] == 403])
    waf_blocks_count = len(df[df["disruptive_action"] == "block"])

    tp_b = len(df[df["metric_cell"] == "TP_B"])
    fn_b = len(df[df["metric_cell"] == "FN_B"])
    br = (tp_b / (tp_b + fn_b) * 100) if (tp_b + fn_b) > 0 else 0.0

    tp_d = len(df[df["metric_cell"] == "TP_D"])
    fn_d = len(df[df["metric_cell"] == "FN_D"])
    dr = (tp_d / (tp_d + fn_d) * 100) if (tp_d + fn_d) > 0 else 0.0

    inconclusive_count = len(df[df["verdict"] == "INCONCLUSIVE"])
    evaluable_count = total_probes - inconclusive_count

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Total Probes Dispatched</div>
            <div class="metric-value">{total_probes}</div>
            <div class="metric-subtitle">{evaluable_count} evaluable / {inconclusive_count} inconclusive</div>
        </div>
        """, unsafe_allow_html=True)

    with m2:
        pct_403 = (http_403_count / total_probes * 100) if total_probes > 0 else 0
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Perimeter Denials (HTTP 403)</div>
            <div class="metric-value">{http_403_count}</div>
            <div class="metric-subtitle">{pct_403:.1f}% client-observed denials</div>
        </div>
        """, unsafe_allow_html=True)

    with m3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">WAF Verified Blocks</div>
            <div class="metric-value">{waf_blocks_count}</div>
            <div class="metric-subtitle">Confirmed ModSecurity audit evidence</div>
        </div>
        """, unsafe_allow_html=True)

    with m4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Empirical Blocking Rate (BR)</div>
            <div class="metric-value">{br:.1f}%</div>
            <div class="metric-subtitle">{tp_b} enforced / {tp_b+fn_b} evaluable malicious</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # 3. Clean Multi-Dimensional Filters
    with st.container(border=True):
        f1, f2, f3, f4, f5 = st.columns([1.2, 1.2, 1.2, 1.0, 1.4])
        endpoints = ["All"] + sorted(list(df["endpoint"].dropna().unique()))
        sel_endpoint = f1.selectbox("Target Endpoint", endpoints)

        families = ["All"] + sorted(list(df["family_id"].dropna().unique()))
        sel_family = f2.selectbox("Threat Class", families)

        actions = ["All"] + sorted(list(df["disruptive_action"].dropna().unique()))
        sel_action = f3.selectbox("WAF Action", actions)

        statuses = ["All"] + sorted([str(s) for s in df["client_status"].dropna().unique()])
        sel_status = f4.selectbox("Status Code", statuses)

        search_rule = f5.text_input("Search CRS Rule ID", "", placeholder="e.g. 942100")

    # Filter logic
    filtered_df = df.copy()
    if sel_endpoint != "All":
        filtered_df = filtered_df[filtered_df["endpoint"] == sel_endpoint]
    if sel_family != "All":
        filtered_df = filtered_df[filtered_df["family_id"] == sel_family]
    if sel_action != "All":
        filtered_df = filtered_df[filtered_df["disruptive_action"] == sel_action]
    if sel_status != "All":
        filtered_df = filtered_df[filtered_df["client_status"] == int(sel_status)]
    if search_rule.strip():
        filtered_df = filtered_df[
            filtered_df["root_rule_id"].astype(str).str.contains(search_rule.strip()) |
            filtered_df["matched_rule_ids"].astype(str).str.contains(search_rule.strip())
        ]

    st.caption(f"Showing **{len(filtered_df)}** of **{len(df)}** test records")

    # 4. Side-by-Side Normalized Event Stream & Forensic Drawer
    col_table, col_drawer = st.columns([3, 2])

    with col_table:
        st.markdown("##### Normalized Event Stream")
        display_cols = [
            "correlation_id", "case_id", "family_id", "state", "client_status",
            "disruptive_action", "inbound_score", "verdict", "metric_cell"
        ]
        available_cols = [c for c in display_cols if c in filtered_df.columns]
        st.dataframe(filtered_df[available_cols], use_container_width=True, height=450)

    with col_drawer:
        st.markdown("##### Forensic Inspection Drawer")
        if not filtered_df.empty:
            corr_ids = list(filtered_df["correlation_id"].unique())
            selected_corr = st.selectbox("Inspect Transaction (X-Request-ID):", corr_ids)
            event_row = filtered_df[filtered_df["correlation_id"] == selected_corr].iloc[0]

            # Block A: Client Observation
            st.markdown(f"""
            <div class="forensic-box">
                <div class="forensic-title">A. Client Observation</div>
                <div class="forensic-field"><b>Endpoint:</b> <code>{event_row.get('method', 'GET')} {event_row.get('endpoint', '')}</code></div>
                <div class="forensic-field"><b>HTTP Status:</b> <code>{event_row.get('client_status')}</code></div>
                <div class="forensic-field"><b>Correlation ID:</b> <code>{selected_corr}</code></div>
                <div class="forensic-field"><b>Payload SHA-256:</b> <code>{str(event_row.get('request_sha256', 'N/A'))[:24]}...</code></div>
            </div>
            """, unsafe_allow_html=True)

            # Block B: WAF Telemetry Evidence
            score_color = "#ef4444" if event_row.get("inbound_score", 0) >= 5 else "#10b981"
            st.markdown(f"""
            <div class="forensic-box">
                <div class="forensic-title">B. WAF ModSecurity Evidence</div>
                <div class="forensic-field"><b>WAF TxID:</b> <code>{event_row.get('waf_txn_id', 'N/A')}</code></div>
                <div class="forensic-field"><b>Disruptive Action:</b> <code>{str(event_row.get('disruptive_action')).upper()}</code> (Phase {event_row.get('interrupt_phase', 'N/A')})</div>
                <div class="forensic-field"><b>Anomaly Score:</b> <b style="color:{score_color};">{event_row.get('inbound_score', 0)}</b> / Threshold 5</div>
                <div class="forensic-field"><b>Root CRS Rule:</b> <code>{event_row.get('root_rule_id', 'N/A')}</code> - <i>{event_row.get('root_rule_name', 'Clean')}</i></div>
                <div class="forensic-field"><b>Matched Variable:</b> <code>{event_row.get('waf_matched_variable', 'None')}</code></div>
                <div class="forensic-field"><b>Offending Snippet:</b> <code>{event_row.get('waf_payload_snippet', 'None')}</code></div>
                <div class="forensic-field"><b>Audit Ref:</b> <code>{str(event_row.get('raw_log_ref', 'N/A'))[:28]}...</code></div>
            </div>
            """, unsafe_allow_html=True)

            # Block C: Backend Oracle State
            st.markdown(f"""
            <div class="forensic-box">
                <div class="forensic-title">C. Backend Oracle Outcome</div>
                <div class="forensic-field"><b>Target App Received:</b> <code>{event_row.get('app_received')}</code></div>
                <div class="forensic-field"><b>Backend Compromised:</b> <code>{event_row.get('backend_effect')}</code></div>
                <div class="forensic-field"><b>Oracle Diagnostic:</b> {event_row.get('oracle_observation', 'None')}</div>
                <div class="forensic-field"><b>Evaluation Cell:</b> <code>{event_row.get('metric_cell', 'N/A')}</code> | <b>Verdict:</b> <b>{event_row.get('verdict', 'N/A')}</b></div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.info("No events match the selected filter criteria.")


def run_terminal_preview():
    """Terminal preview for headless testing."""
    print("=" * 78)
    print("    WAFBench Evaluation Dashboard - Terminal Preview (Academic Style)")
    print("=" * 78)
    sample_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_events.json")
    if os.path.exists(sample_file):
        with open(sample_file, "r", encoding="utf-8") as f:
            records = json.load(f)
        print(f"[+] Loaded {len(records)} sample events from sample_events.json")
        for r in records[:4]:
            print(f"  * {r.get('endpoint', ''):<15} | Status {r.get('client_status', 0)} | WAF {r.get('disruptive_action', ''):<5} | Verdict: {r.get('verdict', '')}")
    print("=" * 78)


if __name__ == "__main__":
    if STREAMLIT_AVAILABLE:
        render_streamlit_dashboard()
    else:
        run_terminal_preview()
