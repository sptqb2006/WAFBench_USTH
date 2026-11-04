#!/usr/bin/env python3
"""
WAFBench Analytics Dashboard (Streamlit :8501)
Academic & Forensic Evaluation Console
"""

import os
import sys
import json
import html

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
        '<span class="academic-badge status-demo"><span class="status-dot"></span>Demo Dataset</span>'
        if is_demo else
        '<span class="academic-badge status-live"><span class="status-dot"></span>Live Event-DB</span>'
    )

    st.markdown(f"""
    <div class="academic-header">
        <div style="font-size: 1.75rem; font-weight: 600; margin: 0 0 4px 0;">
            WAFBench Telemetry & Evaluation Console
        </div>
        <div style="font-size: 0.9rem; opacity: 0.8;">
            Three-tier correlated evaluation framework for Nginx 1.26 + ModSecurity v3 + OWASP Core Rule Set (CRS v4.0.0)
        </div>
        <div class="academic-badge-row">
            {badge_status}
            <span class="academic-badge">Target: C0 Baseline</span>
            <span class="academic-badge">Paranoia: PL1</span>
            <span class="academic-badge">Threshold: 5</span>
            <span class="academic-badge">Engine: Dual-Mode</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    if df is None or df.empty:
        st.warning("No evaluation events found. Start Docker services (`docker compose up -d`) to begin streaming.")
        return

    # 2. Summary KPI Metric Cards (Animate UI Academic Card Architecture)
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
    evaluable_pct = (evaluable_count / total_probes * 100) if total_probes > 0 else 0.0
    pct_403 = (http_403_count / total_probes * 100) if total_probes > 0 else 0.0
    waf_block_pct = (waf_blocks_count / total_probes * 100) if total_probes > 0 else 0.0
    discrepancy = abs(http_403_count - waf_blocks_count)

    br_badge_bg = "#f0fdf4" if br >= 80.0 else ("#fffbeb" if br >= 50.0 else "#fef2f2")
    br_badge_color = "#15803d" if br >= 80.0 else ("#b45309" if br >= 50.0 else "#b91c1c")
    br_badge_border = "#bbf7d0" if br >= 80.0 else ("#fde68a" if br >= 50.0 else "#fecaca")
    br_bar_color = "#10b981" if br >= 80.0 else ("#f59e0b" if br >= 50.0 else "#ef4444")

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f"""
        <div class="metric-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <span class="metric-title" style="margin-bottom: 0;">Total Probes</span>
                <span class="academic-badge" style="font-size: 0.70rem; font-weight: 600; padding: 2px 6px; border-radius: 4px; background-color: #f1f5f9; color: #475569; border: 1px solid #cbd5e1;">N = {total_probes:,}</span>
            </div>
            <div class="metric-value" style="font-variant-numeric: tabular-nums; font-weight: 700; letter-spacing: -0.02em;">{total_probes:,}</div>
            <div style="width: 100%; height: 4px; background-color: #f1f5f9; border-radius: 9999px; overflow: hidden; margin: 8px 0 6px 0;">
                <div style="width: {evaluable_pct:.1f}%; height: 100%; background-color: #2563eb; border-radius: 9999px; transition: width var(--spring-dialog);"></div>
            </div>
            <div class="metric-subtitle" style="display: flex; justify-content: space-between; align-items: center;">
                <span>{evaluable_count:,} evaluable ({evaluable_pct:.1f}%)</span>
                <span style="color: #94a3b8;">{inconclusive_count} inconclusive</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with m2:
        st.markdown(f"""
        <div class="metric-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <span class="metric-title" style="margin-bottom: 0;">Perimeter Denials</span>
                <span class="academic-badge" style="font-size: 0.70rem; font-weight: 600; padding: 2px 6px; border-radius: 4px; background-color: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe;">HTTP 403</span>
            </div>
            <div class="metric-value" style="font-variant-numeric: tabular-nums; font-weight: 700; letter-spacing: -0.02em;">{http_403_count:,}</div>
            <div style="width: 100%; height: 4px; background-color: #f1f5f9; border-radius: 9999px; overflow: hidden; margin: 8px 0 6px 0;">
                <div style="width: {pct_403:.1f}%; height: 100%; background-color: #3b82f6; border-radius: 9999px; transition: width var(--spring-dialog);"></div>
            </div>
            <div class="metric-subtitle" style="display: flex; justify-content: space-between; align-items: center;">
                <span>{pct_403:.1f}% client denials</span>
                <span style="color: #94a3b8;">{http_403_count:,}/{total_probes:,}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with m3:
        audit_badge = (
            '<span class="academic-badge" style="font-size: 0.70rem; font-weight: 600; padding: 2px 6px; border-radius: 4px; background-color: #f0fdf4; color: #15803d; border: 1px solid #bbf7d0;">Audit Confirmed</span>'
            if discrepancy == 0 else
            f'<span class="academic-badge" style="font-size: 0.70rem; font-weight: 600; padding: 2px 6px; border-radius: 4px; background-color: #fffbeb; color: #b45309; border: 1px solid #fde68a;">Δ {discrepancy} Divergence</span>'
        )
        st.markdown(f"""
        <div class="metric-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <span class="metric-title" style="margin-bottom: 0;">WAF Verified Blocks</span>
                {audit_badge}
            </div>
            <div class="metric-value" style="font-variant-numeric: tabular-nums; font-weight: 700; letter-spacing: -0.02em;">{waf_blocks_count:,}</div>
            <div style="width: 100%; height: 4px; background-color: #f1f5f9; border-radius: 9999px; overflow: hidden; margin: 8px 0 6px 0;">
                <div style="width: {waf_block_pct:.1f}%; height: 100%; background-color: #10b981; border-radius: 9999px; transition: width var(--spring-dialog);"></div>
            </div>
            <div class="metric-subtitle" style="display: flex; justify-content: space-between; align-items: center;">
                <span>Confirmed ModSecurity logs</span>
                <span style="color: #94a3b8;">{waf_block_pct:.1f}% share</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with m4:
        st.markdown(f"""
        <div class="metric-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <span class="metric-title" style="margin-bottom: 0;">Blocking Rate (BR)</span>
                <span class="academic-badge" style="font-size: 0.70rem; font-weight: 600; padding: 2px 6px; border-radius: 4px; background-color: {br_badge_bg}; color: {br_badge_color}; border: 1px solid {br_badge_border};">DR: {dr:.1f}%</span>
            </div>
            <div class="metric-value" style="font-variant-numeric: tabular-nums; font-weight: 700; letter-spacing: -0.02em;">{br:.1f}%</div>
            <div style="width: 100%; height: 4px; background-color: #f1f5f9; border-radius: 9999px; overflow: hidden; margin: 8px 0 6px 0;">
                <div style="width: {min(br, 100.0):.1f}%; height: 100%; background-color: {br_bar_color}; border-radius: 9999px; transition: width var(--spring-dialog);"></div>
            </div>
            <div class="metric-subtitle" style="display: flex; justify-content: space-between; align-items: center;">
                <span>{tp_b:,} enforced / {tp_b+fn_b:,} malicious</span>
                <span style="color: #94a3b8;">FN_B: {fn_b:,}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # 3. Clean Multi-Dimensional Filters (Animate UI Motion & Modern Academic System)
    with st.container(border=True):
        st.markdown("""
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; padding-bottom: 6px; border-bottom: 1px solid var(--border-subtle, #f1f5f9);">
            <div style="display: flex; align-items: center; gap: 8px;">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#475569" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"></polygon>
                </svg>
                <span style="font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #334155;">
                    Multi-Dimensional Telemetry Filters
                </span>
            </div>
            <span style="font-size: 0.72rem; color: #94a3b8; font-family: ui-monospace, monospace; letter-spacing: 0.02em;">
                CORRELATED QUERY
            </span>
        </div>
        """, unsafe_allow_html=True)

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

        # 100% Preserved Filter Logic
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

        # Active filter chips & pill counter
        total_probes_count = len(df)
        filtered_count = len(filtered_df)
        pct_filtered = (filtered_count / total_probes_count * 100) if total_probes_count > 0 else 0.0

        active_criteria = []
        if sel_endpoint != "All":
            active_criteria.append(("Endpoint", sel_endpoint))
        if sel_family != "All":
            active_criteria.append(("Threat", sel_family))
        if sel_action != "All":
            active_criteria.append(("Action", sel_action))
        if sel_status != "All":
            active_criteria.append(("Status", sel_status))
        if search_rule.strip():
            active_criteria.append(("Rule ID", search_rule.strip()))

        chips_html = ""
        for tag, val in active_criteria:
            chips_html += f"""
            <span style="display: inline-flex; align-items: center; gap: 4px; font-size: 0.72rem; padding: 2px 8px; border-radius: 9999px; background-color: #eff6ff; color: #1e40af; border: 1px solid #bfdbfe; font-weight: 500; transition: transform var(--spring-pop, 450ms ease);">
                <span style="color: #64748b;">{tag}:</span> <b>{val}</b>
            </span>
            """

        if not active_criteria:
            chips_html = """
            <span style="display: inline-flex; align-items: center; gap: 5px; font-size: 0.72rem; padding: 2px 8px; border-radius: 9999px; background-color: #f8fafc; color: #64748b; border: 1px solid #e2e8f0; font-weight: 500;">
                <span style="width: 6px; height: 6px; border-radius: 50%; background-color: #94a3b8; display: inline-block;"></span>
                All records active
            </span>
            """

        pct_style = (
            "background-color: #f1f5f9; color: #475569; border: 1px solid #cbd5e1;"
            if pct_filtered == 100.0 else
            ("background-color: #e0f2fe; color: #0369a1; border: 1px solid #bae6fd;"
             if pct_filtered > 0 else
             "background-color: #fef2f2; color: #b91c1c; border: 1px solid #fecaca;")
        )

        st.markdown(f"""
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; margin-top: 10px; padding-top: 8px; border-top: 1px solid var(--border-subtle, #f1f5f9);">
            <div style="display: flex; align-items: center; gap: 6px; flex-wrap: wrap;">
                <span style="font-size: 0.72rem; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.04em;">Criteria:</span>
                {chips_html}
            </div>
            <div style="display: inline-flex; align-items: center; gap: 5px; font-size: 0.75rem; padding: 3px 10px; border-radius: 9999px; background-color: #f8fafc; border: 1px solid var(--border-subtle, #e2e8f0); color: #475569; font-variant-numeric: tabular-nums;">
                <span style="color: #64748b;">Showing</span>
                <span style="font-weight: 700; color: #0f172a;">{filtered_count:,}</span>
                <span style="color: #94a3b8;">of</span>
                <span style="font-weight: 600; color: #334155;">{total_probes_count:,}</span>
                <span style="color: #64748b;">test records</span>
                <span style="font-size: 0.68rem; font-weight: 600; {pct_style} padding: 1px 6px; border-radius: 9999px; margin-left: 2px;">
                    {pct_filtered:.0f}%
                </span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # 4. Side-by-Side Normalized Event Stream & Forensic Drawer
    col_table, col_drawer = st.columns([3, 2])

    with col_table:
        event_count = len(filtered_df)
        st.markdown(f"""
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; padding-bottom: 6px; border-bottom: 1px solid var(--border-subtle, #e2e8f0);">
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="font-size: 0.92rem; font-weight: 600; color: var(--text-primary, #0f172a); letter-spacing: -0.01em;">
                    Normalized Event Stream
                </span>
                <span style="font-size: 0.72rem; font-weight: 500; color: var(--text-muted, #64748b);">
                    Correlated telemetry records
                </span>
            </div>
            <div style="display: inline-flex; align-items: center; gap: 5px; font-size: 0.72rem; padding: 2px 8px; border-radius: 9999px; background-color: var(--surface-secondary, #f8fafc); border: 1px solid var(--border-subtle, #cbd5e1); color: var(--text-secondary, #475569); font-variant-numeric: tabular-nums;">
                <span style="font-weight: 600; color: var(--text-primary, #0f172a);">{event_count:,}</span>
                <span>events</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        display_cols = [
            "correlation_id", "case_id", "family_id", "state", "client_status",
            "disruptive_action", "inbound_score", "verdict", "metric_cell"
        ]
        available_cols = [c for c in display_cols if c in filtered_df.columns]

        column_config = {
            "correlation_id": st.column_config.TextColumn("Correlation ID", help="UUIDv4 X-Request-ID propagation trace"),
            "case_id": st.column_config.TextColumn("Case ID", help="WAFBench benchmark test case identifier"),
            "family_id": st.column_config.TextColumn("Threat Family", help="CRS attack taxonomy classification"),
            "state": st.column_config.TextColumn("State", help="Architecture state (S1: Direct, S2: Detect, S3: Block)"),
            "client_status": st.column_config.NumberColumn("HTTP Status", format="%d", help="Client HTTP response status code"),
            "disruptive_action": st.column_config.TextColumn("WAF Action", help="ModSecurity disruptive rule action"),
            "inbound_score": st.column_config.NumberColumn("Score", format="%d", help="CRS Inbound Anomaly Score"),
            "verdict": st.column_config.TextColumn("Verdict", help="Three-tier correlated evaluation outcome"),
            "metric_cell": st.column_config.TextColumn("Metric Cell", help="Formal confusion matrix cell designation (e.g. TP_B, FP_B)"),
        } if hasattr(st, "column_config") else None

        st.dataframe(
            filtered_df[available_cols],
            use_container_width=True,
            height=480,
            hide_index=True,
            column_config=column_config
        )

    with col_drawer:
        st.markdown("##### Forensic Inspection Drawer")
        if not filtered_df.empty:
            corr_ids = list(filtered_df["correlation_id"].unique())
            selected_corr = st.selectbox("Inspect Transaction (X-Request-ID):", corr_ids)
            event_row = filtered_df[filtered_df["correlation_id"] == selected_corr].iloc[0]

            # Block A: Client Observation
            status_code = event_row.get("client_status")
            try:
                status_int = int(status_code)
            except (ValueError, TypeError):
                status_int = None

            if status_int == 200:
                status_bg = "#dcfce7"
                status_fg = "#15803d"
                status_border = "#bbf7d0"
            elif status_int == 403:
                status_bg = "#fee2e2"
                status_fg = "#b91c1c"
                status_border = "#fecaca"
            else:
                status_bg = "#fef3c7"
                status_fg = "#b45309"
                status_border = "#fde68a"

            status_display = str(status_code) if status_code is not None else "N/A"
            method_val = event_row.get("method", "GET")
            endpoint_val = event_row.get("endpoint", "")
            sha_raw = str(event_row.get("request_sha256", "N/A"))
            sha_truncated = f"{sha_raw[:24]}..." if len(sha_raw) > 24 else sha_raw

            st.markdown(f"""
            <div class="forensic-box">
                <div class="forensic-title" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; padding-bottom: 6px; border-bottom: 1px solid var(--border-subtle, #e2e8f0);">
                    <div style="display: flex; align-items: center; gap: 7px;">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#475569" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect>
                            <line x1="8" y1="21" x2="16" y2="21"></line>
                            <line x1="12" y1="17" x2="12" y2="21"></line>
                        </svg>
                        <span>A. Client Observation</span>
                    </div>
                    <span style="font-size: 0.68rem; font-family: ui-monospace, monospace; color: var(--text-muted, #64748b); letter-spacing: 0.04em;">TIER 1 PROBE</span>
                </div>
                <div class="forensic-field" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-size: 0.8rem; color: #475569; font-weight: 500;">Endpoint:</span>
                    <span style="display: inline-flex; align-items: center; gap: 4px;">
                        <span style="font-family: ui-monospace, monospace; font-size: 0.72rem; font-weight: 700; padding: 1px 5px; border-radius: 4px; background-color: #f1f5f9; color: #334155; border: 1px solid #cbd5e1;">{method_val}</span>
                        <code style="font-family: ui-monospace, monospace; font-size: 0.80rem; background-color: #ffffff; color: #0f172a; padding: 2px 6px; border-radius: 4px; border: 1px solid var(--border-subtle, #e2e8f0);">{endpoint_val}</code>
                    </span>
                </div>
                <div class="forensic-field" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-size: 0.8rem; color: #475569; font-weight: 500;">HTTP Status:</span>
                    <span style="font-family: ui-monospace, monospace; font-size: 0.75rem; font-weight: 600; padding: 2px 8px; border-radius: 4px; background-color: {status_bg}; color: {status_fg}; border: 1px solid {status_border}; transition: transform var(--spring-pop, 0.2s ease);">{status_display}</span>
                </div>
                <div class="forensic-field" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-size: 0.8rem; color: #475569; font-weight: 500;">Correlation ID:</span>
                    <code style="font-family: ui-monospace, monospace; font-size: 0.75rem; background-color: #ffffff; color: #0f172a; padding: 2px 6px; border-radius: 4px; border: 1px solid var(--border-subtle, #e2e8f0); transition: border-color var(--spring-highlight, 0.15s ease);" title="{selected_corr}">{selected_corr}</code>
                </div>
                <div class="forensic-field" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2px;">
                    <span style="font-size: 0.8rem; color: #475569; font-weight: 500;">Payload SHA-256:</span>
                    <code style="font-family: ui-monospace, monospace; font-size: 0.75rem; background-color: #ffffff; color: #475569; padding: 2px 6px; border-radius: 4px; border: 1px solid var(--border-subtle, #e2e8f0);" title="{sha_raw}">{sha_truncated}</code>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Block B: WAF ModSecurity Evidence
            waf_txn_id = str(event_row.get("waf_txn_id") or "N/A")
            waf_txn_trunc = f"{waf_txn_id[:24]}..." if len(waf_txn_id) > 24 else waf_txn_id
            waf_txn_esc = html.escape(waf_txn_id)
            waf_txn_trunc_esc = html.escape(waf_txn_trunc)

            raw_action = str(event_row.get("disruptive_action") or "none").strip().lower()
            action_upper = raw_action.upper() if raw_action and raw_action != "none" else "NONE"
            raw_phase = event_row.get("interrupt_phase")
            phase_display = f"Phase {raw_phase}" if raw_phase is not None and str(raw_phase).strip() not in ("", "None", "nan") else "Phase N/A"

            if raw_action in ("block", "drop", "deny"):
                action_bg = "#fee2e2"
                action_fg = "#b91c1c"
                action_border = "#fecaca"
            elif raw_action in ("allow", "pass"):
                action_bg = "#dcfce7"
                action_fg = "#15803d"
                action_border = "#bbf7d0"
            elif raw_action in ("detect", "none", "log"):
                action_bg = "#fef3c7"
                action_fg = "#b45309"
                action_border = "#fde68a"
            else:
                action_bg = "#f1f5f9"
                action_fg = "#475569"
                action_border = "#cbd5e1"

            raw_score = event_row.get("inbound_score", 0)
            try:
                score_val = int(raw_score)
            except (ValueError, TypeError):
                score_val = 0

            if score_val >= 5:
                score_bg = "#fee2e2"
                score_fg = "#b91c1c"
                score_border = "#fecaca"
            else:
                score_bg = "#dcfce7"
                score_fg = "#15803d"
                score_border = "#bbf7d0"

            root_rule_id = str(event_row.get("root_rule_id") or "N/A")
            root_rule_name = str(event_row.get("root_rule_name") or "Clean")
            rule_id_esc = html.escape(root_rule_id)
            rule_name_esc = html.escape(root_rule_name)
            rule_name_trunc = f"{root_rule_name[:24]}..." if len(root_rule_name) > 24 else root_rule_name
            rule_name_trunc_esc = html.escape(rule_name_trunc)

            matched_var = str(event_row.get("waf_matched_variable") or "None")
            matched_var_esc = html.escape(matched_var)
            matched_var_trunc = f"{matched_var[:24]}..." if len(matched_var) > 24 else matched_var
            matched_var_trunc_esc = html.escape(matched_var_trunc)

            snippet = str(event_row.get("waf_payload_snippet") or "None")
            snippet_esc = html.escape(snippet)
            snippet_trunc = f"{snippet[:24]}..." if len(snippet) > 24 else snippet
            snippet_trunc_esc = html.escape(snippet_trunc)

            if snippet not in ("None", "", "N/A"):
                snippet_bg = "#fef2f2"
                snippet_fg = "#991b1b"
                snippet_border = "#fecaca"
            else:
                snippet_bg = "#ffffff"
                snippet_fg = "#64748b"
                snippet_border = "var(--border-subtle, #e2e8f0)"

            raw_log_ref = str(event_row.get("raw_log_ref") or "N/A")
            log_ref_esc = html.escape(raw_log_ref)
            log_ref_trunc = f"{raw_log_ref[:24]}..." if len(raw_log_ref) > 24 else raw_log_ref
            log_ref_trunc_esc = html.escape(log_ref_trunc)

            st.markdown(f"""
            <div class="forensic-box">
                <div class="forensic-title" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; padding-bottom: 6px; border-bottom: 1px solid var(--border-subtle, #e2e8f0);">
                    <div style="display: flex; align-items: center; gap: 7px;">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#475569" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                        </svg>
                        <span>B. WAF ModSecurity Evidence</span>
                    </div>
                    <span style="font-size: 0.68rem; font-family: ui-monospace, monospace; color: var(--text-muted, #64748b); letter-spacing: 0.04em;">TIER 2 TELEMETRY</span>
                </div>
                <div class="forensic-field" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-size: 0.8rem; color: #475569; font-weight: 500;">WAF TxID:</span>
                    <code style="font-family: ui-monospace, monospace; font-size: 0.75rem; background-color: #ffffff; color: #0f172a; padding: 2px 6px; border-radius: 4px; border: 1px solid var(--border-subtle, #e2e8f0); transition: border-color var(--spring-highlight, 0.15s ease);" title="{waf_txn_esc}">{waf_txn_trunc_esc}</code>
                </div>
                <div class="forensic-field" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-size: 0.8rem; color: #475569; font-weight: 500;">Disruptive Action:</span>
                    <span style="display: inline-flex; align-items: center; gap: 5px;">
                        <span style="font-family: ui-monospace, monospace; font-size: 0.72rem; font-weight: 700; padding: 2px 7px; border-radius: 4px; background-color: {action_bg}; color: {action_fg}; border: 1px solid {action_border}; transition: transform var(--spring-pop, 0.2s ease);">{action_upper}</span>
                        <span style="font-size: 0.72rem; font-family: ui-monospace, monospace; color: #64748b;">({phase_display})</span>
                    </span>
                </div>
                <div class="forensic-field" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-size: 0.8rem; color: #475569; font-weight: 500;">Anomaly Score:</span>
                    <span style="display: inline-flex; align-items: center; gap: 5px;">
                        <span style="font-family: ui-monospace, monospace; font-size: 0.75rem; font-weight: 700; padding: 2px 8px; border-radius: 4px; background-color: {score_bg}; color: {score_fg}; border: 1px solid {score_border}; transition: transform var(--spring-pop, 0.2s ease);">{score_val} pts</span>
                        <span style="font-size: 0.72rem; font-family: ui-monospace, monospace; color: #64748b;">/ Threshold 5</span>
                    </span>
                </div>
                <div class="forensic-field" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-size: 0.8rem; color: #475569; font-weight: 500;">Root CRS Rule:</span>
                    <span style="display: inline-flex; align-items: center; gap: 5px; max-width: 65%; justify-content: flex-end;" title="{rule_name_esc}">
                        <code style="font-family: ui-monospace, monospace; font-size: 0.75rem; background-color: #ffffff; color: #0f172a; padding: 2px 6px; border-radius: 4px; border: 1px solid var(--border-subtle, #e2e8f0); white-space: nowrap;">{rule_id_esc}</code>
                        <span style="font-size: 0.75rem; color: #475569; font-style: italic; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{rule_name_trunc_esc}</span>
                    </span>
                </div>
                <div class="forensic-field" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-size: 0.8rem; color: #475569; font-weight: 500;">Matched Variable:</span>
                    <code style="font-family: ui-monospace, monospace; font-size: 0.75rem; background-color: #ffffff; color: #0f172a; padding: 2px 6px; border-radius: 4px; border: 1px solid var(--border-subtle, #e2e8f0); transition: border-color var(--spring-highlight, 0.15s ease);" title="{matched_var_esc}">{matched_var_trunc_esc}</code>
                </div>
                <div class="forensic-field" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-size: 0.8rem; color: #475569; font-weight: 500;">Offending Snippet:</span>
                    <code style="font-family: ui-monospace, monospace; font-size: 0.75rem; background-color: {snippet_bg}; color: {snippet_fg}; padding: 2px 6px; border-radius: 4px; border: 1px solid {snippet_border}; transition: border-color var(--spring-highlight, 0.15s ease); max-width: 65%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="{snippet_esc}">{snippet_trunc_esc}</code>
                </div>
                <div class="forensic-field" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2px;">
                    <span style="font-size: 0.8rem; color: #475569; font-weight: 500;">Audit Ref:</span>
                    <code style="font-family: ui-monospace, monospace; font-size: 0.75rem; background-color: #ffffff; color: #475569; padding: 2px 6px; border-radius: 4px; border: 1px solid var(--border-subtle, #e2e8f0); transition: border-color var(--spring-highlight, 0.15s ease);" title="{log_ref_esc}">{log_ref_trunc_esc}</code>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Block C: Backend Oracle State
            app_recv_raw = event_row.get("app_received")
            if app_recv_raw is True or str(app_recv_raw).strip().lower() in ("true", "1", "yes"):
                app_recv_text = "TRUE"
                app_recv_bg = "#dcfce7"
                app_recv_fg = "#15803d"
                app_recv_border = "#bbf7d0"
            elif app_recv_raw is False or str(app_recv_raw).strip().lower() in ("false", "0", "no"):
                app_recv_text = "FALSE"
                app_recv_bg = "#f1f5f9"
                app_recv_fg = "#475569"
                app_recv_border = "#cbd5e1"
            else:
                app_recv_text = html.escape(str(app_recv_raw)) if app_recv_raw is not None else "N/A"
                app_recv_bg = "#f8fafc"
                app_recv_fg = "#64748b"
                app_recv_border = "#e2e8f0"

            effect_raw = event_row.get("backend_effect")
            effect_str = str(effect_raw).strip().lower() if effect_raw is not None else ""
            if effect_raw is True or effect_str in ("true", "1", "compromised"):
                effect_display = "COMPROMISED"
                effect_bg = "#fee2e2"
                effect_fg = "#b91c1c"
                effect_border = "#fecaca"
            elif effect_raw is False or effect_str in ("false", "0", "intact", "clean", "none"):
                effect_display = "INTACT"
                effect_bg = "#dcfce7"
                effect_fg = "#15803d"
                effect_border = "#bbf7d0"
            else:
                effect_display = html.escape(str(effect_raw)) if effect_raw is not None else "UNKNOWN"
                effect_bg = "#f1f5f9"
                effect_fg = "#475569"
                effect_border = "#cbd5e1"

            oracle_obs_raw = event_row.get("oracle_observation")
            if oracle_obs_raw is None or str(oracle_obs_raw).strip() in ("", "None", "nan"):
                oracle_obs_text = "None"
            else:
                oracle_obs_text = str(oracle_obs_raw).strip()
            oracle_obs_esc = html.escape(oracle_obs_text)

            metric_cell_raw = str(event_row.get("metric_cell") or "N/A").strip()
            metric_cell_esc = html.escape(metric_cell_raw)

            verdict_raw = str(event_row.get("verdict") or "N/A").strip()
            verdict_upper = verdict_raw.upper()
            verdict_esc = html.escape(verdict_upper)
            if verdict_upper == "PASS":
                verdict_bg = "#dcfce7"
                verdict_fg = "#15803d"
                verdict_border = "#bbf7d0"
            elif verdict_upper == "FAIL":
                verdict_bg = "#fee2e2"
                verdict_fg = "#b91c1c"
                verdict_border = "#fecaca"
            elif verdict_upper in ("INCONCLUSIVE", "INCONC", "WARN", "WARNING"):
                verdict_bg = "#fef3c7"
                verdict_fg = "#b45309"
                verdict_border = "#fde68a"
            else:
                verdict_bg = "#f1f5f9"
                verdict_fg = "#475569"
                verdict_border = "#cbd5e1"

            st.markdown(f"""
            <div class="forensic-box">
                <div class="forensic-title" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; padding-bottom: 6px; border-bottom: 1px solid var(--border-subtle, #e2e8f0);">
                    <div style="display: flex; align-items: center; gap: 7px;">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#475569" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <ellipse cx="12" cy="5" rx="9" ry="3"></ellipse>
                            <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path>
                            <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path>
                        </svg>
                        <span>C. Backend Oracle Outcome</span>
                    </div>
                    <span style="font-size: 0.68rem; font-family: ui-monospace, monospace; color: var(--text-muted, #64748b); letter-spacing: 0.04em;">TIER 3 GROUND TRUTH</span>
                </div>
                <div class="forensic-field" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-size: 0.8rem; color: #475569; font-weight: 500;">Target App Received:</span>
                    <span style="font-family: ui-monospace, monospace; font-size: 0.72rem; font-weight: 700; padding: 2px 8px; border-radius: 9999px; background-color: {app_recv_bg}; color: {app_recv_fg}; border: 1px solid {app_recv_border}; transition: transform var(--spring-pop, 0.2s ease);">{app_recv_text}</span>
                </div>
                <div class="forensic-field" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-size: 0.8rem; color: #475569; font-weight: 500;">Backend Compromised:</span>
                    <span style="font-family: ui-monospace, monospace; font-size: 0.72rem; font-weight: 700; padding: 2px 8px; border-radius: 4px; background-color: {effect_bg}; color: {effect_fg}; border: 1px solid {effect_border}; transition: transform var(--spring-pop, 0.2s ease);">{effect_display}</span>
                </div>
                <div class="forensic-field" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-size: 0.8rem; color: #475569; font-weight: 500;">Evaluation Cell:</span>
                    <code style="font-family: ui-monospace, monospace; font-size: 0.75rem; font-weight: 600; background-color: #ffffff; color: #0f172a; padding: 2px 6px; border-radius: 4px; border: 1px solid var(--border-subtle, #e2e8f0); transition: border-color var(--spring-highlight, 0.15s ease);">{metric_cell_esc}</code>
                </div>
                <div class="forensic-field" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-size: 0.8rem; color: #475569; font-weight: 500;">Ground Truth Verdict:</span>
                    <span style="font-family: ui-monospace, monospace; font-size: 0.75rem; font-weight: 700; padding: 2px 8px; border-radius: 4px; background-color: {verdict_bg}; color: {verdict_fg}; border: 1px solid {verdict_border}; transition: transform var(--spring-pop, 0.2s ease);">{verdict_esc}</span>
                </div>
                <div style="margin-top: 8px; padding: 8px 10px; background-color: var(--surface-secondary, #f8fafc); border-radius: 4px; border: 1px solid var(--border-subtle, #e2e8f0); transition: border-color var(--spring-highlight, 0.15s ease);">
                    <div style="font-size: 0.70rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; color: #64748b; margin-bottom: 3px;">Oracle Diagnostic</div>
                    <div style="font-size: 0.78rem; color: #334155; line-height: 1.4; word-break: break-word;">{oracle_obs_esc}</div>
                </div>
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
