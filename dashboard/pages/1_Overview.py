#!/usr/bin/env python3
"""
WAFBench Executive KPI Overview Page
Quantitative WAF Evaluation conforming to Table 4.6 and Table 5.2.
Metrics: DR, BR, FPR_D, FPR_B, RPR.
Clean Academic Theme with Animate UI Motion Tokens.
"""

import os
import sys
import json
import pandas as pd
import streamlit as st

# Import shared academic styling
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from styles import apply_academic_styling
except ImportError:
    apply_academic_styling = lambda: None

st.set_page_config(
    page_title="Executive Overview - WAFBench",
    layout="wide",
    initial_sidebar_state="expanded"
)
apply_academic_styling()

# Page-specific Animate UI Motion & Card Styling
st.markdown("""
<style>
    /* -------------------------------------------------------------
       Animate UI Motion Tokens & Academic Cards
       ------------------------------------------------------------- */
    .metric-card {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 1.1rem 1.2rem;
        text-align: left;
        box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04);
        transition: transform 0.18s cubic-bezier(0.2, 0, 0, 1),
                    box-shadow 0.18s ease-in-out,
                    border-color 0.18s ease-in-out;
        user-select: none;
        cursor: default;
    }
    .metric-card:hover {
        border-color: #cbd5e1;
        box-shadow: 0 4px 12px rgba(15, 23, 42, 0.06);
    }
    .metric-card:active {
        transform: scale(0.985);
    }
    .metric-title {
        font-size: 0.74rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #64748b;
        margin-bottom: 6px;
        font-weight: 600;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .metric-value {
        font-size: 1.85rem;
        font-weight: 700;
        color: #0f172a;
        line-height: 1.15;
        font-feature-settings: "tnum" 1, "cv02" 1;
    }
    .metric-subtitle {
        font-size: 0.76rem;
        color: #64748b;
        margin-top: 6px;
        line-height: 1.35;
    }
    .metric-formula-badge {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 0.68rem;
        padding: 2px 6px;
        border-radius: 4px;
        background: #f1f5f9;
        color: #475569;
        border: 1px solid #e2e8f0;
        font-weight: 600;
    }

    /* Forensic Box Container */
    .forensic-box {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 1.25rem;
        margin-bottom: 1.2rem;
        box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04);
        transition: transform 0.18s cubic-bezier(0.2, 0, 0, 1),
                    box-shadow 0.18s ease-in-out,
                    border-color 0.18s ease-in-out;
    }
    .forensic-box:hover {
        border-color: #cbd5e1;
        box-shadow: 0 4px 12px rgba(15, 23, 42, 0.06);
    }
    .forensic-box:active {
        transform: scale(0.985);
    }
    .forensic-title {
        font-size: 0.95rem;
        font-weight: 600;
        color: #0f172a;
        margin-bottom: 4px;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .forensic-desc {
        font-size: 0.80rem;
        color: #64748b;
        margin-bottom: 12px;
        line-height: 1.45;
    }

    /* 2x2 Confusion Matrix Tables */
    .matrix-table {
        width: 100%;
        border-collapse: separate;
        border-spacing: 8px;
        margin-top: 6px;
    }
    .matrix-header-cell {
        font-size: 0.72rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        color: #64748b;
        text-align: center;
        padding: 6px 8px;
    }
    .matrix-row-label {
        font-size: 0.74rem;
        font-weight: 600;
        color: #475569;
        text-align: right;
        padding: 6px 12px;
        vertical-align: middle;
        white-space: nowrap;
    }
    .matrix-cell {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        padding: 10px 14px;
        text-align: center;
        transition: transform 0.15s cubic-bezier(0.2, 0, 0, 1),
                    background-color 0.15s ease-in-out,
                    border-color 0.15s ease-in-out;
        cursor: default;
    }
    .matrix-cell:hover {
        border-color: #cbd5e1;
        background: #f1f5f9;
    }
    .matrix-cell:active {
        transform: scale(0.985);
    }
    .matrix-cell-positive {
        background: #f0fdf4;
        border-color: #bbf7d0;
    }
    .matrix-cell-positive:hover {
        border-color: #86efac;
        background: #dcfce7;
    }
    .matrix-cell-negative {
        background: #fef2f2;
        border-color: #fecaca;
    }
    .matrix-cell-negative:hover {
        border-color: #fca5a5;
        background: #fee2e2;
    }
    .matrix-cell-neutral {
        background: #f8fafc;
        border-color: #e2e8f0;
    }
    .cell-symbol {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 0.76rem;
        font-weight: 700;
        color: #334155;
    }
    .cell-value {
        font-size: 1.6rem;
        font-weight: 700;
        color: #0f172a;
        margin: 2px 0;
        font-feature-settings: "tnum" 1;
    }
    .cell-label {
        font-size: 0.68rem;
        color: #64748b;
        line-height: 1.25;
    }
    .matrix-footer {
        margin-top: 10px;
        padding-top: 8px;
        border-top: 1px solid #e2e8f0;
        font-size: 0.74rem;
        color: #64748b;
        display: flex;
        justify-content: space-between;
    }

    /* Spring Highlight for Table */
    div[data-testid="stDataFrame"] tbody tr:hover {
        background-color: #f8fafc !important;
        transition: background-color 0.15s cubic-bezier(0.2, 0, 0, 1);
    }

    /* Reduced Motion */
    @media (prefers-reduced-motion: reduce) {
        * {
            transition-duration: 0.01ms !important;
            animation-duration: 0.01ms !important;
            transform: none !important;
        }
    }
</style>
""", unsafe_allow_html=True)


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
        query = "SELECT * FROM normalized_events ORDER BY id DESC LIMIT 1000;"
        df = pd.read_sql(query, conn)
        conn.close()
        if df is not None and not df.empty:
            return df, False  # Live stream from PostgreSQL
    except Exception:
        pass

    # 2. Resilient Fallback to sample_events.json (Demo Mode)
    sample_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sample_events.json")
    if os.path.exists(sample_file):
        with open(sample_file, "r", encoding="utf-8") as f:
            records = json.load(f)
        return pd.DataFrame(records), True

    return pd.DataFrame(), False


data_res = load_data()
if isinstance(data_res, tuple):
    df, is_demo = data_res
else:
    df, is_demo = data_res, True

# Academic Header
source_badge = (
    '<span class="academic-badge academic-badge-demo">Source: Corpus Reference (sample_events.json)</span>'
    if is_demo else
    '<span class="academic-badge academic-badge-live">Source: Live Telemetry DB (PostgreSQL)</span>'
)

st.markdown(f"""
<div class="academic-header">
    <div style="font-size: 1.6rem; font-weight: 700; color: #0f172a; margin: 0 0 4px 0; letter-spacing: -0.02em;">
        Executive KPI & Empirical Benchmark Overview
    </div>
    <div style="font-size: 0.88rem; color: #475569; line-height: 1.45;">
        Quantitative WAF evaluation metrics according to Table 4.6 and Table 5.2 
        (<em>DR</em>, <em>BR</em>, <em>FPR<sub>D</sub></em>, <em>FPR<sub>B</sub></em>, <em>RPR</em>).
    </div>
    <div class="academic-badge-row">
        {source_badge}
        <span class="academic-badge">Target Profile: C0 Baseline</span>
        <span class="academic-badge">OWASP CRS: v4.0.0 (PL1)</span>
        <span class="academic-badge">Threshold: Inbound Score ≥ 5</span>
        <span class="academic-badge">Framework: 3-Tier Correlated</span>
    </div>
</div>
""", unsafe_allow_html=True)

if not df.empty:
    valid_df = df[df["validity"] == "VALID"]

    # -------------------------------------------------------------
    # 1. Calculation Formulas (Strictly conforming to Table 4.6 & Table 5.2)
    # -------------------------------------------------------------
    # Blocking Rate (BR)
    tp_b = len(valid_df[valid_df["metric_cell"] == "TP_B"])
    fn_b = len(valid_df[valid_df["metric_cell"] == "FN_B"])
    br = (tp_b / (tp_b + fn_b) * 100) if (tp_b + fn_b) > 0 else 0.0

    # Detection Rate (DR)
    tp_d = len(valid_df[valid_df["metric_cell"] == "TP_D"])
    fn_d = len(valid_df[valid_df["metric_cell"] == "FN_D"])
    dr = (tp_d / (tp_d + fn_d) * 100) if (tp_d + fn_d) > 0 else 0.0

    # Detection False Positive Rate (FPR_D)
    fp_d = len(valid_df[valid_df["metric_cell"] == "FP_D"])
    tn_d = len(valid_df[valid_df["metric_cell"] == "TN_D"])
    fpr_d = (fp_d / (fp_d + tn_d) * 100) if (fp_d + tn_d) > 0 else 0.0

    # Blocking False Positive Rate (FPR_B)
    fp_b = len(valid_df[valid_df["metric_cell"] == "FP_B"])
    tn_b = len(valid_df[valid_df["metric_cell"] == "TN_B"])
    fpr_b = (fp_b / (fp_b + tn_b) * 100) if (fp_b + tn_b) > 0 else 0.0

    # Regression Pass Rate (RPR)
    if "regression_pass_rate" in df.columns and df["regression_pass_rate"].dropna().any():
        rpr = float(df["regression_pass_rate"].dropna().iloc[0])
        rpr_note = "Post-tuning holdouts"
    else:
        rpr = 100.0
        rpr_note = "C0 baseline invariance"

    # -------------------------------------------------------------
    # 2. Executive KPI Cards (Animate UI Motion Cards)
    # -------------------------------------------------------------
    c1, c2, c3, c4, c5 = st.columns(5)

    with c1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">
                <span>Blocking Rate (BR)</span>
                <span class="metric-formula-badge">Table 5.2</span>
            </div>
            <div class="metric-value">{br:.1f}%</div>
            <div class="metric-subtitle">
                <strong>{tp_b}</strong> enforced of {tp_b + fn_b} evaluable attacks<br>
                <span style="font-family: ui-monospace, monospace; font-size: 0.70rem; color: #64748b;">Formula: TP_B / (TP_B + FN_B)</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with c2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">
                <span>Detection Rate (DR)</span>
                <span class="metric-formula-badge">Table 5.2</span>
            </div>
            <div class="metric-value">{dr:.1f}%</div>
            <div class="metric-subtitle">
                <strong>{tp_d}</strong> detected of {tp_d + fn_d} evaluable attacks<br>
                <span style="font-family: ui-monospace, monospace; font-size: 0.70rem; color: #64748b;">Formula: TP_D / (TP_D + FN_D)</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with c3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">
                <span>Blocking FPR (FPR_B)</span>
                <span class="metric-formula-badge">Table 5.2</span>
            </div>
            <div class="metric-value">{fpr_b:.1f}%</div>
            <div class="metric-subtitle">
                <strong>{fp_b}</strong> false denials of {fp_b + tn_b} benign<br>
                <span style="font-family: ui-monospace, monospace; font-size: 0.70rem; color: #64748b;">Formula: FP_B / (FP_B + TN_B)</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with c4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">
                <span>Detection FPR (FPR_D)</span>
                <span class="metric-formula-badge">Table 5.2</span>
            </div>
            <div class="metric-value">{fpr_d:.1f}%</div>
            <div class="metric-subtitle">
                <strong>{fp_d}</strong> false alarms of {fp_d + tn_d} benign<br>
                <span style="font-family: ui-monospace, monospace; font-size: 0.70rem; color: #64748b;">Formula: FP_D / (FP_D + TN_D)</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with c5:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">
                <span>Regression Pass (RPR)</span>
                <span class="metric-formula-badge">Table 5.2</span>
            </div>
            <div class="metric-value">{rpr:.1f}%</div>
            <div class="metric-subtitle">
                <strong>{rpr_note}</strong><br>
                <span style="font-family: ui-monospace, monospace; font-size: 0.70rem; color: #64748b;">Formula: Passed / Eligible Units</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # -------------------------------------------------------------
    # 3. Confusion Matrices (State 3 Blocking vs State 2 DetectionOnly)
    # -------------------------------------------------------------
    col_cm1, col_cm2 = st.columns(2)

    with col_cm1:
        tp_b_class = "matrix-cell-positive" if tp_b > 0 else "matrix-cell-neutral"
        fn_b_class = "matrix-cell-negative" if fn_b > 0 else "matrix-cell-neutral"
        fp_b_class = "matrix-cell-negative" if fp_b > 0 else "matrix-cell-neutral"
        tn_b_class = "matrix-cell-positive" if tn_b > 0 else "matrix-cell-neutral"

        st.markdown(f"""
        <div class="forensic-box">
            <div class="forensic-title">
                <span>Confusion Matrix: State 3 — Blocking Mode</span>
                <span class="metric-formula-badge">SecRuleEngine On</span>
            </div>
            <div class="forensic-desc">
                Evaluates attributable perimeter enforcement (HTTP 403) and absence of backend harm on baseline-confirmed probes.
            </div>
            <table class="matrix-table">
                <thead>
                    <tr>
                        <th class="matrix-header-cell" style="text-align: left; width: 32%;">Ground Truth \\ WAF Action</th>
                        <th class="matrix-header-cell">WAF Blocked (403 + Oracle Intact)</th>
                        <th class="matrix-header-cell">WAF Permitted (Status ≠ 403)</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="matrix-row-label">Actual Malicious</td>
                        <td class="matrix-cell {tp_b_class}">
                            <div class="cell-symbol">TP_B</div>
                            <div class="cell-value">{tp_b}</div>
                            <div class="cell-label">Enforced & Oracle Intact</div>
                        </td>
                        <td class="matrix-cell {fn_b_class}">
                            <div class="cell-symbol">FN_B</div>
                            <div class="cell-value">{fn_b}</div>
                            <div class="cell-label">WAF Bypass / Harm Executed</div>
                        </td>
                    </tr>
                    <tr>
                        <td class="matrix-row-label">Actual Benign / Edge</td>
                        <td class="matrix-cell {fp_b_class}">
                            <div class="cell-symbol">FP_B</div>
                            <div class="cell-value">{fp_b}</div>
                            <div class="cell-label">Erroneous 403 Denial</div>
                        </td>
                        <td class="matrix-cell {tn_b_class}">
                            <div class="cell-symbol">TN_B</div>
                            <div class="cell-value">{tn_b}</div>
                            <div class="cell-label">Legitimate Flow Passed</div>
                        </td>
                    </tr>
                </tbody>
            </table>
            <div class="matrix-footer">
                <span>Empirical Blocking Rate: <strong>{br:.1f}%</strong></span>
                <span>Blocking False Positive Rate: <strong>{fpr_b:.1f}%</strong></span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col_cm2:
        tp_d_class = "matrix-cell-positive" if tp_d > 0 else "matrix-cell-neutral"
        fn_d_class = "matrix-cell-negative" if fn_d > 0 else "matrix-cell-neutral"
        fp_d_class = "matrix-cell-negative" if fp_d > 0 else "matrix-cell-neutral"
        tn_d_class = "matrix-cell-positive" if tn_d > 0 else "matrix-cell-neutral"

        st.markdown(f"""
        <div class="forensic-box">
            <div class="forensic-title">
                <span>Confusion Matrix: State 2 — DetectionOnly Mode</span>
                <span class="metric-formula-badge">SecRuleEngine DetectionOnly</span>
            </div>
            <div class="forensic-desc">
                Evaluates CRS inbound anomaly scoring (Score ≥ 5) on traffic passing transparently without perimeter interruption.
            </div>
            <table class="matrix-table">
                <thead>
                    <tr>
                        <th class="matrix-header-cell" style="text-align: left; width: 32%;">Ground Truth \\ WAF Action</th>
                        <th class="matrix-header-cell">Flagged (Inbound Score ≥ 5)</th>
                        <th class="matrix-header-cell">Passed (Inbound Score &lt; 5)</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="matrix-row-label">Actual Malicious</td>
                        <td class="matrix-cell {tp_d_class}">
                            <div class="cell-symbol">TP_D</div>
                            <div class="cell-value">{tp_d}</div>
                            <div class="cell-label">Anomaly Detected (≥ 5)</div>
                        </td>
                        <td class="matrix-cell {fn_d_class}">
                            <div class="cell-symbol">FN_D</div>
                            <div class="cell-value">{fn_d}</div>
                            <div class="cell-label">Sub-threshold / Missed</div>
                        </td>
                    </tr>
                    <tr>
                        <td class="matrix-row-label">Actual Benign / Edge</td>
                        <td class="matrix-cell {fp_d_class}">
                            <div class="cell-symbol">FP_D</div>
                            <div class="cell-value">{fp_d}</div>
                            <div class="cell-label">False Positive Alarm (≥ 5)</div>
                        </td>
                        <td class="matrix-cell {tn_d_class}">
                            <div class="cell-symbol">TN_D</div>
                            <div class="cell-value">{tn_d}</div>
                            <div class="cell-label">Clean Inspection (&lt; 5)</div>
                        </td>
                    </tr>
                </tbody>
            </table>
            <div class="matrix-footer">
                <span>Detection Rate: <strong>{dr:.1f}%</strong></span>
                <span>Detection False Positive Rate: <strong>{fpr_d:.1f}%</strong></span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # -------------------------------------------------------------
    # 4. Population Breakdown & Validity Classification (Table 4.6)
    # -------------------------------------------------------------
    st.subheader("Population Breakdown & Validity Classification")
    st.markdown(
        "Strict verification of attempted cases conforming to Table 4.6. "
        "Inconclusive and invalid cases are strictly isolated from the evaluation rate denominators."
    )

    total_attempted = len(df)
    total_evaluable = len(valid_df[valid_df["verdict"] != "INCONCLUSIVE"])
    total_inconclusive = len(df[df["verdict"] == "INCONCLUSIVE"])
    total_invalid = sum(1 for v in df["validity"] if str(v).startswith("E_"))

    p1, p2, p3, p4 = st.columns(4)
    with p1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Attempted Test Cases</div>
            <div class="metric-value">{total_attempted}</div>
            <div class="metric-subtitle">Total benchmark probes dispatched</div>
        </div>
        """, unsafe_allow_html=True)

    with p2:
        eval_pct = (total_evaluable / total_attempted * 100) if total_attempted > 0 else 0.0
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Valid & Evaluable Units</div>
            <div class="metric-value">{total_evaluable}</div>
            <div class="metric-subtitle">{eval_pct:.1f}% of total population</div>
        </div>
        """, unsafe_allow_html=True)

    with p3:
        inconc_pct = (total_inconclusive / total_attempted * 100) if total_attempted > 0 else 0.0
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Inconclusive Denials</div>
            <div class="metric-value">{total_inconclusive}</div>
            <div class="metric-subtitle">{inconc_pct:.1f}% unconfirmed attribution</div>
        </div>
        """, unsafe_allow_html=True)

    with p4:
        inv_pct = (total_invalid / total_attempted * 100) if total_attempted > 0 else 0.0
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Execution Anomalies</div>
            <div class="metric-value">{total_invalid}</div>
            <div class="metric-subtitle">{inv_pct:.1f}% telemetry/correlation errors</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    v_taxonomy = {
        "VALID": {
            "classification": "Valid Evaluable",
            "desc": "Conforms strictly to 3-tier correlation criteria across Client, WAF, and Oracle."
        },
        "I_UNATTRIBUTED": {
            "classification": "Inconclusive",
            "desc": "Client-observed denial attributable to neither the WAF nor the application."
        },
        "I_BASELINE_CONFLICT": {
            "classification": "Inconclusive",
            "desc": "Malicious probe exhibited no effect in State 1 baseline harness."
        },
        "I_UNSTABLE": {
            "classification": "Inconclusive",
            "desc": "Disagreement across repeated test runs violating stability rule."
        },
        "E_CORRELATION": {
            "classification": "Execution Error",
            "desc": "Missing X-Request-ID correlation header across telemetry tiers."
        },
        "E_MISSING_WAF_LOG": {
            "classification": "Execution Error",
            "desc": "Observed HTTP 403 status without attributable ModSecurity JSON audit log entry."
        }
    }

    v_counts = df["validity"].value_counts().reset_index()
    v_counts.columns = ["validity", "count"]
    v_rows = []
    for _, row in v_counts.iterrows():
        val = str(row["validity"])
        cnt = int(row["count"])
        pct = (cnt / total_attempted * 100) if total_attempted > 0 else 0.0
        tax = v_taxonomy.get(val, {"classification": "Other", "desc": "Custom classification"})
        v_rows.append({
            "Validity Code": val,
            "Classification": tax["classification"],
            "Count": cnt,
            "Share (%)": f"{pct:.1f}%",
            "Methodological Definition (Table 4.6 & Section 5.2)": tax["desc"]
        })

    breakdown_df = pd.DataFrame(v_rows)
    st.dataframe(breakdown_df, use_container_width=True, hide_index=True)

else:
    st.markdown("""
    <div class="forensic-box" style="text-align: center; padding: 2rem;">
        <div style="font-weight: 600; font-size: 1.1rem; color: #0f172a; margin-bottom: 6px;">
            No Benchmark Records Available
        </div>
        <div style="font-size: 0.88rem; color: #64748b;">
            No telemetry records were found in the database or sample dataset. 
            Start Docker Compose services or execute the benchmark runner to populate evaluation metrics.
        </div>
    </div>
    """, unsafe_allow_html=True)
