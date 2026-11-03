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

st.set_page_config(page_title="Evidence Viewer - WAFBench", layout="wide", initial_sidebar_state="expanded")
apply_academic_styling()

st.title("3-Tier Raw Evidence Viewer")
st.markdown("Side-by-side inspection of evidence across all three tiers: **Client Capture**, **ModSecurity Audit Log**, and **Backend Application Oracle**.")

def load_data():
    sample_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sample_events.json")
    if os.path.exists(sample_file):
        with open(sample_file, "r", encoding="utf-8") as f:
            return pd.DataFrame(json.load(f))
    return pd.DataFrame()

df = load_data()

if not df.empty:
    corr_ids = list(df["correlation_id"].unique())
    selected_id = st.selectbox("Select Transaction by Correlation ID (X-Request-ID):", corr_ids)
    record = df[df["correlation_id"] == selected_id].iloc[0]

    col_t1, col_t2, col_t3 = st.columns(3)

    with col_t1:
        st.subheader("Tier 1: Client Probe")
        with st.container(border=True):
            st.write(f"**Request:** `{record.get('method')} {record.get('endpoint')}`")
            st.write(f"**Status Received:** `{record.get('client_status')}`")
            st.write(f"**Payload SHA-256:** `{record.get('request_sha256')[:24]}...`")
            st.write(f"**Response Snippet:**")
            st.code(record.get("response_body_snippet", "N/A"), language="html")

    with col_t2:
        st.subheader("Tier 2: WAF Evidence")
        with st.container(border=True):
            st.write(f"**TxID:** `{record.get('waf_txn_id', 'N/A')}`")
            st.write(f"**Inbound Score:** `{record.get('inbound_score')}` (Threshold: 5)")
            st.write(f"**Action:** `{record.get('disruptive_action', 'none').upper()}`")
            st.write(f"**Root Rule:** `{record.get('root_rule_id')}` - *{record.get('root_rule_name')}*")
            st.write(f"**Offending Payload:**")
            st.code(record.get("waf_payload_snippet") or "None", language="text")
            st.write(f"**Audit Pointer:** `{record.get('raw_log_ref', 'N/A')}`")

    with col_t3:
        st.subheader("Tier 3: Backend Oracle")
        with st.container(border=True):
            st.write(f"**App Received Request:** `{record.get('app_received')}`")
            st.write(f"**Backend Mutated / Effect:** `{record.get('backend_effect')}`")
            st.write(f"**Oracle Observation:**")
            st.info(record.get("oracle_observation", "None"))
            st.write(f"**Metric Quadrant:** `{record.get('metric_cell')}`")
            st.write(f"**Final Verdict:** `{record.get('verdict')}`")
else:
    st.info("No evidence records available.")
