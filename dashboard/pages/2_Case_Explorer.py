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

st.set_page_config(page_title="Case Explorer - WAFBench", layout="wide", initial_sidebar_state="expanded")
apply_academic_styling()

st.title("Multi-Dimensional Case Explorer")
st.markdown("Filter, search, and drill down into evaluation test cases by vulnerability class, CRS rule ID, and execution state.")

def load_data():
    sample_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sample_events.json")
    if os.path.exists(sample_file):
        with open(sample_file, "r", encoding="utf-8") as f:
            return pd.DataFrame(json.load(f))
    return pd.DataFrame()

df = load_data()

if not df.empty:
    col1, col2, col3 = st.columns(3)
    
    families = ["All"] + sorted(list(df["family_id"].dropna().unique()))
    sel_family = col1.selectbox("Filter by Threat Family", families)

    states = ["All"] + sorted(list(df["state"].dropna().unique()))
    sel_state = col2.selectbox("Filter by Execution State", states)

    verdicts = ["All"] + sorted(list(df["verdict"].dropna().unique()))
    sel_verdict = col3.selectbox("Filter by Evaluation Verdict", verdicts)

    filtered = df.copy()
    if sel_family != "All":
        filtered = filtered[filtered["family_id"] == sel_family]
    if sel_state != "All":
        filtered = filtered[filtered["state"] == sel_state]
    if sel_verdict != "All":
        filtered = filtered[filtered["verdict"] == sel_verdict]

    st.markdown(f"**Found {len(filtered)} matching test cases**")

    display_cols = [
        "case_id", "family_id", "state", "method", "endpoint", 
        "client_status", "root_rule_id", "inbound_score", "verdict", "metric_cell"
    ]
    st.dataframe(filtered[[c for c in display_cols if c in filtered.columns]], use_container_width=True)
else:
    st.info("No test cases found.")
