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

st.set_page_config(page_title="Executive Overview - WAFBench", layout="wide", initial_sidebar_state="expanded")
apply_academic_styling()

st.title("Executive KPI & Benchmark Overview")
st.markdown("Quantitative WAF evaluation metrics according to Table 4.6 and Table 5.2 ($DR$, $BR$, $FPR_D$, $FPR_B$, $RPR$).")

def load_data():
    sample_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sample_events.json")
    if os.path.exists(sample_file):
        with open(sample_file, "r", encoding="utf-8") as f:
            return pd.DataFrame(json.load(f))
    return pd.DataFrame()

df = load_data()

if not df.empty:
    valid_df = df[df["validity"] == "VALID"]
    
    # 1. Core KPIs
    c1, c2, c3, c4 = st.columns(4)
    tp_b = len(valid_df[valid_df["metric_cell"] == "TP_B"])
    fn_b = len(valid_df[valid_df["metric_cell"] == "FN_B"])
    br = (tp_b / (tp_b + fn_b) * 100) if (tp_b + fn_b) > 0 else 0.0

    tp_d = len(valid_df[valid_df["metric_cell"] == "TP_D"])
    fn_d = len(valid_df[valid_df["metric_cell"] == "FN_D"])
    dr = (tp_d / (tp_d + fn_d) * 100) if (tp_d + fn_d) > 0 else 0.0

    fp_d = len(valid_df[valid_df["metric_cell"] == "FP_D"])
    tn_d = len(valid_df[valid_df["metric_cell"] == "TN_D"])
    fpr_d = (fp_d / (fp_d + tn_d) * 100) if (fp_d + tn_d) > 0 else 0.0

    fp_b = len(valid_df[valid_df["metric_cell"] == "FP_B"])
    tn_b = len(valid_df[valid_df["metric_cell"] == "TN_B"])
    fpr_b = (fp_b / (fp_b + tn_b) * 100) if (fp_b + tn_b) > 0 else 0.0

    c1.metric("Empirical Blocking Rate (BR)", f"{br:.1f}%", f"{tp_b} of {tp_b+fn_b} malicious blocked")
    c2.metric("Detection Rate (DR)", f"{dr:.1f}%", f"{tp_d} of {tp_d+fn_d} malicious detected")
    c3.metric("Detection FPR", f"{fpr_d:.1f}%", f"{fp_d} false alarms")
    c4.metric("Blocking FPR", f"{fpr_b:.1f}%", f"{fp_b} erroneous blocks")

    st.markdown("---")

    # 2. Confusion Matrices (Detection vs Blocking)
    col_cm1, col_cm2 = st.columns(2)

    with col_cm1:
        st.subheader("Confusion Matrix: Blocking Mode")
        cm_blocking = pd.DataFrame({
            "Backend Uncompromised": [f"TP_B ({tp_b})", f"FP_B ({fp_b})"],
            "Backend Compromised": [f"FN_B ({fn_b})", f"TN_B ({tn_b})"]
        }, index=["Actual Malicious", "Actual Benign/Edge"])
        st.table(cm_blocking)

    with col_cm2:
        st.subheader("Confusion Matrix: DetectionOnly Mode")
        cm_detection = pd.DataFrame({
            "WAF Detected (Score >= 5)": [f"TP_D ({tp_d})", f"FP_D ({fp_d})"],
            "WAF Passed (Score < 5)": [f"FN_D ({fn_d})", f"TN_D ({tn_d})"]
        }, index=["Actual Malicious", "Actual Benign/Edge"])
        st.table(cm_detection)

    st.markdown("---")
    st.subheader("Validity Classification & Sample Breakdown")
    v_counts = df["validity"].value_counts().reset_index()
    v_counts.columns = ["Validity Status", "Count"]
    st.dataframe(v_counts, use_container_width=True)
else:
    st.info("No records available to compute benchmark statistics.")
