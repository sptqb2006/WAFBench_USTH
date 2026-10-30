import streamlit as st

st.set_page_config(page_title="Executive Overview - WAFBench", layout="wide")
st.title("Executive KPI & Benchmark Overview")
st.markdown("Quantitative WAF evaluation metrics according to Table 5.2 (DR, BR, FPR_D, FPR_B, RPR).")

st.info("Displays detailed distributions of anomaly scores, confusion matrices, and validity classification breakdowns.")
