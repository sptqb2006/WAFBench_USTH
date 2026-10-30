import streamlit as st
import os
import psycopg2
from psycopg2.extras import RealDictCursor
import pandas as pd

st.set_page_config(
    page_title="WAFBench Analytics Dashboard",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title("WAFBench: Evidence-First WAF Evaluation Dashboard")
st.markdown("""
Evaluation and visualization platform for Web Application Firewall performance
(Nginx 1.26 + ModSecurity v3 + OWASP Core Rule Set v4.0.0).
""")

# Sidebar info
st.sidebar.markdown("### System Status")
st.sidebar.info("""
- Gateway: :8080 (Nginx + ModSec v3)
- Direct-to-App: :8001 (Loopback baseline)
- Engine Mode: C0 Baseline (PL1, Inbound 5/4)
""")

# Database Connection Helper
def get_db_data():
    try:
        conn = psycopg2.connect(
            host=os.getenv("EVENT_DB_HOST", "localhost"),
            port=int(os.getenv("EVENT_DB_PORT", "5432")),
            dbname=os.getenv("EVENT_DB_NAME", "wafbench_events"),
            user=os.getenv("EVENT_DB_USER", "telemetry_user"),
            password=os.getenv("EVENT_DB_PASSWORD", "telemetry_secret_pass"),
            cursor_factory=RealDictCursor
        )
        query = "SELECT * FROM normalized_events ORDER BY id DESC LIMIT 500;"
        df = pd.read_sql(query, conn)
        conn.close()
        return df
    except Exception:
        return None

df = get_db_data()

# Metric Summary Cards
col1, col2, col3, col4 = st.columns(4)

if df is not None and not df.empty:
    tp_d = len(df[df['metric_cell'] == 'TP_D'])
    fn_d = len(df[df['metric_cell'] == 'FN_D'])
    dr = (tp_d / (tp_d + fn_d) * 100) if (tp_d + fn_d) > 0 else 0

    tp_b = len(df[df['metric_cell'] == 'TP_B'])
    fn_b = len(df[df['metric_cell'] == 'FN_B'])
    br = (tp_b / (tp_b + fn_b) * 100) if (tp_b + fn_b) > 0 else 0

    fp_d = len(df[df['metric_cell'] == 'FP_D'])
    tn_d = len(df[df['metric_cell'] == 'TN_D'])
    fpr_d = (fp_d / (fp_d + tn_d) * 100) if (fp_d + tn_d) > 0 else 0

    fp_b = len(df[df['metric_cell'] == 'FP_B'])
    tn_b = len(df[df['metric_cell'] == 'TN_B'])
    fpr_b = (fp_b / (fp_b + tn_b) * 100) if (fp_b + tn_b) > 0 else 0

    col1.metric("Detection Rate (DR)", f"{dr:.1f}%", f"{tp_d}/{tp_d+fn_d} cases")
    col2.metric("Blocking Rate (BR)", f"{br:.1f}%", f"{tp_b}/{tp_b+fn_b} cases")
    col3.metric("Detection FPR", f"{fpr_d:.1f}%", f"{fp_d} false alarms")
    col4.metric("Blocking FPR", f"{fpr_b:.1f}%", f"{fp_b} erroneous blocks")
else:
    col1.metric("Detection Rate (DR)", "N/A", "Awaiting execution")
    col2.metric("Blocking Rate (BR)", "N/A", "Awaiting execution")
    col3.metric("Detection FPR", "N/A", "Awaiting execution")
    col4.metric("Blocking FPR", "N/A", "Awaiting execution")

st.markdown("---")
st.subheader("Recent Telemetry Events")

if df is not None and not df.empty:
    st.dataframe(df[['correlation_id', 'case_id', 'state', 'label', 'inbound_score', 'disruptive_action', 'verdict', 'metric_cell']], use_container_width=True)
else:
    st.info("No empirical records found in database. Run 'make test' to collect telemetry.")
