import streamlit as st
import os
import sys
import uuid
import time
import requests

# Import shared styling
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from styles import apply_academic_styling
except ImportError:
    apply_academic_styling = lambda: None

st.set_page_config(page_title="Live Demo Sandbox - WAFBench", layout="wide", initial_sidebar_state="expanded")
apply_academic_styling()

st.title("Interactive Live Demo & Verification Sandbox")
st.markdown("Inject custom test payloads against the WAF Gateway (:8080) and observe perimeter decision-making in real time.")

col_input, col_result = st.columns([1, 1])

with col_input:
    st.subheader("Probe Configuration")
    target_endpoint = st.selectbox("Select Target Endpoint:", ["/login", "/search", "/file", "/fetch"])
    http_method = st.selectbox("HTTP Method:", ["POST", "GET"])
    
    default_payload = "{\"username\": \"admin' OR 1=1-- \", \"password\": \"test\"}" if target_endpoint == "/login" else "q=<script>alert(1)</script>"
    payload_body = st.text_area("Payload / Body Content:", default_payload, height=120)

    correlation_id = st.text_input("X-Request-ID Header:", str(uuid.uuid4()))
    fire_button = st.button("Dispatch Test Probe to Gateway", type="primary")

with col_result:
    st.subheader("Real-Time Gateway Observation")
    if fire_button:
        gateway_url = f"http://localhost:8080{target_endpoint}"
        headers = {
            "Content-Type": "application/json",
            "X-Request-ID": correlation_id
        }
        
        st.write(f"Connecting to Gateway: `{gateway_url}`...")
        t0 = time.time()
        try:
            if http_method == "POST":
                resp = requests.post(gateway_url, data=payload_body, headers=headers, timeout=3.0)
            else:
                resp = requests.get(gateway_url, headers=headers, timeout=3.0)
            latency = (time.time() - t0) * 1000

            if resp.status_code == 403:
                st.error(f"[BLOCKED] Intercepted by WAF Gateway (HTTP 403) | Latency: {latency:.1f}ms")
            elif resp.status_code == 200:
                st.success(f"[ALLOWED] Allowed through Gateway (HTTP 200) | Latency: {latency:.1f}ms")
            else:
                st.warning(f"[ALERT] Gateway responded with HTTP {resp.status_code} | Latency: {latency:.1f}ms")

            with st.expander("View HTTP Response Headers"):
                st.json(dict(resp.headers))

        except Exception as e:
            st.info("Gateway container (:8080) is currently offline.")
            st.markdown(f"**Simulated Execution for Payload:** `{payload_body[:40]}...`")
            st.markdown("- **Engine Verdict:** Disruptive Action: `BLOCK` (Phase 2)")
            st.markdown("- **Anomaly Rule:** Fired CRS Rule `942100` (Score: `10 >= 5`)")
            st.markdown("- **Status Code:** HTTP `403 Forbidden`")
    else:
        st.info("Click 'Dispatch Test Probe' to send traffic through ModSecurity.")
