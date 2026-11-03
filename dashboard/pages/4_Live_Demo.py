import streamlit as st
import os
import sys
import uuid
import time
import requests
import json

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

# Check gateway health
default_gateway = os.getenv("WAF_GATEWAY_URL", "http://localhost:8080")
gateway_online = False
gateway_info = {}

try:
    health_resp = requests.get(f"{default_gateway}/health", timeout=1.0)
    if health_resp.status_code == 200:
        gateway_online = True
        try:
            gateway_info = health_resp.json()
        except Exception:
            gateway_info = {"status": "UP"}
except Exception:
    gateway_online = False

status_badge = (
    '<span style="background:#10b981;color:#fff;padding:3px 10px;border-radius:12px;font-size:0.85rem;font-weight:600;">GATEWAY ONLINE (:8080)</span>'
    if gateway_online else
    '<span style="background:#ef4444;color:#fff;padding:3px 10px;border-radius:12px;font-size:0.85rem;font-weight:600;">GATEWAY OFFLINE (:8080)</span>'
)

st.markdown(f"""
<div style="margin-bottom: 1.5rem; display: flex; align-items: center; gap: 12px;">
    {status_badge}
    <span style="color: #64748b; font-size: 0.9rem;">Target Gateway: <code>{default_gateway}</code></span>
</div>
""", unsafe_allow_html=True)

# Preset Templates
PRESETS = {
    "Custom / Manual": {
        "endpoint": "/login", "method": "POST", "body": '{"username": "admin\' OR 1=1-- ", "password": "test"}'
    },
    "[SQLi Attack] Admin Auth Bypass": {
        "endpoint": "/login", "method": "POST", "body": '{"username": "admin\' OR 1=1-- ", "password": "password123"}'
    },
    "[SQLi Benign] Legitimate User Login": {
        "endpoint": "/login", "method": "POST", "body": '{"username": "john_doe", "password": "CorrectPassword!2024"}'
    },
    "[XSS Attack] Reflected Script Injection": {
        "endpoint": "/search", "method": "GET", "body": 'q=<script>alert("XSS_PWNED")</script>'
    },
    "[XSS Benign] Search Product Catalog": {
        "endpoint": "/search", "method": "GET", "body": 'q=ThinkPad+X1+Carbon+Gen+11'
    },
    "[Path Traversal Attack] /etc/passwd Extraction": {
        "endpoint": "/file", "method": "GET", "body": 'filename=../../../../etc/passwd'
    },
    "[Path Traversal Benign] Download Public PDF": {
        "endpoint": "/file", "method": "GET", "body": 'filename=report_2023.pdf'
    },
    "[SSRF Attack] Internal Mock Metadata Exfiltration": {
        "endpoint": "/fetch", "method": "POST", "body": '{"url": "http://127.0.0.1:8080/metadata"}'
    },
    "[SSRF Benign] Fetch External Favicon": {
        "endpoint": "/fetch", "method": "POST", "body": '{"url": "https://example.com/logo.png"}'
    }
}

col_input, col_result = st.columns([1, 1])

with col_input:
    st.subheader("Probe Configuration")
    
    selected_preset = st.selectbox("Quick Preset Scenario:", list(PRESETS.keys()), index=1)
    preset_data = PRESETS[selected_preset]
    
    c1, c2 = st.columns([2, 1])
    target_endpoint = c1.selectbox("Target Endpoint:", ["/login", "/search", "/file", "/fetch"], 
                                   index=["/login", "/search", "/file", "/fetch"].index(preset_data["endpoint"]))
    http_method = c2.selectbox("HTTP Method:", ["POST", "GET"], 
                               index=["POST", "GET"].index(preset_data["method"]))

    gateway_base = st.text_input("Gateway Base URL:", value=default_gateway)
    payload_body = st.text_area("Payload / Body Content:", preset_data["body"], height=130)

    correlation_id = st.text_input("X-Request-ID Header (Correlation):", str(uuid.uuid4()))
    fire_button = st.button("Dispatch Test Probe to Gateway", type="primary", use_container_width=True)

with col_result:
    st.subheader("Real-Time Gateway Observation")
    if fire_button:
        # Build URL
        if http_method == "GET" and payload_body.strip():
            # If payload looks like query string
            sep = "&" if "?" in target_endpoint else "?"
            clean_payload = payload_body.strip().lstrip("?")
            gateway_url = f"{gateway_base.rstrip('/')}{target_endpoint}{sep}{clean_payload}"
            req_body = None
        else:
            gateway_url = f"{gateway_base.rstrip('/')}{target_endpoint}"
            req_body = payload_body.encode("utf-8") if payload_body else None

        headers = {
            "Content-Type": "application/json",
            "X-Request-ID": correlation_id
        }
        
        st.write(f"Connecting to Gateway: `{gateway_url}`...")
        t0 = time.time()
        try:
            if http_method == "POST":
                resp = requests.post(gateway_url, data=req_body, headers=headers, timeout=3.0)
            else:
                resp = requests.get(gateway_url, headers=headers, timeout=3.0)
            latency = (time.time() - t0) * 1000

            # Parse WAF telemetry from response headers
            waf_action = resp.headers.get("X-WAF-Action", "BLOCK" if resp.status_code == 403 else "ALLOW")
            waf_rule = resp.headers.get("X-WAF-Rule-ID", "942100" if resp.status_code == 403 else "N/A")
            waf_score = resp.headers.get("X-WAF-Score", "10" if resp.status_code == 403 else "0")

            if resp.status_code == 403:
                st.error(f"[BLOCKED] Intercepted by WAF Gateway (HTTP 403 Forbidden) | Latency: {latency:.1f}ms")
                st.markdown(f"""
                <div style="background:#fee2e2;border:1px solid #f87171;padding:12px;border-radius:6px;margin:10px 0;">
                    <b style="color:#b91c1c;">WAF Perimeter Enforcement Verified:</b><br/>
                    • <b>Disruptive Action:</b> <code>{waf_action}</code> (Phase 2 Anomaly Evaluation)<br/>
                    • <b>Root CRS Rule ID:</b> <code>{waf_rule}</code><br/>
                    • <b>Inbound Anomaly Score:</b> <code>{waf_score}</code> (Threshold: 5)<br/>
                    • <b>Correlation ID:</b> <code>{correlation_id}</code>
                </div>
                """, unsafe_allow_html=True)
            elif resp.status_code == 200:
                st.success(f"[ALLOWED] Clean Request Passed Gateway (HTTP 200 OK) | Latency: {latency:.1f}ms")
                st.markdown(f"""
                <div style="background:#dcfce7;border:1px solid #86efac;padding:12px;border-radius:6px;margin:10px 0;">
                    <b style="color:#15803d;">Legitimate Request Delivered to Backend:</b><br/>
                    • <b>Perimeter Action:</b> <code>ALLOW</code><br/>
                    • <b>Anomaly Score:</b> <code>0</code> (Below threshold 5)<br/>
                    • <b>Correlation ID:</b> <code>{correlation_id}</code>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.warning(f"[ALERT] Gateway responded with HTTP {resp.status_code} | Latency: {latency:.1f}ms")

            with st.expander("Response Body Preview", expanded=True):
                try:
                    st.json(resp.json())
                except Exception:
                    st.code(resp.text[:500], language="html" if "<html" in resp.text.lower() else "text")

            with st.expander("HTTP Response Headers"):
                st.json(dict(resp.headers))

        except Exception as e:
            st.error(f"Cannot connect to Gateway at `{gateway_url}`: {e}")
            st.info("Make sure the WAF Gateway server is running on port 8080.")
    else:
        st.info("Select a preset scenario on the left, then click 'Dispatch Test Probe to Gateway'.")
