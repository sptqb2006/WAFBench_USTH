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

# Inject Animate UI Motion Tokens and Micro-interactions
st.markdown("""
<style>
    /* -------------------------------------------------------------
       Animate UI Motion Tokens & Academic Design System
       ------------------------------------------------------------- */
    
    /* Primary Dispatch Button with spring.press (scale 0.97) */
    div.stButton > button,
    button[kind="primary"],
    button[data-testid="stBaseButton-primary"] {
        transition: transform 0.15s cubic-bezier(0.23, 1, 0.32, 1),
                    box-shadow 0.15s cubic-bezier(0.23, 1, 0.32, 1),
                    background-color 0.15s ease,
                    border-color 0.15s ease !important;
        border-radius: 6px !important;
        font-weight: 600 !important;
        letter-spacing: 0.01em !important;
    }

    div.stButton > button:hover,
    button[kind="primary"]:hover,
    button[data-testid="stBaseButton-primary"]:hover {
        box-shadow: 0 2px 8px rgba(26, 115, 232, 0.25) !important;
    }

    div.stButton > button:active,
    button[kind="primary"]:active,
    button[data-testid="stBaseButton-primary"]:active {
        transform: scale(0.97) !important; /* spring.press */
    }

    /* Scenario Card Presentation & spring.choice (scale 0.985) */
    .scenario-preset-card {
        background-color: #f8f9fa;
        border: 1px solid #dadce0;
        border-radius: 6px;
        padding: 12px 14px;
        margin: 8px 0 16px 0;
        box-shadow: 0 1px 2px rgba(60, 64, 67, 0.06);
        transition: transform 0.15s cubic-bezier(0.23, 1, 0.32, 1),
                    border-color 0.15s ease,
                    box-shadow 0.15s ease;
    }

    .scenario-preset-card:hover {
        border-color: #1a73e8;
        box-shadow: 0 2px 6px rgba(60, 64, 67, 0.12);
    }

    .scenario-preset-card:active {
        transform: scale(0.985); /* scale.choice */
    }

    /* Verdict Alert Cards with subtle glow and borders */
    .alert-block {
        background-color: #fef2f2;
        border: 1px solid #fecaca;
        border-left: 4px solid #dc2626;
        border-radius: 6px;
        padding: 14px 16px;
        margin: 12px 0;
        box-shadow: 0 1px 3px rgba(220, 38, 38, 0.08), 0 0 0 1px rgba(220, 38, 38, 0.05);
    }

    .alert-allow {
        background-color: #f0fdf4;
        border: 1px solid #bbf7d0;
        border-left: 4px solid #16a34a;
        border-radius: 6px;
        padding: 14px 16px;
        margin: 12px 0;
        box-shadow: 0 1px 3px rgba(22, 163, 74, 0.08), 0 0 0 1px rgba(22, 163, 74, 0.05);
    }

    .alert-warning {
        background-color: #fffbeb;
        border: 1px solid #fef3c7;
        border-left: 4px solid #d97706;
        border-radius: 6px;
        padding: 14px 16px;
        margin: 12px 0;
        box-shadow: 0 1px 3px rgba(217, 119, 6, 0.08);
    }

    .verdict-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 10px;
        padding-bottom: 8px;
        border-bottom: 1px solid rgba(0, 0, 0, 0.06);
    }

    .verdict-title {
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 0.95rem;
        font-weight: 700;
    }

    .verdict-badge {
        font-size: 0.75rem;
        font-weight: 600;
        padding: 2px 8px;
        border-radius: 4px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }

    .verdict-grid {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 8px 16px;
        font-size: 0.85rem;
        color: #3c4043;
    }

    .verdict-row {
        display: flex;
        justify-content: space-between;
        padding: 3px 0;
    }

    .verdict-label {
        color: #5f6368;
        font-weight: 500;
    }

    .verdict-value {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-weight: 600;
        color: #202124;
    }

    /* Respect Reduced Motion */
    @media (prefers-reduced-motion: reduce) {
        *, *::before, *::after {
            transition-duration: 0.01ms !important;
            animation-duration: 0.01ms !important;
        }
    }
</style>
""", unsafe_allow_html=True)

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
    '<span class="academic-badge academic-badge-live" style="display:inline-flex; align-items:center; gap:6px;">'
    '<svg width="8" height="8" viewBox="0 0 8 8" fill="none"><circle cx="4" cy="4" r="3" fill="#137333" stroke="#34a853" stroke-width="1.5"/></svg>'
    'GATEWAY ONLINE (:8080)'
    '</span>'
    if gateway_online else
    '<span class="academic-badge" style="display:inline-flex; align-items:center; gap:6px; border-color:#ea4335; color:#c5221f; background-color:#fce8e6;">'
    '<svg width="8" height="8" viewBox="0 0 8 8" fill="none"><circle cx="4" cy="4" r="3" fill="#b3261e" stroke="#ea4335" stroke-width="1.5"/></svg>'
    'GATEWAY OFFLINE (:8080)'
    '</span>'
)

st.markdown(f"""
<div class="academic-header">
    <div style="font-size: 1.5rem; font-weight: 600; margin: 0 0 4px 0;">
        Interactive Live Demo & Verification Sandbox
    </div>
    <div style="font-size: 0.88rem; color: #5f6368;">
        Inject custom test payloads against the WAF Gateway (:8080) and observe perimeter decision-making in real time.
    </div>
    <div class="academic-badge-row" style="margin-top: 10px;">
        {status_badge}
        <span class="academic-badge">Target: <code>{default_gateway}</code></span>
        <span class="academic-badge">Evaluation Protocol: HTTP/1.1</span>
        <span class="academic-badge">Paranoia Level: PL1</span>
        <span class="academic-badge">Inbound Score Threshold: 5</span>
    </div>
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
    with st.container(border=True):
        st.subheader("Probe Configuration")
        
        selected_preset = st.selectbox("Quick Preset Scenario:", list(PRESETS.keys()), index=1)
        preset_data = PRESETS[selected_preset]
        
        # Scenario preset presentation card with spring.choice
        if "Attack" in selected_preset:
            exp_color = "#b91c1c"
            exp_bg = "#fee2e2"
            exp_border = "#fca5a5"
            exp_badge = "EXPECTED: BLOCK (403)"
            scenario_desc = "Malicious signature payload targeting perimeter vulnerability filter."
        elif "Benign" in selected_preset:
            exp_color = "#15803d"
            exp_bg = "#dcfce7"
            exp_border = "#86efac"
            exp_badge = "EXPECTED: ALLOW (200)"
            scenario_desc = "Legitimate standard payload designed to verify zero false positives."
        else:
            exp_color = "#1e40af"
            exp_bg = "#dbeafe"
            exp_border = "#93c5fd"
            exp_badge = "USER DEFINED PROBE"
            scenario_desc = "Custom user-supplied endpoint, HTTP method, and payload content."

        st.markdown(f"""
        <div class="scenario-preset-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                <span style="font-size:0.75rem; font-weight:700; text-transform:uppercase; letter-spacing:0.04em; color:#5f6368;">Scenario Profile</span>
                <span style="font-size:0.72rem; font-weight:600; padding:2px 8px; border-radius:4px; background:{exp_bg}; color:{exp_color}; border:1px solid {exp_border}; font-family:ui-monospace, monospace;">{exp_badge}</span>
            </div>
            <div style="font-size:0.85rem; color:#202124; font-weight:500;">
                {scenario_desc}
            </div>
            <div style="font-size:0.78rem; color:#5f6368; margin-top:6px; display:flex; gap:12px;">
                <span>Default Endpoint: <code>{preset_data['endpoint']}</code></span>
                <span>Default Method: <code>{preset_data['method']}</code></span>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        available_endpoints = ["/login", "/search", "/file", "/fetch"]
        endpoint_idx = available_endpoints.index(preset_data["endpoint"]) if preset_data["endpoint"] in available_endpoints else 0
        
        available_methods = ["POST", "GET"]
        method_idx = available_methods.index(preset_data["method"]) if preset_data["method"] in available_methods else 0

        c1, c2 = st.columns([2, 1])
        target_endpoint = c1.selectbox("Target Endpoint:", available_endpoints, index=endpoint_idx)
        http_method = c2.selectbox("HTTP Method:", available_methods, index=method_idx)

        gateway_base = st.text_input("Gateway Base URL:", value=default_gateway)
        payload_body = st.text_area("Payload / Body Content:", preset_data["body"], height=130)

        correlation_id = st.text_input("X-Request-ID Header (Correlation):", str(uuid.uuid4()))
        fire_button = st.button("Dispatch Test Probe to Gateway", type="primary", use_container_width=True)

with col_result:
    with st.container(border=True):
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
            
            st.markdown(f'<div style="font-size:0.85rem; color:#5f6368; margin-bottom:8px;">Connecting to Gateway: <code>{gateway_url}</code>...</div>', unsafe_allow_html=True)
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
                    st.markdown(f"""
                    <div class="alert-block">
                        <div class="verdict-header">
                            <div class="verdict-title" style="color: #b91c1c;">
                                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#dc2626" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <circle cx="12" cy="12" r="10"></circle>
                                    <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line>
                                </svg>
                                <span>Perimeter Enforcement Verified (HTTP 403 Forbidden)</span>
                            </div>
                            <span class="verdict-badge" style="background: #fee2e2; color: #991b1b; border: 1px solid #fca5a5;">
                                {latency:.1f} ms
                            </span>
                        </div>
                        <div class="verdict-grid">
                            <div class="verdict-row">
                                <span class="verdict-label">Perimeter Action:</span>
                                <span class="verdict-value">{waf_action} (Phase 2 Anomaly)</span>
                            </div>
                            <div class="verdict-row">
                                <span class="verdict-label">Triggered CRS Rule:</span>
                                <span class="verdict-value">{waf_rule}</span>
                            </div>
                            <div class="verdict-row">
                                <span class="verdict-label">Inbound Anomaly Score:</span>
                                <span class="verdict-value">{waf_score} (Threshold: 5)</span>
                            </div>
                            <div class="verdict-row">
                                <span class="verdict-label">Perimeter Status:</span>
                                <span class="verdict-value">Intercepted & Blocked</span>
                            </div>
                        </div>
                        <div style="margin-top: 10px; padding-top: 8px; border-top: 1px solid #fecaca; font-size: 0.8rem; color: #7f1d1d;">
                            <b>Correlation ID:</b> <code style="background: #fee2e2; color: #991b1b; padding: 2px 6px; border-radius: 4px;">{correlation_id}</code>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                elif resp.status_code == 200:
                    st.markdown(f"""
                    <div class="alert-allow">
                        <div class="verdict-header">
                            <div class="verdict-title" style="color: #15803d;">
                                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#16a34a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                                    <polyline points="22 4 12 14.01 9 11.01"></polyline>
                                </svg>
                                <span>Clean Traffic Passed Gateway (HTTP 200 OK)</span>
                            </div>
                            <span class="verdict-badge" style="background: #dcfce7; color: #166534; border: 1px solid #86efac;">
                                {latency:.1f} ms
                            </span>
                        </div>
                        <div class="verdict-grid">
                            <div class="verdict-row">
                                <span class="verdict-label">Perimeter Action:</span>
                                <span class="verdict-value">ALLOW</span>
                            </div>
                            <div class="verdict-row">
                                <span class="verdict-label">Triggered CRS Rule:</span>
                                <span class="verdict-value">None (Clean Traffic)</span>
                            </div>
                            <div class="verdict-row">
                                <span class="verdict-label">Inbound Anomaly Score:</span>
                                <span class="verdict-value">{waf_score} (Below Threshold 5)</span>
                            </div>
                            <div class="verdict-row">
                                <span class="verdict-label">Backend Delivery:</span>
                                <span class="verdict-value">Successfully Delivered</span>
                            </div>
                        </div>
                        <div style="margin-top: 10px; padding-top: 8px; border-top: 1px solid #bbf7d0; font-size: 0.8rem; color: #14532d;">
                            <b>Correlation ID:</b> <code style="background: #dcfce7; color: #166534; padding: 2px 6px; border-radius: 4px;">{correlation_id}</code>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div class="alert-warning">
                        <div class="verdict-header">
                            <div class="verdict-title" style="color: #b45309;">
                                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#d97706" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <circle cx="12" cy="12" r="10"></circle>
                                    <line x1="12" y1="8" x2="12" y2="12"></line>
                                    <line x1="12" y1="16" x2="12.01" y2="16"></line>
                                </svg>
                                <span>Perimeter Gateway Alert (HTTP {resp.status_code})</span>
                            </div>
                            <span class="verdict-badge" style="background: #fef3c7; color: #92400e; border: 1px solid #fde68a;">
                                {latency:.1f} ms
                            </span>
                        </div>
                        <div class="verdict-grid">
                            <div class="verdict-row">
                                <span class="verdict-label">HTTP Status Code:</span>
                                <span class="verdict-value">{resp.status_code}</span>
                            </div>
                            <div class="verdict-row">
                                <span class="verdict-label">Perimeter Action:</span>
                                <span class="verdict-value">{waf_action}</span>
                            </div>
                            <div class="verdict-row">
                                <span class="verdict-label">Inbound Anomaly Score:</span>
                                <span class="verdict-value">{waf_score}</span>
                            </div>
                            <div class="verdict-row">
                                <span class="verdict-label">Triggered CRS Rule:</span>
                                <span class="verdict-value">{waf_rule}</span>
                            </div>
                        </div>
                        <div style="margin-top: 10px; padding-top: 8px; border-top: 1px solid #fde68a; font-size: 0.8rem; color: #78350f;">
                            <b>Correlation ID:</b> <code style="background: #fef3c7; color: #92400e; padding: 2px 6px; border-radius: 4px;">{correlation_id}</code>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                with st.expander("Response Body Preview", expanded=True):
                    try:
                        st.json(resp.json())
                    except Exception:
                        st.code(resp.text[:500], language="html" if "<html" in resp.text.lower() else "text")

                with st.expander("HTTP Response Headers"):
                    st.json(dict(resp.headers))

            except Exception as e:
                st.error(f"Cannot connect to Gateway at `{gateway_url}`: {e}")
                st.info("Ensure the WAF Gateway server is running and accessible on port 8080.")
        else:
            st.markdown("""
            <div style="background-color: #f8f9fa; border: 1px dashed #dadce0; border-radius: 6px; padding: 32px 20px; text-align: center; color: #5f6368; margin-top: 8px;">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#9aa0a6" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom: 10px; display: block; margin-left: auto; margin-right: auto;">
                    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
                </svg>
                <div style="font-weight: 600; color: #3c4043; font-size: 0.95rem; margin-bottom: 4px;">Awaiting Probe Dispatch</div>
                <div style="font-size: 0.84rem; max-width: 420px; margin: 0 auto; line-height: 1.4;">Select a scenario preset on the left or customize your payload parameters, then click <b>Dispatch Test Probe to Gateway</b>.</div>
            </div>
            """, unsafe_allow_html=True)
