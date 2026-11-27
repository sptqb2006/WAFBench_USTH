#!/usr/bin/env python3
"""
WAFBench Dashboard Styling Module
Modern Academic Design System with Slate/Zinc Neutral Palette & Animate UI Motion Tokens.
Sleek, Compact Pinned Sidebar (200px) with Collapse Button Removed.
"""

import streamlit as st


def apply_academic_styling():
    """
    Injects crisp, consistent Light Academic Theme CSS.
    Applies slate/zinc neutral surfaces, high-contrast typography,
    and physics-based micro-interactions.
    """
    st.markdown("""
    <style>
        /* -------------------------------------------------------------
           0. Design Tokens: Slate/Zinc Palette & Animate UI Motion Engine
           ------------------------------------------------------------- */
        :root {
            /* Neutral Slate/Zinc Surfaces & Typography */
            --text-primary: #0f172a;           /* slate-900 */
            --text-secondary: #475569;         /* slate-600 */
            --text-muted: #64748b;             /* slate-500 */
            --border-subtle: #e2e8f0;          /* slate-200 */
            --border-strong: #cbd5e1;          /* slate-300 */
            --surface-bg: #ffffff;             /* pure white */
            --surface-secondary: #f8fafc;      /* slate-50 */
            --surface-tertiary: #f1f5f9;       /* slate-100 */

            /* Accent Tokens */
            --accent-primary: #0284c7;         /* sky-600 */
            --accent-hover: #0369a1;           /* sky-700 */
            --accent-subtle: #e0f2fe;          /* sky-100 */
            --accent-glow: rgba(2, 132, 199, 0.15);

            /* Semantic Status Tokens */
            --status-success: #16a34a;         /* green-600 */
            --status-success-bg: #f0fdf4;      /* green-50 */
            --status-success-border: #bbf7d0;  /* green-200 */

            --status-error: #dc2626;           /* red-600 */
            --status-error-bg: #fef2f2;        /* red-50 */
            --status-error-border: #fecaca;    /* red-200 */

            --status-warning: #d97706;         /* amber-600 */
            --status-warning-bg: #fffbeb;      /* amber-50 */
            --status-warning-border: #fde68a;  /* amber-200 */

            /* Animate UI Motion Linear Springs */
            --spring-press: 400ms linear(0, 0.0261, 0.0935, 0.188, 0.2977, 0.4132, 0.5271, 0.6343, 0.7313, 0.8159, 0.8872, 0.9452, 0.9906, 1.0244, 1.048, 1.063, 1.0709, 1.0732, 1.0713, 1.0663, 1.0594, 1.0514, 1.0429, 1.0346, 1.0267, 1.0196, 1.0134, 1.0082, 1.004, 1.0007, 0.9982, 0.9965, 1, 0.9948, 0.9946, 0.9948, 1, 1, 1, 1);
            --spring-pop: 450ms linear(0, 0.0189, 0.0684, 0.1388, 0.2222, 0.3122, 0.404, 0.4937, 0.5786, 0.657, 0.7276, 0.7899, 0.8438, 0.8895, 0.9275, 0.9583, 0.9828, 1.0015, 1.0154, 1.0252, 1.0316, 1.0352, 1.0366, 1.0363, 1.0348, 1.0324, 1.0294, 1.0262, 1.0228, 1.0195, 1.0163, 1.0134, 1.0107, 1.0083, 1.0063, 1.0045, 1.003, 1.0018, 1.0009, 1.0001, 0.9996, 0.9992, 0.9989, 1, 1);
            --spring-dialog: 750ms linear(0, 0.0071, 0.0261, 0.0541, 0.0886, 0.1279, 0.1702, 0.2143, 0.2592, 0.3041, 0.3485, 0.3918, 0.4336, 0.4738, 0.5121, 0.5485, 0.5829, 0.6153, 0.6456, 0.674, 0.7004, 0.725, 0.7479, 0.769, 0.7886, 0.8066, 0.8233, 0.8386, 0.8527, 0.8656, 0.8775, 0.8884, 0.8983, 0.9074, 0.9158, 0.9234, 0.9303, 0.9367, 0.9424, 0.9477, 0.9525, 0.9569, 0.9609, 0.9645, 0.9678, 0.9708, 0.9735, 0.976, 0.9782, 0.9803, 0.9821, 0.9838, 0.9853, 0.9867, 0.9879, 0.9891, 0.9901, 0.9911, 0.9919, 0.9927, 0.9934, 0.994, 0.9946, 0.9951, 0.9955, 0.996, 0.9964, 0.9967, 0.997, 0.9973, 0.9976, 0.9978, 1, 1, 1);
            --spring-highlight: 300ms linear(0, 0.0233, 0.0813, 0.1598, 0.2483, 0.3396, 0.4288, 0.5126, 0.5894, 0.658, 0.7183, 0.7704, 0.8149, 0.8524, 0.8837, 0.9094, 0.9303, 0.9472, 0.9607, 0.9713, 0.9796, 0.986, 0.9908, 0.9944, 0.997, 0.9988, 1.0001, 1.001, 1.0015, 1);
            --ease-out: cubic-bezier(0.16, 1, 0.3, 1);

            /* Surface Radii & Shadows */
            --radius-sm: 6px;
            --radius-md: 8px;
            --radius-lg: 10px;
            --shadow-subtle: 0 1px 3px rgba(0, 0, 0, 0.05), 0 1px 2px rgba(0, 0, 0, 0.03);
            --shadow-elevated: 0 4px 6px -1px rgba(0, 0, 0, 0.07), 0 2px 4px -2px rgba(0, 0, 0, 0.05);
            --shadow-popover: 0 10px 25px -5px rgba(0, 0, 0, 0.08), 0 8px 10px -6px rgba(0, 0, 0, 0.04);
        }

        /* Strict Accessibility: Zero Transitions & Animations for Reduced Motion */
        @media (prefers-reduced-motion: reduce) {
            *,
            *::before,
            *::after {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
                transition-delay: 0s !important;
                scroll-behavior: auto !important;
            }
        }

        /* -------------------------------------------------------------
           1. Pure Light Base Typography & Surfaces
           ------------------------------------------------------------- */
        body, .stApp {
            background-color: var(--surface-bg) !important;
            color: var(--text-primary) !important;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif !important;
            -webkit-font-smoothing: antialiased !important;
            -moz-osx-font-smoothing: grayscale !important;
        }

        /* Primary Headings */
        h1, h2, h3, h4, h5, h6 {
            color: var(--text-primary) !important;
            font-weight: 600 !important;
            letter-spacing: -0.02em !important;
        }

        p, span, label, div {
            color: inherit;
        }

        /* Subtle secondary text utility */
        .text-secondary {
            color: var(--text-secondary) !important;
        }
        .text-muted {
            color: var(--text-muted) !important;
        }

        /* Main content container */
        [data-testid="stMainBlockContainer"],
        .block-container {
            padding-top: 1.5rem !important;
            padding-bottom: 2.5rem !important;
            padding-left: 2rem !important;
            padding-right: 2rem !important;
            max-width: 100% !important;
        }

        /* -------------------------------------------------------------
           2. Sleek, Compact Pinned Sidebar (200px) & Top Bar
           ------------------------------------------------------------- */
        
        /* Fixed 200px sidebar width & rigid boundary */
        section[data-testid="stSidebar"],
        section#stSidebar,
        div[data-testid="stSidebar"] {
            width: 200px !important;
            min-width: 200px !important;
            max-width: 200px !important;
            background-color: var(--surface-secondary) !important;
            border-right: 1px solid var(--border-subtle) !important;
            box-sizing: border-box !important;
        }

        section[data-testid="stSidebar"] > div:first-child,
        div[data-testid="stSidebar"] > div:first-child {
            width: 200px !important;
            min-width: 200px !important;
            max-width: 200px !important;
            box-sizing: border-box !important;
        }

        [data-testid="stSidebarContent"],
        [data-testid="stSidebarUserContent"] {
            background-color: var(--surface-secondary) !important;
            padding: 8px 6px !important;
            width: 200px !important;
            max-width: 200px !important;
            box-sizing: border-box !important;
        }

        /* Suppress sidebar resize trigger handles */
        [data-testid="stSidebarResizer"],
        div[class*="resizeTrigger"] {
            display: none !important;
            pointer-events: none !important;
        }
        
        /* Top bar / header styling */
        [data-testid="stHeader"],
        header[data-testid="stHeader"] {
            background-color: var(--surface-bg) !important;
            border-bottom: 1px solid var(--border-subtle) !important;
        }
            
        /* Suppress sidebar collapse triggers */
        [data-testid="stSidebarCollapseButton"],
        button[aria-label="Collapse sidebar"],
        button[aria-label="Close sidebar"],
        button[data-testid="stSidebarChevron"],
        button[data-testid="baseButton-headerNoPadding"],
        [data-testid="stSidebarHeader"] button {
            display: none !important;
            visibility: hidden !important;
            pointer-events: none !important;
            width: 0 !important;
            height: 0 !important;
            margin: 0 !important;
            padding: 0 !important;
        }

        [data-testid="stSidebarHeader"] {
            display: none !important;
            height: 0 !important;
            padding: 0 !important;
            margin: 0 !important;
        }

        /* Open/Expand Sidebar Trigger Button with Animate UI tokens */
        [data-testid="collapsedControl"],
        [data-testid="stExpandSidebarButton"],
        button[aria-label="Expand sidebar"],
        button[aria-label="Open sidebar"] {
            display: flex !important;
            visibility: visible !important;
            opacity: 1 !important;
            background-color: var(--surface-bg) !important;
            border: 1px solid var(--border-subtle) !important;
            border-radius: var(--radius-md) !important;
            box-shadow: var(--shadow-subtle) !important;
            transition: transform var(--spring-press), background-color var(--spring-highlight), border-color var(--spring-highlight), box-shadow var(--spring-highlight) !important;
        }

        [data-testid="collapsedControl"]:hover,
        [data-testid="stExpandSidebarButton"]:hover,
        button[aria-label="Expand sidebar"]:hover,
        button[aria-label="Open sidebar"]:hover {
            box-shadow: 0 2px 6px var(--accent-glow) !important;
            border-color: var(--accent-primary) !important;
            background-color: var(--surface-secondary) !important;
        }

        [data-testid="collapsedControl"]:active,
        [data-testid="stExpandSidebarButton"]:active,
        button[aria-label="Expand sidebar"]:active,
        button[aria-label="Open sidebar"]:active {
            transform: scale(0.97) !important; /* spring.press for buttons */
        }

        [data-testid="collapsedControl"] button,
        [data-testid="stExpandSidebarButton"] button {
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            color: var(--accent-primary) !important;
            background: transparent !important;
            border: none !important;
            cursor: pointer !important;
        }

        /* Suppress unnecessary Streamlit deploy button */
        [data-testid="stAppDeployButton"] {
            display: none !important;
        }

        /* Remove Print option from MainMenu (...) */
        [data-testid="stMainMenuItem-print"],
        li:has([data-testid="stMainMenuItem-print"]),
        ul[role="menu"] > li:has([data-testid="stMainMenuItem-print"]) {
            display: none !important;
            visibility: hidden !important;
            height: 0 !important;
            min-height: 0 !important;
            max-height: 0 !important;
            padding: 0 !important;
            margin: 0 !important;
            overflow: hidden !important;
        }

        /* Navigation Links List */
        nav[data-testid="stSidebarNav"] {
            padding: 6px 4px !important;
        }

        [data-testid="stSidebarNavSeparator"] {
            margin: 8px 0 !important;
            border-color: var(--border-subtle) !important;
        }

        ul[data-testid="stSidebarNavItems"] {
            gap: 4px !important;
            padding: 0 !important;
            list-style: none !important;
        }

        div[data-testid="stSidebarNavLinkContainer"] {
            width: 100% !important;
        }

        a[data-testid="stSidebarNavLink"] {
            display: flex !important;
            align-items: center !important;
            padding: 8px 12px !important;
            border-radius: var(--radius-md) !important;
            text-decoration: none !important;
            color: var(--text-secondary) !important;
            font-size: 0.88rem !important;
            font-weight: 500 !important;
            border: 1px solid transparent !important;
            border-left: 3px solid transparent !important;
            transition: transform var(--spring-press), background-color var(--spring-highlight), color var(--spring-highlight), border-color var(--spring-highlight) !important;
        }

        a[data-testid="stSidebarNavLink"]:hover {
            background-color: var(--surface-tertiary) !important;
            color: var(--accent-primary) !important;
        }

        a[data-testid="stSidebarNavLink"]:active {
            transform: scale(0.985) !important; /* spring.press for nav items/cards */
        }

        /* Active Navigation Link Pill - Crisp Academic High-Contrast Styling */
        a[data-testid="stSidebarNavLink"][aria-current="page"],
        a[data-testid="stSidebarNavLink"].active {
            background-color: var(--accent-subtle) !important;
            border-color: rgba(2, 132, 199, 0.2) !important;
            border-left: 3px solid var(--accent-primary) !important;
            color: var(--accent-hover) !important;
            font-weight: 600 !important;
        }

        a[data-testid="stSidebarNavLink"][aria-current="page"] span,
        a[data-testid="stSidebarNavLink"][aria-current="page"] p,
        a[data-testid="stSidebarNavLink"].active span,
        a[data-testid="stSidebarNavLink"].active p {
            color: var(--accent-hover) !important;
            font-weight: 600 !important;
        }

        /* Clean replacement for 'app' filename label ('app' -> 'WAFBench Console') */
        a[data-testid="stSidebarNavLink"] span[label="app"],
        a[data-testid="stSidebarNavLink"][href$="/"] span[label="app"],
        a[data-testid="stSidebarNavLink"][href$=":8501"] span[label="app"],
        a[data-testid="stSidebarNavLink"][href$=":8501/"] span[label="app"] {
            font-size: 0 !important;
            color: inherit !important;
        }

        a[data-testid="stSidebarNavLink"] span[label="app"] p,
        a[data-testid="stSidebarNavLink"][href$="/"] span[label="app"] p,
        a[data-testid="stSidebarNavLink"][href$=":8501"] span[label="app"] p,
        a[data-testid="stSidebarNavLink"][href$=":8501/"] span[label="app"] p {
            font-size: 0 !important;
            margin: 0 !important;
            color: inherit !important;
        }

        a[data-testid="stSidebarNavLink"] span[label="app"] p::after,
        a[data-testid="stSidebarNavLink"][href$="/"] span[label="app"] p::after,
        a[data-testid="stSidebarNavLink"][href$=":8501"] span[label="app"] p::after,
        a[data-testid="stSidebarNavLink"][href$=":8501/"] span[label="app"] p::after,
        a[data-testid="stSidebarNavLink"] span[label="app"]:not(:has(p))::after {
            content: "WAFBench Console" !important;
            font-size: 0.88rem !important;
            font-weight: inherit !important;
            color: inherit !important;
            display: inline-block !important;
            visibility: visible !important;
        }

        /* -------------------------------------------------------------
           3. Crisp Light Academic Cards & Containers
           ------------------------------------------------------------- */
        
        /* Academic title card */
        .academic-header {
            padding: 1.25rem 1.5rem;
            margin-bottom: 1.25rem;
            border-radius: var(--radius-lg);
            background-color: var(--surface-secondary);
            border: 1px solid var(--border-subtle);
            color: var(--text-primary);
            box-shadow: var(--shadow-subtle);
        }
        .academic-badge-row {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            margin-top: 10px;
        }
        .academic-badge {
            font-size: 0.76rem;
            font-weight: 500;
            padding: 3px 9px;
            border-radius: var(--radius-sm);
            border: 1px solid var(--border-subtle);
            background-color: var(--surface-bg);
            color: var(--text-secondary);
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03);
            transition: transform var(--spring-pop), box-shadow var(--spring-highlight), border-color var(--spring-highlight);
        }
        .academic-badge:hover {
            transform: translateY(-1px);
            border-color: var(--border-strong);
        }
        .academic-badge-live {
            border-color: var(--status-success-border) !important;
            color: var(--status-success) !important;
            background-color: var(--status-success-bg) !important;
            font-weight: 600 !important;
        }
        .academic-badge-demo {
            border-color: var(--status-warning-border) !important;
            color: var(--status-warning) !important;
            background-color: var(--status-warning-bg) !important;
            font-weight: 600 !important;
        }
        .academic-badge-error,
        .academic-badge-blocked {
            border-color: var(--status-error-border) !important;
            color: var(--status-error) !important;
            background-color: var(--status-error-bg) !important;
            font-weight: 600 !important;
        }
        .academic-badge-accent {
            border-color: var(--accent-subtle) !important;
            color: var(--accent-primary) !important;
            background-color: var(--accent-subtle) !important;
            font-weight: 600 !important;
        }

        /* Metric cards */
        .metric-card {
            background-color: var(--surface-bg);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-lg);
            padding: 1.1rem;
            text-align: left;
            box-shadow: var(--shadow-subtle);
            transition: box-shadow var(--spring-highlight), border-color var(--spring-highlight), transform var(--spring-press);
        }
        .metric-card:hover {
            border-color: var(--border-strong);
            box-shadow: var(--shadow-elevated);
        }
        .metric-card:active {
            transform: scale(0.985); /* spring.press for cards */
        }
        .metric-title {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            margin-bottom: 6px;
            font-weight: 600;
        }
        .metric-value {
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--text-primary);
            line-height: 1.2;
            letter-spacing: -0.02em;
        }
        .metric-subtitle {
            font-size: 0.76rem;
            color: var(--text-muted);
            margin-top: 6px;
        }

        /* Forensic Drawer section boxes */
        .forensic-box {
            background-color: var(--surface-secondary);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-lg);
            padding: 14px 16px;
            margin-bottom: 12px;
            box-shadow: var(--shadow-subtle);
            transition: transform var(--spring-dialog), box-shadow var(--spring-highlight), border-color var(--spring-highlight);
        }
        .forensic-box:hover {
            border-color: var(--border-strong);
        }
        .forensic-box:active {
            transform: scale(0.985);
        }
        .forensic-title {
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            margin-bottom: 8px;
            color: var(--text-primary);
        }
        .forensic-field {
            font-size: 0.85rem;
            margin-bottom: 5px;
            color: #334155; /* slate-700 */
            line-height: 1.45;
        }
        .forensic-field b {
            color: var(--text-primary);
            font-weight: 600;
        }
        .forensic-field code {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace !important;
            font-size: 0.82rem !important;
            background-color: var(--surface-bg) !important;
            color: var(--text-primary) !important;
            padding: 2px 6px !important;
            border-radius: 4px !important;
            border: 1px solid var(--border-subtle) !important;
        }

        /* -------------------------------------------------------------
           4. Status Alert Callout Surfaces (Verdict Cards)
           ------------------------------------------------------------- */
        .alert-block {
            background-color: var(--status-error-bg) !important;
            border: 1px solid var(--status-error-border) !important;
            border-left: 4px solid var(--status-error) !important;
            border-radius: var(--radius-lg) !important;
            padding: 14px 16px !important;
            margin: 12px 0 !important;
            box-shadow: 0 1px 3px rgba(220, 38, 38, 0.06), 0 1px 2px rgba(0, 0, 0, 0.03) !important;
        }

        .alert-allow,
        .alert-success {
            background-color: var(--status-success-bg) !important;
            border: 1px solid var(--status-success-border) !important;
            border-left: 4px solid var(--status-success) !important;
            border-radius: var(--radius-lg) !important;
            padding: 14px 16px !important;
            margin: 12px 0 !important;
            box-shadow: 0 1px 3px rgba(22, 163, 74, 0.06), 0 1px 2px rgba(0, 0, 0, 0.03) !important;
        }

        .alert-warning {
            background-color: var(--status-warning-bg) !important;
            border: 1px solid var(--status-warning-border) !important;
            border-left: 4px solid var(--status-warning) !important;
            border-radius: var(--radius-lg) !important;
            padding: 14px 16px !important;
            margin: 12px 0 !important;
            box-shadow: 0 1px 3px rgba(217, 119, 6, 0.06), 0 1px 2px rgba(0, 0, 0, 0.03) !important;
        }

        .alert-info {
            background-color: #f0f9ff !important;
            border: 1px solid #bae6fd !important;
            border-left: 4px solid var(--accent-primary) !important;
            border-radius: var(--radius-lg) !important;
            padding: 14px 16px !important;
            margin: 12px 0 !important;
            box-shadow: 0 1px 3px rgba(2, 132, 199, 0.06), 0 1px 2px rgba(0, 0, 0, 0.03) !important;
        }

        /* -------------------------------------------------------------
           5. Controls, Buttons & Micro-Interactions (Animate UI)
           ------------------------------------------------------------- */
        
        /* Secondary & Standard Buttons */
        div[data-testid="stButton"] > button,
        .stButton > button,
        div[data-testid="stDownloadButton"] > button,
        .stDownloadButton > button {
            border-radius: var(--radius-md) !important;
            font-weight: 500 !important;
            font-size: 0.88rem !important;
            border: 1px solid var(--border-subtle) !important;
            background-color: var(--surface-bg) !important;
            color: var(--text-primary) !important;
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04) !important;
            transition: transform var(--spring-press), box-shadow var(--spring-highlight), background-color 0.15s var(--ease-out), border-color 0.15s var(--ease-out), color 0.15s var(--ease-out) !important;
        }

        div[data-testid="stButton"] > button:hover,
        .stButton > button:hover,
        div[data-testid="stDownloadButton"] > button:hover,
        .stDownloadButton > button:hover {
            border-color: var(--border-strong) !important;
            background-color: var(--surface-secondary) !important;
            color: var(--accent-primary) !important;
        }

        div[data-testid="stButton"] > button:active,
        .stButton > button:active,
        div[data-testid="stDownloadButton"] > button:active,
        .stDownloadButton > button:active {
            transform: scale(0.97) !important; /* spring.press */
        }

        /* Primary Call-to-Action Buttons */
        div[data-testid="stButton"] > button[kind="primary"],
        button[data-testid="stBaseButton-primary"],
        button[kind="primary"] {
            background-color: var(--accent-primary) !important;
            color: #ffffff !important;
            border: 1px solid var(--accent-primary) !important;
            box-shadow: 0 1px 2px rgba(2, 132, 199, 0.2) !important;
        }

        div[data-testid="stButton"] > button[kind="primary"]:hover,
        button[data-testid="stBaseButton-primary"]:hover,
        button[kind="primary"]:hover {
            background-color: var(--accent-hover) !important;
            border-color: var(--accent-hover) !important;
            color: #ffffff !important;
            box-shadow: 0 2px 6px rgba(2, 132, 199, 0.3) !important;
        }

        div[data-testid="stButton"] > button[kind="primary"]:active,
        button[data-testid="stBaseButton-primary"]:active,
        button[kind="primary"]:active {
            transform: scale(0.97) !important; /* spring.press */
        }

        /* Native Streamlit Metric cards */
        [data-testid="stMetric"] {
            background-color: var(--surface-bg) !important;
            border: 1px solid var(--border-subtle) !important;
            border-radius: var(--radius-lg) !important;
            padding: 1rem !important;
            box-shadow: var(--shadow-subtle) !important;
            transition: box-shadow var(--spring-highlight), border-color var(--spring-highlight), transform var(--spring-press) !important;
        }
        [data-testid="stMetric"]:hover {
            border-color: var(--border-strong) !important;
            box-shadow: var(--shadow-elevated) !important;
        }
        [data-testid="stMetric"]:active {
            transform: scale(0.985) !important;
        }
        [data-testid="stMetricLabel"] {
            color: var(--text-secondary) !important;
            font-size: 0.8rem !important;
            font-weight: 500 !important;
        }
        [data-testid="stMetricValue"] {
            color: var(--text-primary) !important;
            font-weight: 700 !important;
        }

        /* Tabs styling */
        div[data-testid="stTabs"] button[role="tab"] {
            font-size: 0.88rem !important;
            font-weight: 500 !important;
            color: var(--text-secondary) !important;
            border: none !important;
            border-bottom: 2px solid transparent !important;
            padding: 8px 16px !important;
            background: transparent !important;
            transition: color var(--spring-highlight), border-color var(--spring-highlight) !important;
        }
        div[data-testid="stTabs"] button[role="tab"]:hover {
            color: var(--accent-primary) !important;
        }
        div[data-testid="stTabs"] button[role="tab"][aria-selected="true"] {
            color: var(--accent-primary) !important;
            border-bottom: 2px solid var(--accent-primary) !important;
            font-weight: 600 !important;
        }

        /* Expanders */
        div[data-testid="stExpander"] {
            border: 1px solid var(--border-subtle) !important;
            border-radius: var(--radius-lg) !important;
            background-color: var(--surface-bg) !important;
            box-shadow: var(--shadow-subtle) !important;
            overflow: hidden !important;
        }
        div[data-testid="stExpander"] details summary {
            padding: 12px 16px !important;
            font-weight: 500 !important;
            color: var(--text-primary) !important;
            background-color: var(--surface-secondary) !important;
            transition: background-color var(--spring-highlight), color var(--spring-highlight) !important;
        }
        div[data-testid="stExpander"] details summary:hover {
            background-color: var(--surface-tertiary) !important;
            color: var(--accent-primary) !important;
        }

        /* Form Inputs & Selects */
        div[data-baseweb="input"],
        div[data-baseweb="select"] > div,
        div[data-baseweb="textarea"] {
            border: 1px solid var(--border-subtle) !important;
            border-radius: var(--radius-md) !important;
            background-color: var(--surface-bg) !important;
            color: var(--text-primary) !important;
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03) !important;
            transition: border-color var(--spring-highlight), box-shadow var(--spring-highlight) !important;
        }
        div[data-baseweb="input"]:focus-within,
        div[data-baseweb="select"] > div:focus-within,
        div[data-baseweb="textarea"]:focus-within {
            border-color: var(--accent-primary) !important;
            box-shadow: 0 0 0 3px var(--accent-glow) !important;
        }
        input, textarea, select {
            color: var(--text-primary) !important;
        }

        /* Tables & DataFrames with row hover highlight */
        div[data-testid="stDataFrame"],
        div[data-testid="stTable"] {
            border: 1px solid var(--border-subtle) !important;
            border-radius: var(--radius-lg) !important;
            overflow: hidden !important;
            box-shadow: var(--shadow-subtle) !important;
        }
        table {
            border-collapse: separate !important;
            border-spacing: 0 !important;
            width: 100% !important;
        }
        th {
            background-color: var(--surface-secondary) !important;
            color: var(--text-secondary) !important;
            font-weight: 600 !important;
            font-size: 0.8rem !important;
            text-transform: uppercase !important;
            letter-spacing: 0.04em !important;
            border-bottom: 1px solid var(--border-subtle) !important;
            padding: 10px 14px !important;
        }
        td {
            border-bottom: 1px solid var(--border-subtle) !important;
            color: var(--text-primary) !important;
            font-size: 0.86rem !important;
            padding: 10px 14px !important;
            transition: background-color var(--spring-highlight) !important;
        }
        tr:hover td {
            background-color: var(--surface-secondary) !important; /* spring.highlight */
        }

        /* Popovers, Tooltips & Modal Surfaces */
        div[data-baseweb="popover"],
        div[data-baseweb="tooltip"] {
            border-radius: var(--radius-md) !important;
            box-shadow: var(--shadow-popover) !important;
            border: 1px solid var(--border-subtle) !important;
            animation: springPop var(--spring-pop) !important;
        }
        div[data-baseweb="modal"] {
            border-radius: var(--radius-lg) !important;
            box-shadow: var(--shadow-popover) !important;
            border: 1px solid var(--border-subtle) !important;
            animation: springDialog var(--spring-dialog) !important;
        }
        @keyframes springPop {
            from {
                opacity: 0;
                transform: scale(0.96);
            }
            to {
                opacity: 1;
                transform: scale(1);
            }
        }
        @keyframes springDialog {
            from {
                opacity: 0;
                transform: translateY(8px) scale(0.985);
            }
            to {
                opacity: 1;
                transform: translateY(0) scale(1);
            }
        }

        /* Monospace / Code Elements */
        code {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace !important;
            font-size: 0.84em !important;
            background-color: var(--surface-tertiary) !important;
            color: var(--text-primary) !important;
            padding: 2px 5px !important;
            border-radius: 4px !important;
            border: 1px solid var(--border-subtle) !important;
        }
        pre {
            background-color: var(--surface-secondary) !important;
            border: 1px solid var(--border-subtle) !important;
            border-radius: var(--radius-md) !important;
            padding: 12px 14px !important;
        }
        pre code {
            border: none !important;
            background: transparent !important;
            padding: 0 !important;
        }
    </style>
    """, unsafe_allow_html=True)
