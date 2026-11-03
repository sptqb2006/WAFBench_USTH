#!/usr/bin/env python3
"""
WAFBench Dashboard Styling Module
Pure Light Academic Theme.
Sleek, Compact Pinned Sidebar (200px) with Collapse Button Removed.
Dark Mode & Theme Switching Completely Drenched and Removed.
"""

import streamlit as st


def apply_academic_styling():
    """
    Injects crisp, consistent Light Theme CSS.
    Completely eliminates dark mode styling and theme glitches.
    """
    st.markdown("""
    <style>
        /* -------------------------------------------------------------
           1. Pure Light Base Typography & Surfaces
           ------------------------------------------------------------- */
        body, .stApp {
            background-color: #ffffff !important;
            color: #202124 !important;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important;
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
        
        /* Fixed 200px sidebar width */
        section[data-testid="stSidebar"],
        section#stSidebar {
            width: 200px !important;
            min-width: 200px !important;
            max-width: 200px !important;
            background-color: #f8f9fa !important;
            border-right: 1px solid #dadce0 !important;
            box-sizing: border-box !important;
        }

        [data-testid="stSidebarContent"] {
            background-color: #f8f9fa !important;
            padding: 8px 6px !important;
        }
        
        /* Top bar / header styling */
        [data-testid="stHeader"],
        header[data-testid="stHeader"] {
            background-color: #f8f9fa !important;
            border-bottom: 1px solid #dadce0 !important;
        }
            
        /* Hide the button that collapses the sidebar */
        [data-testid="stSidebarCollapseButton"],
        button[aria-label="Collapse sidebar"],
        button[aria-label="Close sidebar"] {
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

        /* Open/Expand Sidebar Trigger Button (when sidebar is collapsed) */
        [data-testid="collapsedControl"],
        [data-testid="stExpandSidebarButton"] {
            display: flex !important;
            visibility: visible !important;
            opacity: 1 !important;
            background-color: #ffffff !important;
            border: 1px solid #dadce0 !important;
            border-radius: 8px !important;
            box-shadow: 0 1px 3px rgba(60, 64, 67, 0.25) !important;
            transition: box-shadow 0.15s ease-in-out !important;
        }

        [data-testid="collapsedControl"]:hover,
        [data-testid="stExpandSidebarButton"]:hover {
            box-shadow: 0 2px 6px rgba(60, 64, 67, 0.35) !important;
            border-color: #1a73e8 !important;
        }

        [data-testid="collapsedControl"] button,
        [data-testid="stExpandSidebarButton"] button {
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            color: #1a73e8 !important;
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
            border-color: #dadce0 !important;
        }

        ul[data-testid="stSidebarNavItems"] {
            gap: 4px !important;
            padding: 0 !important;
        }

        div[data-testid="stSidebarNavLinkContainer"] {
            width: 100% !important;
        }

        a[data-testid="stSidebarNavLink"] {
            display: flex !important;
            align-items: center !important;
            padding: 8px 12px !important;
            border-radius: 8px !important;
            text-decoration: none !important;
            color: #3c4043 !important;
            font-size: 0.88rem !important;
            font-weight: 500 !important;
            transition: background-color 0.15s ease-in-out, color 0.15s ease-in-out !important;
        }

        a[data-testid="stSidebarNavLink"]:hover {
            background-color: #e8f0fe !important;
            color: #1a73e8 !important;
        }

        /* Active Navigation Link Pill */
        a[data-testid="stSidebarNavLink"][aria-current="page"] {
            background-color: #d3e3fd !important;
            color: #041e49 !important;
            font-weight: 600 !important;
        }

        /* Clean replacement for 'app' filename label */
        a[data-testid="stSidebarNavLink"][href$="/"] span[label="app"] p,
        a[data-testid="stSidebarNavLink"][href$=":8501"] span[label="app"] p,
        a[data-testid="stSidebarNavLink"][href$=":8501/"] span[label="app"] p {
            font-size: 0 !important;
        }
        a[data-testid="stSidebarNavLink"][href$="/"] span[label="app"] p::after,
        a[data-testid="stSidebarNavLink"][href$=":8501"] span[label="app"] p::after,
        a[data-testid="stSidebarNavLink"][href$=":8501/"] span[label="app"] p::after {
            content: "WAFBench Console" !important;
            font-size: 0.88rem !important;
            font-weight: 500 !important;
            display: block !important;
        }

        /* -------------------------------------------------------------
           3. Crisp Light Academic Cards & Containers
           ------------------------------------------------------------- */
        
        /* Academic title card */
        .academic-header {
            padding: 1.2rem 1.4rem;
            margin-bottom: 1.2rem;
            border-radius: 8px;
            background-color: #f8f9fa;
            border: 1px solid #dadce0;
            color: #202124;
        }
        .academic-badge-row {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            margin-top: 8px;
        }
        .academic-badge {
            font-size: 0.78rem;
            font-weight: 500;
            padding: 3px 8px;
            border-radius: 4px;
            border: 1px solid #dadce0;
            background-color: #ffffff;
            color: #3c4043;
        }
        .academic-badge-live {
            border-color: #34a853;
            color: #137333;
            background-color: #e6f4ea;
        }
        .academic-badge-demo {
            border-color: #fbbc04;
            color: #b06000;
            background-color: #fef7e0;
        }

        /* Metric cards */
        .metric-card {
            background-color: #ffffff;
            border: 1px solid #dadce0;
            border-radius: 8px;
            padding: 1rem;
            text-align: left;
            box-shadow: 0 1px 2px rgba(60, 64, 67, 0.08);
            transition: box-shadow 0.15s ease-in-out, border-color 0.15s ease-in-out;
        }
        .metric-card:hover {
            border-color: #1a73e8;
            box-shadow: 0 1px 3px 1px rgba(60, 64, 67, 0.15);
        }
        .metric-title {
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            color: #5f6368;
            margin-bottom: 4px;
            font-weight: 500;
        }
        .metric-value {
            font-size: 1.7rem;
            font-weight: 600;
            color: #202124;
            line-height: 1.2;
        }
        .metric-subtitle {
            font-size: 0.76rem;
            color: #70757a;
            margin-top: 4px;
        }

        /* Forensic Drawer section boxes */
        .forensic-box {
            background-color: #f8f9fa;
            border: 1px solid #dadce0;
            border-radius: 6px;
            padding: 12px 14px;
            margin-bottom: 10px;
        }
        .forensic-title {
            font-size: 0.82rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.03em;
            margin-bottom: 8px;
            color: #202124;
        }
        .forensic-field {
            font-size: 0.85rem;
            margin-bottom: 4px;
            color: #3c4043;
        }
    </style>
    """, unsafe_allow_html=True)
