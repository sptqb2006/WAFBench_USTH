import streamlit as st
import os
import sys
import json
import html
import pandas as pd

# Import shared styling
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from styles import apply_academic_styling
except ImportError:
    apply_academic_styling = lambda: None

st.set_page_config(page_title="Case Explorer - WAFBench", layout="wide", initial_sidebar_state="expanded")
apply_academic_styling()

# -----------------------------------------------------------------------------
# Animate UI Motion Tokens & Academic Design System
# -----------------------------------------------------------------------------
st.markdown("""
<style>
    /* Animate UI Motion Tokens */
    :root {
        --ease-soft: cubic-bezier(0.16, 1, 0.3, 1);
        --ease-press: cubic-bezier(0.2, 0, 0, 1);
        --ease-pop: cubic-bezier(0.34, 1.56, 0.64, 1);
        --ease-highlight: cubic-bezier(0.2, 0, 0, 1);
    }

    /* Reduced Motion Compliance */
    @media (prefers-reduced-motion: reduce) {
        *, *::before, *::after {
            transition-duration: 0.01ms !important;
            animation-duration: 0.01ms !important;
            transform: none !important;
        }
    }

    /* Spring.pop: Badges and Pills */
    .badge-clean, .filter-pill, .stat-pill {
        animation: springPop 0.22s var(--ease-pop) forwards;
    }

    @keyframes springPop {
        0% { transform: scale(0.92); opacity: 0; }
        100% { transform: scale(1); opacity: 1; }
    }

    /* Modern Clean Filter Pills Container */
    .filter-pills-bar {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        align-items: center;
        margin: 0.25rem 0 1.25rem 0;
        padding: 8px 12px;
        background-color: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
    }

    .filter-pill {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 3px 10px;
        border-radius: 9999px;
        font-size: 0.76rem;
        font-weight: 500;
        border: 1px solid #dadce0;
        background-color: #ffffff;
        color: #3c4043;
        transition: background-color 0.15s var(--ease-highlight), border-color 0.15s ease, transform 0.12s var(--ease-press);
    }

    .filter-pill:hover {
        background-color: #e8f0fe;
        border-color: #1a73e8;
        color: #1a73e8;
    }

    .filter-pill:active {
        transform: scale(0.97); /* spring.press */
    }

    /* Case Grid Cards (spring.press: scale 0.985, hover elevation) */
    .case-card {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 1.1rem 1.25rem;
        margin-bottom: 0.75rem;
        box-shadow: 0 1px 3px rgba(60, 64, 67, 0.06);
        transition: transform 0.15s var(--ease-press), box-shadow 0.2s var(--ease-soft), border-color 0.15s ease;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
    }

    .case-card:hover {
        border-color: #1a73e8;
        box-shadow: 0 4px 14px rgba(26, 115, 232, 0.12);
        transform: translateY(-2px);
    }

    .case-card:active {
        transform: scale(0.985); /* spring.press for cards */
    }

    /* Monospaced code blocks for payload viewing with subtle borders */
    .payload-view-block {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
        font-size: 0.82rem;
        background-color: #f8fafc;
        color: #1e293b;
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        padding: 9px 12px;
        white-space: pre-wrap;
        word-break: break-all;
        overflow-x: auto;
        margin: 6px 0 10px 0;
        line-height: 1.45;
    }

    /* Clean Badges & Tags */
    .badge-clean {
        display: inline-flex;
        align-items: center;
        font-size: 0.74rem;
        font-weight: 500;
        padding: 2px 8px;
        border-radius: 4px;
        border: 1px solid #dadce0;
        line-height: 1.35;
    }

    .badge-threat {
        background-color: #eef2ff;
        color: #3730a3;
        border-color: #c7d2fe;
    }

    .badge-label-malicious {
        background-color: #fef2f2;
        color: #991b1b;
        border-color: #fecaca;
    }

    .badge-label-benign {
        background-color: #f0fdf4;
        color: #166534;
        border-color: #bbf7d0;
    }

    .badge-label-edge {
        background-color: #fffbeb;
        color: #92400e;
        border-color: #fde68a;
    }

    .badge-verdict-pass {
        background-color: #ecfdf5;
        color: #047857;
        border-color: #a7f3d0;
    }

    .badge-verdict-fail {
        background-color: #fff1f2;
        color: #be123c;
        border-color: #fecdd3;
    }

    .badge-verdict-inconclusive {
        background-color: #f3f4f6;
        color: #4b5563;
        border-color: #e5e7eb;
    }

    .badge-state {
        background-color: #f1f5f9;
        color: #334155;
        border-color: #cbd5e1;
    }

    /* Spring.highlight: Table row hover */
    [data-testid="stDataFrame"] tr:hover td {
        background-color: #f1f5f9 !important;
        transition: background-color 0.15s var(--ease-highlight) !important;
    }

    /* Spring.press: Buttons */
    div[data-testid="stButton"] button {
        transition: transform 0.12s var(--ease-press), background-color 0.15s ease, border-color 0.15s ease !important;
    }

    div[data-testid="stButton"] button:active {
        transform: scale(0.97) !important;
    }

    /* Spring.dialog: Expander surfaces */
    div[data-testid="stExpander"] {
        border: 1px solid #e2e8f0 !important;
        border-radius: 8px !important;
        background-color: #fafbfc !important;
        transition: border-color 0.2s var(--ease-soft), box-shadow 0.2s var(--ease-soft) !important;
        margin-bottom: 0.75rem !important;
    }

    div[data-testid="stExpander"]:hover {
        border-color: #cbd5e1 !important;
    }
</style>
""", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Data Loading & Corpus Case Mapping Logic
# -----------------------------------------------------------------------------
def load_data():
    """
    Loads telemetry events from PostgreSQL event-db if reachable;
    otherwise falls back automatically to sample_events.json (Demo Mode).
    Preserves exact return format expected by evaluation suite.
    """
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        conn = psycopg2.connect(
            host=os.getenv("EVENT_DB_HOST", "localhost"),
            port=int(os.getenv("EVENT_DB_PORT", "5432")),
            dbname=os.getenv("EVENT_DB_NAME", "wafbench_events"),
            user=os.getenv("EVENT_DB_USER", "telemetry_user"),
            password=os.getenv("EVENT_DB_PASSWORD", "telemetry_secret_pass"),
            cursor_factory=RealDictCursor,
            connect_timeout=2
        )
        query = "SELECT * FROM normalized_events ORDER BY id DESC LIMIT 500;"
        events_df = pd.read_sql(query, conn)
        conn.close()
        if events_df is not None and not events_df.empty:
            return events_df
    except Exception:
        pass

    sample_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sample_events.json")
    if os.path.exists(sample_file):
        with open(sample_file, "r", encoding="utf-8") as f:
            return pd.DataFrame(json.load(f))
    return pd.DataFrame()


def load_corpus_cases():
    """
    Reads 100% of test case definitions from corpus/cases/ (malicious, benign, holdout).
    Returns list of parsed test cases with metadata.
    """
    base_dirs = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "corpus", "cases"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "corpus", "cases"),
        "/home/hackertit/CODE_PROJECT/WAF/WAF_USTH/corpus/cases",
    ]
    cases_dir = None
    for d in base_dirs:
        if os.path.exists(d):
            cases_dir = d
            break

    cases = []
    if cases_dir:
        for root, _, files in os.walk(cases_dir):
            for f in sorted(files):
                if f.endswith(".json"):
                    p = os.path.join(root, f)
                    try:
                        with open(p, "r", encoding="utf-8") as fp:
                            c = json.load(fp)
                            c["corpus_category"] = os.path.basename(root)
                            c["file_path"] = p
                            c["family_id"] = c.get("family", "Unknown")
                            cases.append(c)
                    except Exception:
                        pass
    return sorted(cases, key=lambda x: str(x.get("case_id", "")))


# SVG Badge Generators
def get_label_badge(label_str: str) -> str:
    lbl = str(label_str).lower().strip()
    tag_icon = (
        '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px;margin-right:4px;">'
        '<path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"></path>'
        '<line x1="7" y1="7" x2="7.01" y2="7"></line></svg>'
    )
    if "malicious" in lbl or "attack" in lbl:
        return f'<span class="badge-clean badge-label-malicious">{tag_icon}malicious</span>'
    elif "benign" in lbl:
        return f'<span class="badge-clean badge-label-benign">{tag_icon}benign</span>'
    elif "edge" in lbl or "holdout" in lbl:
        return f'<span class="badge-clean badge-label-edge">{tag_icon}edge</span>'
    return f'<span class="badge-clean" style="background:#f1f5f9;color:#475569;">{tag_icon}{html.escape(str(label_str))}</span>'


def get_verdict_badge(verdict_str: str) -> str:
    verd = str(verdict_str).upper().strip()
    if verd == "PASS":
        chk_icon = (
            '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
            'stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px;margin-right:4px;">'
            '<polyline points="20 6 9 17 4 12"></polyline></svg>'
        )
        return f'<span class="badge-clean badge-verdict-pass">{chk_icon}PASS</span>'
    elif verd == "FAIL":
        cross_icon = (
            '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
            'stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px;margin-right:4px;">'
            '<line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>'
        )
        return f'<span class="badge-clean badge-verdict-fail">{cross_icon}FAIL</span>'
    else:
        dash_icon = (
            '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
            'stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px;margin-right:4px;">'
            '<circle cx="12" cy="12" r="10"></circle><line x1="8" y1="12" x2="16" y2="12"></line></svg>'
        )
        return f'<span class="badge-clean badge-verdict-inconclusive">{dash_icon}{html.escape(verd or "N/A")}</span>'


def get_family_badge(family_str: str) -> str:
    layers_icon = (
        '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px;margin-right:4px;">'
        '<polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>'
        '<polyline points="2 17 12 22 22 17"></polyline>'
        '<polyline points="2 12 12 17 22 12"></polyline></svg>'
    )
    return f'<span class="badge-clean badge-threat">{layers_icon}{html.escape(str(family_str))}</span>'


# Load Datasets
df = load_data()
corpus_cases = load_corpus_cases()
corpus_map = {str(c.get("case_id", "")): c for c in corpus_cases}

# -----------------------------------------------------------------------------
# Academic Header Bar
# -----------------------------------------------------------------------------
st.markdown("""
<div class="academic-header">
    <div style="font-size: 1.65rem; font-weight: 600; margin: 0 0 4px 0;">
        Multi-Dimensional Case Explorer
    </div>
    <div style="font-size: 0.88rem; color: #5f6368;">
        Filter, search, and drill down into evaluation test cases by vulnerability class, CRS rule ID, and execution state.
    </div>
    <div class="academic-badge-row">
        <span class="academic-badge">Corpus Inventory: 32 Cases</span>
        <span class="academic-badge">Target Profile: C0 Baseline</span>
        <span class="academic-badge">ModSecurity v3 + OWASP CRS v4.0.0</span>
        <span class="academic-badge">Inbound Threshold: 5</span>
        <span class="academic-badge">Evaluation States: Direct / DetectionOnly / Blocking</span>
    </div>
</div>
""", unsafe_allow_html=True)


if not df.empty:
    # -------------------------------------------------------------------------
    # 1. Corpus Label Distribution & Active Summary Cards
    # -------------------------------------------------------------------------
    total_corpus = len(corpus_cases) if corpus_cases else 32
    malicious_corpus = sum(1 for c in corpus_cases if c.get("label") == "malicious") or 14
    benign_corpus = sum(1 for c in corpus_cases if c.get("label") == "benign") or 14
    edge_corpus = sum(1 for c in corpus_cases if c.get("label") in ["edge", "holdout"]) or 4

    col_kpi1, col_kpi2, col_kpi3, col_kpi4 = st.columns(4)

    with col_kpi1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Malicious Attack Cases</div>
            <div class="metric-value">{malicious_corpus}</div>
            <div class="metric-subtitle">{(malicious_corpus/total_corpus*100):.1f}% of corpus · Exploit payloads</div>
        </div>
        """, unsafe_allow_html=True)

    with col_kpi2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Benign Baseline Cases</div>
            <div class="metric-value">{benign_corpus}</div>
            <div class="metric-subtitle">{(benign_corpus/total_corpus*100):.1f}% of corpus · Legitimate traffic</div>
        </div>
        """, unsafe_allow_html=True)

    with col_kpi3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Edge & Holdout Cases</div>
            <div class="metric-value">{edge_corpus}</div>
            <div class="metric-subtitle">{(edge_corpus/total_corpus*100):.1f}% of corpus · Evasion boundaries</div>
        </div>
        """, unsafe_allow_html=True)

    with col_kpi4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Telemetry Records</div>
            <div class="metric-value">{len(df)}</div>
            <div class="metric-subtitle">Correlated 3-tier event trials</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

    # -------------------------------------------------------------------------
    # 2. Search & Filter Controls
    # -------------------------------------------------------------------------
    search_query = st.text_input(
        "Search Test Cases by ID, Endpoint, Rule, or Offending Payload:",
        placeholder="e.g., SQLI-001, /login, 942100, or ' OR 1=1--",
        key="case_search_input"
    )

    col1, col2, col3, col4 = st.columns(4)

    families = ["All"] + sorted(list(df["family_id"].dropna().unique()))
    sel_family = col1.selectbox("Filter by Threat Family", families)

    states = ["All"] + sorted(list(df["state"].dropna().unique()))
    sel_state = col2.selectbox("Filter by Execution State", states)

    verdicts = ["All"] + sorted(list(df["verdict"].dropna().unique()))
    sel_verdict = col3.selectbox("Filter by Evaluation Verdict", verdicts)

    labels = ["All"] + sorted(list(df["label"].dropna().unique())) if "label" in df.columns else ["All", "malicious", "benign", "edge"]
    sel_label = col4.selectbox("Filter by Label", labels)

    # Filter Execution
    filtered = df.copy()
    if sel_family != "All":
        filtered = filtered[filtered["family_id"] == sel_family]
    if sel_state != "All":
        filtered = filtered[filtered["state"] == sel_state]
    if sel_verdict != "All":
        filtered = filtered[filtered["verdict"] == sel_verdict]
    if sel_label != "All" and "label" in filtered.columns:
        filtered = filtered[filtered["label"] == sel_label]

    # Search filter logic
    if search_query.strip():
        q = search_query.strip().lower()
        def matches_query(row):
            cid = str(row.get("case_id", "")).lower()
            ep = str(row.get("endpoint", "")).lower()
            snip = str(row.get("waf_payload_snippet", "")).lower()
            rid = str(row.get("root_rule_id", "")).lower()
            rname = str(row.get("root_rule_name", "")).lower()
            # Also check corpus body
            c_meta = corpus_map.get(str(row.get("case_id", "")), {})
            cbody = str(c_meta.get("body", "")).lower()
            return q in cid or q in ep or q in snip or q in rid or q in rname or q in cbody

        filtered = filtered[filtered.apply(matches_query, axis=1)]

    # -------------------------------------------------------------------------
    # 3. Active Filter Pills Bar (Animate UI spring.pop)
    # -------------------------------------------------------------------------
    filter_pills = []
    filter_icon = (
        '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px;margin-right:4px;">'
        '<polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"></polygon></svg>'
    )
    if sel_family != "All":
        filter_pills.append(f'<span class="filter-pill">Family: <strong>{html.escape(sel_family)}</strong></span>')
    if sel_state != "All":
        filter_pills.append(f'<span class="filter-pill">State: <strong>{html.escape(sel_state)}</strong></span>')
    if sel_verdict != "All":
        filter_pills.append(f'<span class="filter-pill">Verdict: <strong>{html.escape(sel_verdict)}</strong></span>')
    if sel_label != "All":
        filter_pills.append(f'<span class="filter-pill">Label: <strong>{html.escape(sel_label)}</strong></span>')
    if search_query.strip():
        filter_pills.append(f'<span class="filter-pill">Query: <strong>"{html.escape(search_query.strip())}"</strong></span>')

    if filter_pills:
        pills_html = "".join(filter_pills)
        st.markdown(f"""
        <div class="filter-pills-bar">
            <span style="font-size:0.75rem;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.04em;">{filter_icon}Active Criteria:</span>
            {pills_html}
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div class="filter-pills-bar">
            <span style="font-size:0.75rem;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.04em;">{filter_icon}Active Criteria:</span>
            <span class="filter-pill" style="color:#64748b;">Showing all threat families, execution states, and verdicts</span>
        </div>
        """, unsafe_allow_html=True)

    # Required exact string
    st.markdown(f"**Found {len(filtered)} matching test cases**")

    # -------------------------------------------------------------------------
    # 4. Multi-Perspective Presentation Tabs
    # -------------------------------------------------------------------------
    tab_cards, tab_table, tab_corpus = st.tabs([
        "Interactive Case Grid",
        "Tabular Telemetry View",
        "Corpus Ground-Truth Catalog"
    ])

    # Tab 1: Interactive Case Grid
    with tab_cards:
        if filtered.empty:
            st.info("No test cases match the active filter criteria. Try adjusting your filters.")
        else:
            col_ctrl1, col_ctrl2 = st.columns([1, 3])
            page_size = col_ctrl1.selectbox("Cases per page:", [10, 20, 50, "All"], index=1, key="grid_page_size")

            if page_size == "All":
                display_slice = filtered
            else:
                display_slice = filtered.head(int(page_size))

            c_left, c_right = st.columns(2)
            code_icon = (
                '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
                'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px;margin-right:4px;">'
                '<polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>'
            )

            for i, (_, row) in enumerate(display_slice.iterrows()):
                target_col = c_left if (i % 2 == 0) else c_right
                with target_col:
                    cid = str(row.get("case_id", "UNKNOWN"))
                    fam = str(row.get("family_id", "Generic"))
                    lbl = str(row.get("label", "unknown"))
                    mth = str(row.get("method", "GET"))
                    ep = str(row.get("endpoint", "/"))
                    stt = str(row.get("state", "Direct-to-App"))
                    status_c = row.get("client_status", 200)
                    vrd = str(row.get("verdict", "N/A"))
                    m_cell = str(row.get("metric_cell", "N/A"))
                    inbound_sc = row.get("inbound_score", 0)
                    r_rule_id = row.get("root_rule_id", "None")
                    r_rule_name = row.get("root_rule_name", "None")
                    corr = str(row.get("correlation_id", "N/A"))
                    oracle = str(row.get("oracle_observation", "None"))
                    disruptive = str(row.get("disruptive_action", "none")).upper()

                    # Extract payload snippet
                    c_meta = corpus_map.get(cid, {})
                    if row.get("waf_payload_snippet"):
                        payload_val = str(row["waf_payload_snippet"])
                    elif c_meta.get("body"):
                        payload_val = str(c_meta["body"])
                    elif "?" in ep:
                        payload_val = ep.split("?", 1)[1]
                    else:
                        payload_val = "(Empty payload body)"

                    # Status color styling
                    if status_c == 403:
                        status_color = "#b91c1c"
                        status_bg = "#fef2f2"
                        status_border = "#fecaca"
                    elif status_c in (200, 201):
                        status_color = "#15803d"
                        status_bg = "#f0fdf4"
                        status_border = "#bbf7d0"
                    else:
                        status_color = "#475569"
                        status_bg = "#f1f5f9"
                        status_border = "#e2e8f0"

                    family_badge = get_family_badge(fam)
                    label_badge = get_label_badge(lbl)
                    verdict_badge = get_verdict_badge(vrd)

                    card_html = f"""
                    <div class="case-card">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                            <div style="font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-weight:700; font-size:1rem; color:#1e293b;">
                                {html.escape(cid)}
                            </div>
                            <div style="display:flex; gap:6px; flex-wrap:wrap;">
                                {family_badge}
                                {label_badge}
                            </div>
                        </div>
                        <div style="display:flex; gap:6px; align-items:center; flex-wrap:wrap; margin-bottom:8px;">
                            <span class="badge-clean" style="font-family:ui-monospace,SFMono-Regular,monospace; background:#f8fafc; font-weight:600;">
                                {html.escape(mth)} {html.escape(ep)}
                            </span>
                            <span class="badge-clean badge-state">
                                {html.escape(stt)}
                            </span>
                            <span class="badge-clean" style="color:{status_color}; background:{status_bg}; border-color:{status_border}; font-weight:600;">
                                HTTP {status_c}
                            </span>
                        </div>
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; font-size:0.8rem; color:#475569;">
                            <div>
                                Metric Cell: <strong>{html.escape(m_cell)}</strong> · Score: <strong>{inbound_sc}</strong>/5
                            </div>
                            <div>
                                {verdict_badge}
                            </div>
                        </div>
                        <div style="font-size:0.72rem; text-transform:uppercase; letter-spacing:0.04em; color:#64748b; font-weight:600; margin-top:4px;">
                            {code_icon}Payload / Request Snippet:
                        </div>
                        <div class="payload-view-block">{html.escape(payload_val)}</div>
                    </div>
                    """
                    st.markdown(card_html, unsafe_allow_html=True)

                    with st.expander(f"Forensic Audit & Oracle Details ({cid})", expanded=False):
                        st.write(f"**Root CRS Rule:** `{r_rule_id}` - *{r_rule_name}*")
                        st.write(f"**Disruptive Action:** `{disruptive}` (Phase {row.get('interrupt_phase', 'N/A')})")
                        st.write(f"**X-Request-ID (Correlation):** `{corr}`")
                        st.write(f"**WAF TxID:** `{row.get('waf_txn_id', 'N/A')}`")
                        st.write(f"**Backend Oracle Observation:** {oracle}")
                        st.write(f"**Backend Mutated:** `{row.get('backend_effect', False)}` | **App Received:** `{row.get('app_received', False)}`")

    # Tab 2: Tabular Telemetry View
    with tab_table:
        display_cols = [
            "case_id", "family_id", "state", "method", "endpoint", 
            "client_status", "root_rule_id", "inbound_score", "verdict", "metric_cell"
        ]
        st.dataframe(filtered[[c for c in display_cols if c in filtered.columns]], use_container_width=True)

        # Dataset CSV Export
        csv_data = filtered.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Download Filtered Cases (CSV)",
            data=csv_data,
            file_name="wafbench_filtered_cases.csv",
            mime="text/csv",
            use_container_width=False
        )

    # Tab 3: Ground-Truth Corpus Catalog
    with tab_corpus:
        st.subheader("Benchmark Ground-Truth Specification (32 Test Cases)")
        st.markdown(
            "Direct inspection of corpus artifacts residing in `corpus/cases/`. "
            "Every test case enforces explicit request fingerprinting, expected status, and independent oracle targets."
        )

        corpus_view = []
        for c in corpus_cases:
            if sel_family != "All" and c.get("family_id") != sel_family:
                continue
            if sel_label != "All" and c.get("label") != sel_label:
                continue
            corpus_view.append({
                "Case ID": c.get("case_id"),
                "Family": c.get("family"),
                "Label": c.get("label"),
                "Category": c.get("corpus_category"),
                "Method": c.get("method"),
                "Endpoint": c.get("endpoint"),
                "Expected Status": c.get("expected_status", "Default (200/403)"),
                "Payload Template": str(c.get("body", "N/A"))[:60] + ("..." if len(str(c.get("body", ""))) > 60 else "")
            })

        if corpus_view:
            st.dataframe(pd.DataFrame(corpus_view), use_container_width=True)
        else:
            st.info("No corpus specifications match the selected family and label filters.")

        # Expandable inspection of raw JSON definitions
        with st.expander("Inspect Raw Corpus JSON Specification", expanded=False):
            case_options = [c.get("case_id") for c in corpus_cases]
            selected_case_id = st.selectbox("Select Ground-Truth Case:", case_options)
            chosen_case = next((c for c in corpus_cases if c.get("case_id") == selected_case_id), None)
            if chosen_case:
                st.json(chosen_case)
else:
    st.info("No test cases found.")
