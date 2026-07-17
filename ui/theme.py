"""SOC-console theme: the dashboard's custom CSS."""

import streamlit as st

CSS = """
<style>
    :root {
        --ls-accent: #2dd4bf;
        --ls-bg: #0d1117;
        --ls-surface: #161b22;
        --ls-surface-2: #1c2230;
        --ls-line: #2a323d;
        --ls-text: #e6edf3;
        --ls-muted: #8b949e;
        --ls-high: #f85149;
        --ls-med: #e3a008;
        --ls-low: #3fb950;
        --ls-info: #58a6ff;
    }

    /* Base */
    .stApp { background: var(--ls-bg); }
    .block-container { padding-top: 1.4rem; padding-bottom: 3rem; max-width: 1400px; }
    h1, h2, h3, h4 { letter-spacing: -0.01em; }
    hr { border-color: var(--ls-line) !important; }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background: var(--ls-surface);
        border-right: 1px solid var(--ls-line);
    }
    [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3 { font-size: 0.95rem; }

    /* Tabs -> pill/underline bar */
    .stTabs [data-baseweb="tab-list"] {
        gap: 4px;
        background: var(--ls-surface);
        padding: 5px;
        border-radius: 12px;
        border: 1px solid var(--ls-line);
    }
    .stTabs [data-baseweb="tab"] {
        height: 40px;
        border-radius: 8px;
        padding: 0 16px;
        color: var(--ls-muted);
        font-weight: 600;
    }
    .stTabs [aria-selected="true"] {
        background: var(--ls-surface-2) !important;
        color: var(--ls-accent) !important;
    }

    /* Native metric cards */
    [data-testid="stMetric"] {
        background: var(--ls-surface);
        border: 1px solid var(--ls-line);
        border-radius: 12px;
        padding: 14px 18px;
    }
    [data-testid="stMetricValue"] { font-variant-numeric: tabular-nums; }

    /* Expanders / log cards */
    [data-testid="stExpander"] {
        border: 1px solid var(--ls-line);
        border-radius: 10px;
        margin-bottom: 8px;
        background: var(--ls-surface);
    }
    [data-testid="stExpander"] summary:hover { color: var(--ls-accent); }

    /* Buttons */
    .stButton > button {
        border-radius: 9px;
        border: 1px solid var(--ls-line);
        font-weight: 600;
    }
    .stButton > button:hover { border-color: var(--ls-accent); color: var(--ls-accent); }

    /* Risk text helpers */
    .risk-high { color: var(--ls-high); font-weight: 700; }
    .risk-medium { color: var(--ls-med); font-weight: 700; }
    .risk-low { color: var(--ls-low); font-weight: 700; }

    /* ---- Custom LocalShield components ---- */
    .ls-header {
        display: flex; align-items: center; gap: 16px;
        padding: 18px 22px; margin-bottom: 6px;
        background: linear-gradient(120deg, var(--ls-surface) 0%, #10202a 100%);
        border: 1px solid var(--ls-line); border-radius: 16px;
        position: relative; overflow: hidden;
    }
    .ls-header::before {
        content:""; position:absolute; left:0; top:0; bottom:0; width:4px;
        background: var(--ls-accent);
    }
    .ls-badge-shield { font-size: 2.1rem; line-height: 1; }
    .ls-header h1 { margin: 0; font-size: 1.7rem; color: var(--ls-text); }
    .ls-header .sub { color: var(--ls-muted); font-size: 0.9rem; margin-top: 2px; }
    .ls-status {
        margin-left: auto; display: flex; align-items: center; gap: 8px;
        font-size: 0.82rem; color: var(--ls-low); font-weight: 600;
        background: rgba(63,185,80,.1); border: 1px solid rgba(63,185,80,.3);
        padding: 6px 12px; border-radius: 20px; white-space: nowrap;
    }
    .ls-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--ls-low);
        box-shadow: 0 0 0 0 rgba(63,185,80,.6); animation: lspulse 2s infinite; }
    @keyframes lspulse {
        0% { box-shadow: 0 0 0 0 rgba(63,185,80,.5); }
        70% { box-shadow: 0 0 0 7px rgba(63,185,80,0); }
        100% { box-shadow: 0 0 0 0 rgba(63,185,80,0); }
    }
    @media (prefers-reduced-motion: reduce) { .ls-dot { animation: none; } }
    /* Watcher-status variants (heartbeat-driven: stale / offline) */
    .ls-status.stale { color: var(--ls-med); background: rgba(227,160,8,.1); border-color: rgba(227,160,8,.3); }
    .ls-status.stale .ls-dot { background: var(--ls-med); animation: none; box-shadow: none; }
    .ls-status.offline { color: var(--ls-high); background: rgba(248,81,73,.1); border-color: rgba(248,81,73,.3); }
    .ls-status.offline .ls-dot { background: var(--ls-high); animation: none; box-shadow: none; }

    .ls-kpi {
        background: var(--ls-surface); border: 1px solid var(--ls-line);
        border-radius: 13px; padding: 15px 17px; height: 100%;
        border-top: 3px solid var(--kpi-accent, var(--ls-accent));
    }
    .ls-kpi .k-top { display:flex; align-items:center; justify-content:space-between; }
    .ls-kpi .k-ico { font-size: 1.15rem; opacity: .9; }
    .ls-kpi .k-label { color: var(--ls-muted); font-size: .74rem; text-transform: uppercase;
        letter-spacing: .06em; font-weight: 600; }
    .ls-kpi .k-val { font-size: 1.9rem; font-weight: 750; line-height: 1.1; margin-top: 6px;
        font-variant-numeric: tabular-nums; color: var(--ls-text); }
    .ls-kpi .k-foot { color: var(--ls-muted); font-size: .76rem; margin-top: 3px; }

    .ls-chip {
        display:inline-block; font-size:.72rem; font-weight:700; padding:3px 9px;
        border-radius: 6px; letter-spacing:.03em;
    }
    .chip-high { color: var(--ls-high); background: rgba(248,81,73,.13); }
    .chip-med  { color: var(--ls-med);  background: rgba(227,160,8,.13); }
    .chip-low  { color: var(--ls-low);  background: rgba(63,185,80,.13); }

    .ls-ip-card {
        display:flex; align-items:center; gap:12px;
        background: var(--ls-surface); border:1px solid var(--ls-line);
        border-left: 3px solid var(--ls-high); border-radius: 10px;
        padding: 12px 15px; margin-bottom: 8px;
    }
    .ls-ip-card .ip { font-family: ui-monospace, Menlo, monospace; font-weight:700; font-size:.98rem; }
    .ls-ip-card .meta { color: var(--ls-muted); font-size:.8rem; }
    .ls-ip-card .tag { margin-left:auto; font-size:.72rem; color: var(--ls-high);
        background: rgba(248,81,73,.12); padding:3px 9px; border-radius:6px; font-weight:700; }
</style>
"""


def apply_theme() -> None:
    """Injects the SOC-console CSS into the page."""
    st.markdown(CSS, unsafe_allow_html=True)
