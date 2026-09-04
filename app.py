"""Hyperion Security Engine — minimal Streamlit UI shell.

This is a plumbing checkpoint that wires together the backend modules
(scanner.py, dependency_check.py, repo_scanner.py, ai_llm.py) with zero
visual polish. Confirms the full pipeline runs end-to-end.
"""

import os
import reportlab
import difflib
import time
from pathlib import Path
from collections import Counter

import streamlit as st
from dotenv import load_dotenv
import plotly.graph_objects as go
import plotly.express as px

# Load API configuration from .env
load_dotenv()

from scanner import scan_source
from dependency_check import check_dependencies
from repo_scanner import scan_repository
from ai_llm import get_analysis
import demo_cache


# ---------------------------------------------------------------------------
# Markdown / HTML rendering helper
# ---------------------------------------------------------------------------
# Streamlit 1.62+ ships a new Markdown parser (color syntax, badges, material
# symbols). It can mangle raw HTML strings. The official recommendation is to
# use st.html() for raw HTML - it bypasses the Markdown parser and sanitizes
# the body with DOMPurify. Our class= attributes are preserved.
def _md(html: str) -> None:
    """Render an HTML string. Equivalent to st.markdown(html, unsafe_allow_html=True)
    in Streamlit 1.62+, but routes through st.html to avoid the new parser."""
    st.html(html)


# ---------------------------------------------------------------------------
# Severity / color helpers
# ---------------------------------------------------------------------------

PALETTE = {
    "bg": "#1A0E12",
    "panel": "#2A151B",
    "panel_alt": "#33191F",
    "border": "#4A2530",
    "text_primary": "#F2E4E7",
    "text_muted": "#B08D93",
    "accent": "#E8724C",
    "critical": "#FF4D4D",
    "high": "#F2994A",
    "medium": "#E0C34E",
    "low": "#6FCF97",
}


def severity_color(severity: str) -> str:
    """Map a severity label to its hex color from the palette."""
    if not severity:
        return PALETTE["text_muted"]
    s = severity.lower()
    if s in ("critical",):
        return PALETTE["critical"]
    if s in ("high",):
        return PALETTE["high"]
    if s in ("medium",):
        return PALETTE["medium"]
    if s in ("low",):
        return PALETTE["low"]
    return PALETTE["text_muted"]


def severity_rank(severity: str) -> int:
    """Lower number = higher priority. Used for sort order."""
    if not severity:
        return 99
    s = severity.lower()
    return {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
    }.get(s, 4)


def render_severity_badge(severity: str) -> str:
    """Return HTML for a compact inline severity badge."""
    color = severity_color(severity)
    label = (severity or "Unknown").upper()
    return (
        f'<span style="display:inline-block;padding:0.05rem 0.4rem;'
        f'border:1px solid {color};color:{color};font-family:\'JetBrains Mono\',monospace;'
        f'font-size:0.65rem;letter-spacing:0.05em;border-radius:2px;'
        f'line-height:1.4;">{label}</span>'
    )


# ---------------------------------------------------------------------------
# CSS injection
# ---------------------------------------------------------------------------

def inject_custom_css():
    """Inject Hyperion Security Engine visual identity via CSS tokens."""
    _md(
        """
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">

        <style>
        :root {
            --bg: #1A0E12;
            --panel: #2A151B;
            --panel-alt: #33191F;
            --border: #4A2530;
            --text-primary: #F2E4E7;
            --text-muted: #B08D93;
            --accent: #E8724C;
            --critical: #FF4D4D;
            --high: #F2994A;
            --medium: #E0C34E;
            --low: #6FCF97;
        }

        /* App background */
        .stApp {
            background-color: var(--bg);
            color: var(--text-primary);
        }

        /* Font application - scoped to text-bearing elements only,
           excluding icon fonts and Material Symbols */
        h1, h2, h3, h4, h5, h6,
        p, span, div, label, button, a, li, td, th,
        [data-testid="stMarkdownContainer"],
        [data-testid="stWidgetLabel"],
        [data-testid="stMetricLabel"],
        [data-testid="stMetricValue"] {
            font-family: 'Space Grotesk', -apple-system, BlinkMacSystemFont, sans-serif !important;
        }

        /* Monospace for code/IDs/line numbers / KPI numbers */
        code, pre, .monospace,
        [class*="stCodeBlock"], [class*="stCode"],
        .kpi-value, .kpi-label, .owasp-count, .dep-vuln-id,
        .attack-step-num, .finding-line {
            font-family: 'JetBrains Mono', 'Courier New', monospace !important;
        }

        /* EXCLUDE icon fonts from font-family override */
        [data-testid="stIconMaterial"],
        [class*="material-icons"],
        [class*="material-symbols"],
        [class*="MaterialIcon"] {
            font-family: 'Material Symbols Outlined', 'Material Icons' !important;
        }

        /* Title spacing fix */
        h1 {
            margin-top: 1.5rem !important;
            margin-bottom: 0.5rem !important;
        }

        /* Top brand strip */
        .hyperion-topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.85rem 1.5rem;
            background-color: var(--panel);
            border-bottom: 1px solid var(--border);
            margin: -1rem -1rem 1rem -1rem;
        }
        .hyperion-brand {
            display: flex;
            align-items: baseline;
            gap: 0.6rem;
        }
        .hyperion-brand-mark {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            color: var(--accent);
            border: 1px solid var(--accent);
            border-radius: 2px;
            padding: 0.1rem 0.4rem;
            letter-spacing: 0.05em;
        }
        .hyperion-brand-name {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--text-primary);
        }
        .hyperion-brand-tag {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 0.8rem;
            color: var(--text-muted);
        }

        /* ---- Dense command-center panel system ---- */

        .hyperion-panel {
            background-color: var(--panel);
            border: 1px solid var(--border);
            border-radius: 3px;
            padding: 0.75rem 0.9rem;
            margin: 0;
            height: 100%;
        }

        .panel-title {
            color: var(--text-muted);
            font-family: 'Space Grotesk', sans-serif;
            font-size: 0.65rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            margin: 0 0 0.5rem 0;
            padding: 0 0 0.35rem 0;
            border-bottom: 1px solid var(--border);
        }

        .panel-note {
            color: var(--text-muted);
            font-family: 'Space Grotesk', sans-serif;
            font-size: 0.75rem;
            font-style: italic;
            padding: 0.5rem 0;
        }

        /* Input panel: top accent bar, same thin borders as everything else */
        .input-panel {
            background-color: var(--panel);
            border: 1px solid var(--border);
            border-top: 2px solid var(--accent);
            border-radius: 3px;
            padding: 1.25rem;
            margin: 0 0 1rem 0;
        }

        /* ---- KPI strip (Row 1) ---- */

        .kpi-strip {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 0.5rem;
            margin: 0 0 0.6rem 0;
        }

        .kpi-card {
            background-color: var(--panel);
            border: 1px solid var(--border);
            border-radius: 3px;
            padding: 0.65rem 0.85rem;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            min-height: 70px;
        }

        .kpi-label {
            color: var(--text-muted);
            font-family: 'Space Grotesk', sans-serif;
            font-size: 0.6rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            line-height: 1.2;
        }

        .kpi-value {
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.6rem;
            font-weight: 700;
            line-height: 1.1;
            margin-top: 0.25rem;
        }

        .kpi-value.critical { color: var(--critical); }
        .kpi-value.high { color: var(--high); }
        .kpi-value.medium { color: var(--medium); }
        .kpi-value.low { color: var(--low); }
        .kpi-value.accent { color: var(--accent); }
        .kpi-value.muted { color: var(--text-muted); }
        .kpi-value.placeholder { color: var(--text-muted); opacity: 0.5; }

        /* ---- Dashboard row container (compact gutters) ---- */
        .dash-row {
            display: grid;
            gap: 0.6rem;
            margin: 0 0 0.6rem 0;
        }

        .dash-row-3 {
            grid-template-columns: 3fr 2fr 2fr;
        }
        .dash-row-2 {
            grid-template-columns: 3fr 2fr;
        }
        .dash-row-1 {
            grid-template-columns: 1fr;
        }

        /* ---- Severity donut + compact legend (Row 2 center) ---- */

        .donut-wrap {
            display: flex;
            align-items: center;
            gap: 0.6rem;
        }
        .donut-legend {
            display: flex;
            flex-direction: column;
            gap: 0.3rem;
            font-family: 'Space Grotesk', sans-serif;
            font-size: 0.7rem;
        }
        .donut-legend-item {
            display: flex;
            align-items: center;
            gap: 0.4rem;
        }
        .donut-legend-swatch {
            width: 10px;
            height: 10px;
            border-radius: 2px;
            display: inline-block;
        }
        .donut-legend-label {
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-size: 0.6rem;
        }
        .donut-legend-count {
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            font-size: 0.75rem;
        }

        /* ---- OWASP bar list (Row 2 right) - pure HTML/CSS ---- */

        .owasp-list {
            display: flex;
            flex-direction: column;
            gap: 0.35rem;
        }
        .owasp-item {
            display: grid;
            grid-template-columns: 1fr auto;
            align-items: center;
            gap: 0.5rem;
            font-family: 'Space Grotesk', sans-serif;
            font-size: 0.7rem;
        }
        .owasp-label {
            color: var(--text-primary);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            font-size: 0.7rem;
        }
        .owasp-bar-row {
            display: flex;
            align-items: center;
            gap: 0.4rem;
            grid-column: 1 / -1;
        }
        .owasp-bar-track {
            flex: 1;
            height: 4px;
            background-color: var(--panel-alt);
            border-radius: 1px;
            overflow: hidden;
        }
        .owasp-bar-fill {
            height: 100%;
            background-color: var(--accent);
            border-radius: 1px;
        }
        .owasp-count {
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            font-size: 0.7rem;
            min-width: 1.5rem;
            text-align: right;
        }

        /* ---- Findings dataframe (Row 3 left) ---- */

        .hyperion-panel .stDataFrame {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
        }
        [data-testid="stDataFrame"] table {
            background-color: var(--panel) !important;
        }
        [data-testid="stDataFrame"] thead th {
            background-color: var(--panel-alt) !important;
            color: var(--text-muted) !important;
            font-family: 'Space Grotesk', sans-serif !important;
            font-size: 0.6rem !important;
            text-transform: uppercase !important;
            letter-spacing: 0.08em !important;
            border-bottom: 1px solid var(--border) !important;
            font-weight: 600 !important;
        }
        [data-testid="stDataFrame"] tbody td {
            background-color: var(--panel) !important;
            color: var(--text-primary) !important;
            border-bottom: 1px solid var(--border) !important;
            font-size: 0.7rem !important;
        }
        [data-testid="stDataFrame"] tbody tr:hover td {
            background-color: var(--panel-alt) !important;
        }
        .finding-line {
            color: var(--accent);
            font-weight: 700;
        }

        /* ---- Dependency findings list (Row 3 right) ---- */

        .dep-list {
            display: flex;
            flex-direction: column;
            gap: 0.4rem;
        }
        .dep-item {
            background-color: var(--panel-alt);
            border: 1px solid var(--border);
            border-left: 3px solid var(--text-muted);
            border-radius: 2px;
            padding: 0.4rem 0.55rem;
            display: flex;
            flex-direction: column;
            gap: 0.2rem;
        }
        .dep-item.critical { border-left-color: var(--critical); }
        .dep-item.high { border-left-color: var(--high); }
        .dep-item.medium { border-left-color: var(--medium); }
        .dep-item.low { border-left-color: var(--low); }
        .dep-item.unknown { border-left-color: var(--text-muted); }

        .dep-row-1 {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 0.5rem;
        }
        .dep-pkg {
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            font-weight: 700;
        }
        .dep-vuln-id {
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.65rem;
        }
        .dep-row-2 {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 0.5rem;
            font-family: 'Space Grotesk', sans-serif;
            font-size: 0.65rem;
            color: var(--text-muted);
        }
        .dep-fix {
            color: var(--low);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.65rem;
        }

        /* ---- Attack path timeline (Row 4) ---- */

        .attack-timeline {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }
        .attack-step {
            display: grid;
            grid-template-columns: 32px 1fr;
            gap: 0.6rem;
            padding: 0.5rem 0;
            border-bottom: 1px solid var(--border);
        }
        .attack-step:last-child {
            border-bottom: none;
        }
        .attack-step-num {
            color: var(--accent);
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            font-size: 0.8rem;
            padding-top: 0.05rem;
        }
        .attack-step-text {
            color: var(--text-primary);
            font-family: 'Space Grotesk', sans-serif;
            font-size: 0.75rem;
            line-height: 1.4;
        }

        /* ---- Empty state banner (above grid) ---- */

        .empty-banner {
            background-color: var(--panel);
            border: 1px solid var(--border);
            border-left: 3px solid var(--accent);
            border-radius: 2px;
            padding: 0.5rem 0.75rem;
            color: var(--text-muted);
            font-family: 'Space Grotesk', sans-serif;
            font-size: 0.75rem;
            margin: 0 0 0.6rem 0;
        }

        /* ---- Section headers ---- */

        .section-header {
            color: var(--text-primary);
            font-size: 0.9rem;
            font-weight: 600;
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.4rem;
            margin: 1rem 0 0.6rem 0;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        /* ---- Tab styling ---- */

        .stTabs [data-baseweb="tab-list"] {
            gap: 4px;
            background-color: var(--panel);
            border: 1px solid var(--border);
            border-radius: 3px;
            padding: 0.3rem;
        }

        .stTabs [data-baseweb="tab"] {
            color: var(--text-muted);
            background-color: transparent;
            border-radius: 2px;
            padding: 0.4rem 0.85rem;
            font-size: 0.8rem;
        }

        .stTabs [aria-selected="true"] {
            color: var(--text-primary);
            background-color: var(--bg);
            border: 1px solid var(--border);
        }

        /* ---- Mode selector: explicit high-contrast ---- */

        [data-testid="stRadio"] > label { display: none !important; }
        [data-testid="stRadio"] [role="radiogroup"] { gap: 0.4rem !important; }
        [data-testid="stRadio"] label[data-baseweb="radio"] {
            background-color: var(--panel-alt) !important;
            border: 1px solid var(--border) !important;
            border-radius: 2px !important;
            padding: 0.4rem 0.9rem !important;
            color: var(--text-muted) !important;
            font-family: 'Space Grotesk', sans-serif !important;
            font-size: 0.8rem !important;
        }
        [data-testid="stRadio"] label[data-baseweb="radio"] div:first-child { display: none !important; }
        [data-testid="stRadio"] label[data-baseweb="radio"]:has(input:checked) {
            background-color: var(--accent) !important;
            border-color: var(--accent) !important;
        }
        [data-testid="stRadio"] label[data-baseweb="radio"]:has(input:checked) div {
            color: #FFFFFF !important;
        }
        [data-testid="stRadio"] label[data-baseweb="radio"] div {
            color: inherit !important;
        }

        /* ---- Text area / text input ---- */

        [data-testid="stTextArea"] textarea,
        [data-testid="stTextInput"] input {
            background-color: var(--bg) !important;
            color: var(--text-primary) !important;
            border: 1px solid var(--border) !important;
            border-radius: 2px !important;
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 0.8rem !important;
        }
        [data-testid="stTextArea"] textarea::placeholder,
        [data-testid="stTextInput"] input::placeholder {
            color: var(--text-muted) !important;
            opacity: 0.6;
        }
        [data-testid="stTextArea"] label,
        [data-testid="stTextInput"] label {
            color: var(--text-muted) !important;
            font-family: 'Space Grotesk', sans-serif !important;
            font-size: 0.75rem !important;
            font-weight: 500 !important;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        /* Manual panel label used above file_uploader / text_area calls
           whose native labels are now collapsed (label_visibility="collapsed").
           Keeps the dense command-center label style without fighting the
           native widget label DOM. */
        .hyperion-panel-label {
            color: var(--text-muted);
            font-family: 'Space Grotesk', sans-serif;
            font-size: 0.65rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin: 0 0 0.3rem 0;
        }

        /* ---- File uploader: only style the OUTER dropzone container.
           We do NOT touch the internal browse button DOM at all - that was
           the source of the 'uploadUpload' text overlap bug. The internal
           button keeps its native Streamlit appearance. ---- */
        [data-testid="stFileUploaderDropzone"] {
            background-color: var(--panel-alt) !important;
            border: 1px dashed var(--border) !important;
            border-radius: 2px !important;
        }
        [data-testid="stFileUploaderDropzoneInstructions"] > span:first-child {
            display: none !important;
        }

        /* Fix: "uploadUpload" text overlap on the browse button.
           Streamlit renders both a native button label and an inner span
           simultaneously. We hide all inner text nodes and inject one clean
           label via ::before so only a single "Browse files" label shows. */
        [data-testid="stFileUploaderDropzone"] button[kind="secondary"] {
            color: transparent !important;
            position: relative !important;
            min-width: 120px !important;
            font-size: 0 !important;
        }
        [data-testid="stFileUploaderDropzone"] button[kind="secondary"] * {
            color: transparent !important;
            font-size: 0 !important;
        }
        [data-testid="stFileUploaderDropzone"] button[kind="secondary"]::before {
            content: "Browse files" !important;
            color: var(--text-primary) !important;
            font-family: 'Space Grotesk', sans-serif !important;
            font-size: 0.85rem !important;
            font-weight: 500 !important;
            position: absolute !important;
            left: 50% !important;
            top: 50% !important;
            transform: translate(-50%, -50%) !important;
            white-space: nowrap !important;
        }


        [data-testid="stFileUploaderFile"] {
            background-color: var(--panel) !important;
            border: 1px solid var(--border) !important;
            border-radius: 2px !important;
        }
        [data-testid="stFileUploaderFile"] div,
        [data-testid="stFileUploaderFile"] span {
            color: var(--text-primary) !important;
        }

        /* ---- Scan button ---- */

        .stButton button {
            background-color: var(--accent) !important;
            color: #FFFFFF !important;
            border: none !important;
            border-radius: 2px !important;
            font-family: 'Space Grotesk', sans-serif !important;
            font-weight: 600 !important;
            padding: 0.5rem !important;
            font-size: 0.85rem !important;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }
        .stButton button:hover {
            background-color: #D5613D !important;
        }

        /* ---- Hide sidebar completely ---- */

        [data-testid="stSidebar"] { display: none !important; }
        [data-testid="stSidebarNav"] { display: none !important; }

        /* ---- Empty / placeholder state for individual panels ---- */
        .text-muted {
            color: var(--text-muted);
            font-size: 0.75rem;
            font-family: 'Space Grotesk', sans-serif;
        }

        .empty-state {
            text-align: center;
            padding: 2rem 1rem;
            color: var(--text-muted);
            background-color: var(--panel);
            border: 1px solid var(--border);
            border-radius: 3px;
            margin: 1rem 0;
            font-family: 'Space Grotesk', sans-serif;
            font-size: 0.8rem;
        }

        /* ---- Alerts ---- */
        .stAlert {
            background-color: var(--panel) !important;
            border: 1px solid var(--border) !important;
            color: var(--text-primary) !important;
            font-size: 0.8rem !important;
        }

        /* ---- Scrollbar ---- */
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: var(--bg); }
        ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

        /* Recommendation rows */
        .rec-list {
            display: flex;
            flex-direction: column;
            gap: 0.4rem;
            margin-top: 0.3rem;
        }
        .rec-item {
            display: flex;
            align-items: flex-start;
            gap: 0.6rem;
            font-size: 0.85rem;
            color: var(--text-primary);
            line-height: 1.45;
        }
        .rec-bullet {
            flex: 0 0 6px;
            width: 6px;
            height: 6px;
            border-radius: 50%;
            margin-top: 0.5rem;
            opacity: 0.9;
        }
        .rec-text {
            flex: 1;
        }
        </style>
        """)


# ---------------------------------------------------------------------------
# Chart renderers (recolored to new palette)
# ---------------------------------------------------------------------------

def render_health_gauge(score):
    """Render health score gauge using Plotly, recolored to the burgundy palette."""
    if score is None:
        score = 0
    if score < 30:
        bar_color = PALETTE["critical"]
    elif score < 70:
        bar_color = PALETTE["high"]
    else:
        bar_color = PALETTE["low"]

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            domain={"x": [0, 1], "y": [0, 1]},
            title={"text": " ", "font": {"size": 1, "color": PALETTE["text_primary"]}},
            number={"font": {"size": 42, "color": PALETTE["text_primary"], "family": "JetBrains Mono"}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": PALETTE["text_muted"], "tickfont": {"color": PALETTE["text_muted"], "size": 9}},
                "bar": {"color": bar_color, "thickness": 0.25},
                "bgcolor": "rgba(0,0,0,0)",
                "borderwidth": 0,
                "steps": [
                    {"range": [0, 30], "color": "rgba(255, 77, 77, 0.12)"},
                    {"range": [30, 70], "color": "rgba(242, 153, 74, 0.12)"},
                    {"range": [70, 100], "color": "rgba(111, 207, 151, 0.12)"},
                ],
            },
        )
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": PALETTE["text_primary"], "family": "Space Grotesk"},
        height=220,
        margin=dict(l=10, r=10, t=10, b=10),
    )
    return fig


def render_severity_donut(vulnerabilities):
    """Render severity distribution donut chart, recolored to the burgundy palette."""
    severity_counts = Counter(v.get("severity", "Unknown") for v in vulnerabilities)
    if not severity_counts:
        return None

    df_data = [{"severity": k, "count": v} for k, v in severity_counts.items()]

    color_map = {
        "Critical": PALETTE["critical"],
        "High": PALETTE["high"],
        "Medium": PALETTE["medium"],
        "Low": PALETTE["low"],
        "Unknown": PALETTE["text_muted"],
    }

    fig = px.pie(
        df_data,
        values="count",
        names="severity",
        hole=0.65,
        color="severity",
        color_discrete_map=color_map,
    )
    fig.update_traces(
        textposition="inside",
        textinfo="value",
        textfont={"color": PALETTE["text_primary"], "family": "JetBrains Mono", "size": 11},
        marker={"line": {"color": PALETTE["panel"], "width": 2}},
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": PALETTE["text_primary"], "family": "Space Grotesk"},
        showlegend=False,
        height=180,
        margin=dict(l=5, r=5, t=5, b=5),
    )
    return fig


# ---------------------------------------------------------------------------
# New HTML-only rendering helpers
# ---------------------------------------------------------------------------

def render_owasp_bar_list(vulnerabilities):
    """Render OWASP category distribution as a pure HTML/CSS ranked bar list."""
    counts = Counter(v.get("owasp_category", "Unknown") for v in vulnerabilities)
    if not counts:
        return None
    sorted_items = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    max_count = max(c for _, c in sorted_items) or 1

    items_html = ""
    for category, count in sorted_items:
        width_pct = (count / max_count) * 100
        short_label = category
        if len(short_label) > 38:
            short_label = short_label[:35] + "..."
        items_html += f'''
        <div class="owasp-item">
            <div class="owasp-label" title="{category}">{short_label}</div>
            <div class="owasp-count">{count}</div>
            <div class="owasp-bar-row">
                <div class="owasp-bar-track">
                    <div class="owasp-bar-fill" style="width: {width_pct:.1f}%;"></div>
                </div>
            </div>
        </div>
        '''
    return f'<div class="owasp-list">{items_html}</div>'


def render_findings_dataframe(scan_findings):
    """Render scan findings as a styled dataframe with severity-colored confidence."""
    if not scan_findings:
        return None

    confidence_color_map = {
        "high": PALETTE["critical"],
        "medium": PALETTE["medium"],
        "low": PALETTE["low"],
    }
    rows = []
    for f in scan_findings:
        conf = f.get("confidence", "")
        color = confidence_color_map.get(conf.lower(), PALETTE["text_muted"])
        rows.append({
            "FILE": f.get("file", ""),
            "LINE": f.get("line_number", ""),
            "PATTERN": f.get("pattern_type", ""),
            "CONFIDENCE": conf.upper() if conf else "",
        })

    import pandas as pd
    df = pd.DataFrame(rows, columns=["FILE", "LINE", "PATTERN", "CONFIDENCE"])

    def color_confidence(val):
        v = (val or "").lower()
        if v == "high":
            return f"color: {PALETTE['critical']}; font-weight: 700;"
        if v == "medium":
            return f"color: {PALETTE['medium']}; font-weight: 700;"
        if v == "low":
            return f"color: {PALETTE['low']}; font-weight: 700;"
        return f"color: {PALETTE['text_muted']};"

    def color_line(val):
        return f"color: {PALETTE['accent']}; font-weight: 700;"

    styled = df.style.map(color_confidence, subset=["CONFIDENCE"]).map(color_line, subset=["LINE"])
    return styled


def render_dep_findings_list(dep_findings):
    """Render dependency/CVE findings as a compact ranked HTML list."""
    if not dep_findings:
        return None
    sorted_items = sorted(
        dep_findings,
        key=lambda f: (severity_rank(f.get("severity", "")), f.get("package", "")),
    )
    items_html = ""
    for f in sorted_items:
        sev = (f.get("severity") or "Unknown").lower()
        sev_class = sev if sev in ("critical", "high", "medium", "low") else "unknown"
        pkg = f.get("package", "")
        installed = f.get("installed_version", "")
        vuln_id = f.get("vuln_id", "")
        fixed = f.get("fixed_version")
        fixed_str = f"→ fix: {fixed}" if fixed else "no fix"

        items_html += f'''
        <div class="dep-item {sev_class}">
            <div class="dep-row-1">
                <span class="dep-pkg">{pkg} {installed}</span>
                {render_severity_badge(f.get("severity", "Unknown"))}
            </div>
            <div class="dep-row-2">
                <span class="dep-vuln-id">{vuln_id}</span>
                <span class="dep-fix">{fixed_str}</span>
            </div>
        </div>
        '''
    return f'<div class="dep-list">{items_html}</div>'


def render_attack_path(attack_steps):
    """Render attack path steps as a compact numbered timeline."""
    if not attack_steps:
        return None
    if isinstance(attack_steps, str):
        return f'<div class="attack-step-text">{attack_steps}</div>'

    items_html = ""
    for idx, step in enumerate(attack_steps, start=1):
        if isinstance(step, dict):
            num = step.get("step", idx)
            text = step.get("narrative", step.get("description", str(step)))
        else:
            num = idx
            text = str(step)
        items_html += f'''
        <div class="attack-step">
            <div class="attack-step-num">#{num:02d}</div>
            <div class="attack-step-text">{text}</div>
        </div>
        '''
    return f'<div class="attack-timeline">{items_html}</div>'


# ---------------------------------------------------------------------------
# Input panel
# ---------------------------------------------------------------------------

def render_input_panel():
    """Render the unified input panel (replaces sidebar)."""
    _md('<div class="input-panel">')

    mode = st.radio(
        "Scan Mode",
        ["Paste code snippet", "Upload file", "GitHub repo URL"],
        index=0,
        horizontal=True,
        label_visibility="visible",
    )

    _md('<div style="height: 0.75rem"></div>')

    code = None
    filename = "input.py"
    repo_url = None

    if mode == "Paste code snippet":
        _md(
            '<div class="hyperion-panel-label">Python code</div>')
        code = st.text_area(
            "Python code",
            height=220,
            placeholder="# Paste your Python code here\nimport os\nos.system('ls')",
            label_visibility="collapsed",
        )

    elif mode == "Upload file":
        _md(
            '<div class="hyperion-panel-label">Python file</div>')
        uploaded_file = st.file_uploader(
            "Python file",
            type=["py"],
            accept_multiple_files=False,
            label_visibility="collapsed",
        )
        if uploaded_file is not None:
            try:
                code = uploaded_file.read().decode("utf-8-sig")
                filename = uploaded_file.name
            except UnicodeDecodeError as e:
                st.error(f"Could not decode uploaded file: {e}")
                code = None

    elif mode == "GitHub repo URL":
        _md(
            '<div class="hyperion-panel-label">Repository URL</div>')
        repo_url = st.text_input(
            "Repository URL",
            placeholder="https://github.com/user/repo",
            label_visibility="collapsed",
        )

    _md('<div style="height: 0.4rem"></div>')
    btn_col1, btn_col2 = st.columns([3, 1])
    with btn_col1:
        scan_clicked = st.button("Scan", type="primary", width="stretch")
    with btn_col2:
        load_demo_clicked = st.button("Load Demo", type="secondary", width="stretch")

    _md('</div>')

    return mode, code, filename, repo_url, scan_clicked, load_demo_clicked


# ---------------------------------------------------------------------------
# Dashboard tab - dense command-center grid
# ---------------------------------------------------------------------------

def _kpi_card(label: str, value, value_class: str = ""):
    """Render a single KPI card as raw HTML (returned as a string)."""
    cls = f"kpi-value {value_class}" if value_class else "kpi-value"
    if value is None or value == "":
        display = '<span class="placeholder">--</span>'
    else:
        display = str(value)
    return f'''
    <div class="kpi-card">
        <div class="kpi-label">{label}</div>
        <div class="{cls}">{display}</div>
    </div>
    '''


def _empty_panel(title: str, note: str = "No data available."):
    """Render an empty panel shell with a muted note."""
    return f'''
    <div class="hyperion-panel">
        <div class="panel-title">{title}</div>
        <div class="panel-note">{note}</div>
    </div>
    '''


def _wrap_row(row_html: str, row_class: str = "dash-row-3"):
    return f'<div class="dash-row {row_class}">{row_html}</div>'


def render_dashboard_tab():
    """Render the Dashboard tab content as a dense command-center grid."""
    has_results = "scan_results" in st.session_state

    if not has_results:
        # Pre-scan empty state: keep the dense grid shape with placeholder values.
        _md(
            '<div class="empty-banner">Run a scan to populate this dashboard.</div>')

        # Row 1: 4 placeholder KPIs
        kpi_html = (
            _kpi_card("HEALTH SCORE", None, "placeholder")
            + _kpi_card("TOTAL FINDINGS", None, "placeholder")
            + _kpi_card("CRITICAL", None, "placeholder")
            + _kpi_card("FILES SCANNED", None, "placeholder")
        )
        _md(f'<div class="kpi-strip">{kpi_html}</div>')

        # Row 2: 3 panel placeholders
        row2 = (
            _empty_panel("HEALTH GAUGE", "Awaiting scan results.")
            + _empty_panel("SEVERITY DISTRIBUTION", "Awaiting scan results.")
            + _empty_panel("OWASP CATEGORIES", "Awaiting scan results.")
        )
        _md(_wrap_row(row2, "dash-row-3"))

        # Row 3: 2 panel placeholders
        row3 = (
            _empty_panel("SCAN FINDINGS", "Awaiting scan results.")
            + _empty_panel("DEPENDENCY FINDINGS", "Awaiting scan results.")
        )
        _md(_wrap_row(row3, "dash-row-2"))

        # Row 4: 1 panel placeholder
        row4 = _empty_panel("ATTACK PATH", "Awaiting scan results.")
        _md(_wrap_row(row4, "dash-row-1"))
        return

    results = st.session_state["scan_results"]
    scan_findings = results.get("scan_findings", []) or []
    dep_findings = results.get("dep_findings", []) or []
    analysis = results.get("analysis")
    has_analysis = isinstance(analysis, dict)

    # ---- Row 1: KPI strip ----
    total_findings = len(scan_findings) + len(dep_findings)

    if has_analysis:
        vulnerabilities = analysis.get("vulnerabilities", []) or []
        severity_counts = Counter(v.get("severity", "Unknown") for v in vulnerabilities)
        critical_count = severity_counts.get("Critical", 0)
        health_score = analysis.get("health_score")
        files_scanned_val = 1  # single-file mode
        files_scanned_label = "FILE MODE"
    else:
        vulnerabilities = []
        severity_counts = Counter()
        # In repo mode, count high-confidence findings as a "critical" proxy
        # since there's no AI severity classification for raw pattern hits.
        critical_count = sum(
            1 for f in scan_findings
            if (f.get("confidence", "") or "").lower() == "high"
        )
        health_score = None
        files_scanned_val = results.get("files_scanned", 0)
        files_scanned_label = "FILES SCANNED"

    kpi_html = (
        _kpi_card("HEALTH SCORE", health_score, "accent")
        + _kpi_card("TOTAL FINDINGS", total_findings, "accent")
        + _kpi_card("CRITICAL", critical_count, "critical")
        + _kpi_card(files_scanned_label, files_scanned_val, "accent")
    )
    _md(f'<div class="kpi-strip">{kpi_html}</div>')

    # ---- Row 2: Health gauge | Severity donut | OWASP bars ----
    # LEFT: Health gauge panel
    if has_analysis and health_score is not None:
        gauge_panel = '<div class="hyperion-panel">'
        gauge_panel += '<div class="panel-title">HEALTH GAUGE</div>'
        gauge_panel += '<div class="donut-wrap" style="justify-content:center;">'
        gauge_panel += '</div></div>'
        _md(gauge_panel)
        fig = render_health_gauge(health_score)
        st.plotly_chart(fig, width="stretch", key="dash_health_gauge")
    else:
        _md(
            _empty_panel("HEALTH GAUGE", "Available in snippet/upload mode."))

    # CENTER: Severity donut + compact legend side by side
    if has_analysis and vulnerabilities:
        center_html = '<div class="hyperion-panel">'
        center_html += '<div class="panel-title">SEVERITY DISTRIBUTION</div>'
        center_html += '<div class="donut-wrap">'
        center_html += '<div style="flex: 0 0 110px;"><div id="donut-anchor"></div></div>'
        center_html += '<div class="donut-legend">'
        # Stable legend order by severity rank
        order = ["Critical", "High", "Medium", "Low", "Unknown"]
        for sev in order:
            c = severity_counts.get(sev, 0)
            if c == 0 and sev != "Unknown":
                continue
            color = severity_color(sev)
            center_html += (
                f'<div class="donut-legend-item">'
                f'<span class="donut-legend-swatch" style="background-color:{color};"></span>'
                f'<span class="donut-legend-label">{sev}</span>'
                f'<span class="donut-legend-count">{c}</span>'
                f'</div>'
            )
        center_html += '</div></div></div>'
        _md(center_html)
        fig = render_severity_donut(vulnerabilities)
        if fig:
            st.plotly_chart(fig, width="stretch", key="dash_severity_donut")
    else:
        _md(
            _empty_panel("SEVERITY DISTRIBUTION", "Available in snippet/upload mode."))

    # RIGHT: OWASP bar list (pure HTML/CSS, no Plotly)
    right_html = '<div class="hyperion-panel">'
    right_html += '<div class="panel-title">OWASP CATEGORIES</div>'
    if has_analysis and vulnerabilities:
        owasp_html = render_owasp_bar_list(vulnerabilities)
        right_html += owasp_html if owasp_html else '<div class="panel-note">No categories identified.</div>'
    else:
        right_html += '<div class="panel-note">Available in snippet/upload mode.</div>'
    right_html += '</div>'
    _md(right_html)

    _md('<div style="height: 0.4rem"></div>')

    # ---- Row 3: Findings dataframe | Dep findings list ----
    # LEFT: scan findings dataframe
    findings_html = '<div class="hyperion-panel">'
    findings_html += '<div class="panel-title">SCAN FINDINGS</div>'
    findings_html += '</div>'
    _md(findings_html)
    styled = render_findings_dataframe(scan_findings)
    if styled is not None:
        st.dataframe(styled, width="stretch", hide_index=True, height=260)
    else:
        _md('<div class="panel-note">No pattern findings.</div>')

    # RIGHT: dependency findings ranked list
    dep_html = '<div class="hyperion-panel">'
    dep_html += '<div class="panel-title">DEPENDENCY FINDINGS</div>'
    dep_list_html = render_dep_findings_list(dep_findings)
    if dep_list_html:
        dep_html += dep_list_html
    else:
        dep_html += '<div class="panel-note">No dependency issues.</div>'
    dep_html += '</div>'
    _md(dep_html)

    _md('<div style="height: 0.4rem"></div>')

    # ---- Row 4: Attack path timeline (full width) ----
    attack_html = '<div class="hyperion-panel">'
    attack_html += '<div class="panel-title">ATTACK PATH</div>'
    if has_analysis:
        attack_steps = analysis.get("attack_path_poc")
        path_html = render_attack_path(attack_steps)
        if path_html:
            attack_html += path_html
        else:
            attack_html += '<div class="panel-note">No attack path generated.</div>'
    else:
        attack_html += '<div class="panel-note">Available in snippet/upload mode.</div>'
    attack_html += '</div>'
    _md(attack_html)


# ---------------------------------------------------------------------------
# Threat modeling tab (logic preserved, palette updated)
# ---------------------------------------------------------------------------

def render_threat_modeling_tab():
    """Render the Threat Modeling & Attack Paths tab."""
    if "scan_results" not in st.session_state:
        _md(
            '<div class="empty-state">Run a scan to generate threat models and attack path analysis.</div>')
        return

    results = st.session_state["scan_results"]
    analysis = results.get("analysis")

    if not analysis:
        _md(
            '<div class="empty-state">Threat modeling and attack path generation are available in snippet/upload mode.</div>')
        return

    if "graphviz_dot_script" in analysis and analysis["graphviz_dot_script"]:
        _md('<div class="section-header">Attack Graph</div>')
        try:
            st.graphviz_chart(analysis["graphviz_dot_script"])
        except Exception as e:
            st.error(f"Could not render attack graph: {e}")

    if "attack_path_poc" in analysis and analysis["attack_path_poc"]:
        _md('<div class="section-header">Attack Path Proof of Concept</div>')
        _md('<div class="hyperion-panel">')
        path_html = render_attack_path(analysis["attack_path_poc"])
        if path_html:
            _md(path_html)
        else:
            _md('<div class="panel-note">No attack path generated.</div>')
        _md('</div>')


# ---------------------------------------------------------------------------
# Recommendations & Hardening tab
# ---------------------------------------------------------------------------

def render_recommendations_tab():
    """Render the Recommendations & Hardening tab as three grouped panels."""
    if "scan_results" not in st.session_state:
        _md(
            '<div class="empty-state">Run a scan to generate recommendations and hardening guidance.</div>')
        return

    results = st.session_state["scan_results"]
    analysis = results.get("analysis")

    if not isinstance(analysis, dict):
        _md(
            '<div class="empty-state">Recommendations are available in snippet/upload mode.</div>')
        return

    recommendations = analysis.get("recommendations")
    if not isinstance(recommendations, dict):
        _md(_empty_panel("RECOMMENDATIONS", "Recommendations not available."))
        return

    groups = [
        ("IMMEDIATE FIXES", "immediate_fixes", "var(--critical)", "01 //"),
        ("ARCHITECTURE HARDENING", "architecture_hardening", "var(--high)", "02 //"),
        ("PIPELINE GUARDRAILS", "pipeline_guardrails", "var(--accent)", "03 //"),
    ]

    for title, key, color, prefix in groups:
        items = recommendations.get(key) or []
        html = '<div class="hyperion-panel">'
        html += (
            f'<div class="panel-title">'
            f'<span style="color:{color};">{prefix}</span> &nbsp;{title}'
            f'</div>'
        )
        if items:
            html += '<div class="rec-list">'
            for item in items:
                text = str(item).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                html += (
                    f'<div class="rec-item">'
                    f'<span class="rec-bullet" style="background-color:{color};"></span>'
                    f'<span class="rec-text">{text}</span>'
                    f'</div>'
                )
            html += '</div>'
        else:
            html += '<div class="panel-note">None identified.</div>'
        html += '</div>'
        _md(html)
        _md('<div style="height: 0.4rem"></div>')


# ---------------------------------------------------------------------------
# Code Refactoring tab
# ---------------------------------------------------------------------------

def render_code_refactoring_tab():
    """Render the Code Refactoring tab: side-by-side diff + download."""
    if "scan_results" not in st.session_state:
        _md('<div class="empty-state">Run a scan to generate refactored code.</div>')
        return

    results = st.session_state["scan_results"]
    analysis = results.get("analysis")

    if not isinstance(analysis, dict):
        _md(
            '<div class="empty-state">Code refactoring is available in snippet/upload mode.</div>')
        return

    refactored = analysis.get("refactored_code") or {}
    full_source = refactored.get("full_source", "")
    filename = refactored.get("file") or "refactored.py"

    if not full_source:
        _md(_empty_panel("CODE REFACTORING", "No refactored code available."))
        return

    original_source = results.get("source_code", "") or ""

    original_lines = original_source.splitlines(keepends=True)
    refactored_lines = full_source.splitlines(keepends=True)
    diff_lines = list(difflib.unified_diff(
        original_lines, refactored_lines,
        fromfile="original", tofile="refactored", lineterm="",
    ))

    added = sum(1 for ln in diff_lines if ln.startswith("+") and not ln.startswith("+++"))
    removed = sum(1 for ln in diff_lines if ln.startswith("-") and not ln.startswith("---"))
    unchanged = max(0, len(original_lines) - removed)

    _md(
        f'<div class="hyperion-panel">'
        f'<div class="panel-title">CODE REFACTORING</div>'
        f'<div class="panel-note">'
        f'<span style="color:var(--low);">+{added} added</span> &nbsp; '
        f'<span style="color:var(--critical);">-{removed} removed</span> &nbsp; '
        f'<span style="color:var(--text-muted);">{unchanged} unchanged</span>'
        f'</div></div>'
    )
    _md('<div style="height: 0.4rem"></div>')

    left_col, right_col = st.columns(2)
    with left_col:
        st.code(original_source, language="python")
    with right_col:
        st.code(full_source, language="python")

    _md('<div style="height: 0.4rem"></div>')

    st.download_button(
        label=f"Download {filename}",
        data=full_source.encode("utf-8"),
        file_name=filename,
        mime="text/plain",
    )


def render_export_tab():
    """Render the Export Report tab: generate and download a PDF report."""
    from datetime import datetime

    if "scan_results" not in st.session_state or not st.session_state["scan_results"]:
        _md('<div class="empty-state">Run a scan to generate a PDF report.</div>')
        return

    results = st.session_state["scan_results"]
    scan_findings = results.get("scan_findings", []) or []
    dep_findings = results.get("dep_findings", []) or []
    analysis = results.get("analysis") or {}
    files_scanned = results.get("files_scanned", 1)
    mode = results.get("mode", "Paste code snippet")

    pdf_bytes = _build_pdf_report(
        scan_findings=scan_findings,
        dep_findings=dep_findings,
        analysis=analysis,
        files_scanned=files_scanned,
        mode=mode,
    )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    st.download_button(
        label="Download Security Report (PDF)",
        data=pdf_bytes,
        file_name=f"hyperion_security_report_{timestamp}.pdf",
        mime="application/pdf",
        type="primary",
        width="stretch",
    )


def _build_pdf_report(
    scan_findings: list,
    dep_findings: list,
    analysis: dict,
    files_scanned: int,
    mode: str,
) -> bytes:
    """Build a professional PDF report from scan results."""
    from datetime import datetime
    from io import BytesIO

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )

    logo_path = ""

    SEVERITY_COLORS = {
        "Critical": "#E5484D",
        "High": "#F0883E",
        "Medium": "#E8C547",
        "Low": "#6FCF97",
    }
    BG = colors.HexColor("#12141A")
    PANEL = colors.HexColor("#1B1E27")
    ROW_ALT = colors.HexColor("#2C2F3A")
    TEXT_PRIMARY = colors.HexColor("#E4E6EB")
    TEXT_MUTED = colors.HexColor("#8B8FA3")
    ACCENT = colors.HexColor("#E8724C")
    DIVIDER = colors.HexColor("#3A3E4A")

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleX", parent=styles["Title"], fontName="Helvetica-Bold",
        fontSize=24, textColor=TEXT_PRIMARY,
        spaceAfter=4, alignment=1,
    )
    subtitle_style = ParagraphStyle(
        "SubtitleX", parent=styles["Normal"], fontName="Helvetica",
        fontSize=12, textColor=TEXT_MUTED,
        spaceAfter=18, alignment=1,
    )
    section_style = ParagraphStyle(
        "SectionX", parent=styles["Heading2"], fontName="Helvetica-Bold",
        fontSize=14, textColor=colors.white, backColor=ACCENT,
        borderPadding=(4, 6, 4, 6), spaceBefore=10, spaceAfter=8,
        leftIndent=0,
    )
    body_style = styles["BodyText"]
    body_style.fontName = "Helvetica"
    body_style.fontSize = 10
    body_style.textColor = TEXT_PRIMARY

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=LETTER,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
    )

    story = []

    if logo_path:
        try:
            story.append(Image(logo_path, width=1.5 * inch, height=1.5 * inch))
            story.append(Spacer(1, 6))
        except Exception:
            pass

    story.append(Paragraph("Hyperion Engine", title_style))
    story.append(Paragraph("Security Report", subtitle_style))

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    health_score = analysis.get("health_score")
    if isinstance(health_score, (int, float)) and health_score >= 90:
        health_color = "#6FCF97"
    elif isinstance(health_score, (int, float)) and health_score >= 70:
        health_color = "#E8C547"
    else:
        health_color = "#E5484D"
    health_score_str = (
        f"{int(health_score)}" if isinstance(health_score, (int, float)) else "N/A"
    )

    overview_data = [
        ["Generated", generated_at],
        ["Scan Mode", mode],
        ["Files Scanned", str(files_scanned)],
        ["Health Score",
         f'<font color="{health_color}"><b>{health_score_str}</b></font>'],
        ["Pattern Findings", str(len(scan_findings))],
        ["Dependency Issues", str(len(dep_findings))],
    ]
    overview_table = Table(
        [[Paragraph(str(cell), body_style) for cell in row] for row in overview_data],
        colWidths=[2 * inch, 4.5 * inch],
    )
    overview_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PANEL),
        ("BACKGROUND", (0, 0), (0, -1), ROW_ALT),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOX", (0, 0), (-1, -1), 0.5, DIVIDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, DIVIDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))

    story.append(Paragraph("Scan Overview", section_style))
    story.append(overview_table)
    story.append(Spacer(1, 14))

    story.append(Paragraph("Vulnerability Findings", section_style))
    if scan_findings:
        vuln_rows = [["File", "Line", "Pattern Type", "Severity"]]
        for finding in scan_findings[:200]:
            severity = finding.get("severity", "Medium")
            color = SEVERITY_COLORS.get(severity, "#6B7280")
            cell_severity = (
                f'<font color="{color}"><b>{severity}</b></font>'
            )
            vuln_rows.append([
                Paragraph(str(finding.get("file", "")), body_style),
                str(finding.get("line", "")),
                Paragraph(str(finding.get("pattern_type", "")), body_style),
                Paragraph(cell_severity, body_style),
            ])
        vuln_table = Table(vuln_rows, colWidths=[2.2 * inch, 0.7 * inch, 2.2 * inch, 1.4 * inch])
        vuln_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("ALIGN", (0, 0), (-1, 0), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BACKGROUND", (0, 1), (-1, -1), PANEL),
            ("BOX", (0, 0), (-1, -1), 0.5, DIVIDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, DIVIDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [PANEL, ROW_ALT]),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(vuln_table)
        if len(scan_findings) > 200:
            story.append(Spacer(1, 6))
            story.append(Paragraph(
                f"<i>Showing first 200 of {len(scan_findings)} findings.</i>",
                body_style,
            ))
    else:
        story.append(Paragraph("<i>No pattern findings.</i>", body_style))
    story.append(Spacer(1, 14))

    story.append(Paragraph("Dependency Vulnerabilities", section_style))
    if dep_findings:
        dep_rows = [["Package", "Vulnerability ID", "Severity", "Fixed Version"]]
        for dep in dep_findings[:200]:
            severity = dep.get("severity", "Medium")
            color = SEVERITY_COLORS.get(severity, "#6B7280")
            fixed_versions = dep.get("fixed_versions") or dep.get("fixed_version") or []
            if isinstance(fixed_versions, list):
                fixed_str = ", ".join(fixed_versions) if fixed_versions else "N/A"
            else:
                fixed_str = str(fixed_versions)
            cell_severity = f'<font color="{color}"><b>{severity}</b></font>'
            dep_rows.append([
                Paragraph(str(dep.get("package", "")), body_style),
                Paragraph(str(dep.get("vuln_id", "")), body_style),
                Paragraph(cell_severity, body_style),
                Paragraph(fixed_str, body_style),
            ])
        dep_table = Table(
            dep_rows,
            colWidths=[1.6 * inch, 1.6 * inch, 1.4 * inch, 1.9 * inch],
        )
        dep_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BACKGROUND", (0, 1), (-1, -1), PANEL),
            ("BOX", (0, 0), (-1, -1), 0.5, DIVIDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, DIVIDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [PANEL, ROW_ALT]),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(dep_table)
        if len(dep_findings) > 200:
            story.append(Spacer(1, 6))
            story.append(Paragraph(
                f"<i>Showing first 200 of {len(dep_findings)} findings.</i>",
                body_style,
            ))
    else:
        story.append(Paragraph("<i>No dependency vulnerabilities.</i>", body_style))
    story.append(Spacer(1, 14))

    story.append(Paragraph("Recommendations", section_style))
    recommendations = analysis.get("recommendations") or {}
    subsections = [
        ("Immediate Fixes", recommendations.get("immediate_fixes") or []),
        ("Architecture Hardening",
         recommendations.get("architecture_hardening") or []),
        ("Pipeline Guardrails",
         recommendations.get("pipeline_guardrails") or []),
    ]
    any_recs = False
    for sub_title, items in subsections:
        if items:
            any_recs = True
            sub_style = ParagraphStyle(
                "SubSection", parent=styles["Heading3"],
                fontName="Helvetica-Bold", fontSize=11,
                textColor=TEXT_PRIMARY,
                spaceBefore=6, spaceAfter=4,
            )
            story.append(Paragraph(sub_title, sub_style))
            for item in items:
                story.append(Paragraph(f"&bull; {item}", body_style))
    if not any_recs:
        story.append(Paragraph("<i>No recommendations available.</i>", body_style))
    story.append(Spacer(1, 14))

    story.append(Paragraph("Attack Path Analysis", section_style))
    attack_steps = analysis.get("attack_path_poc") or []
    if attack_steps:
        for i, step in enumerate(attack_steps, 1):
            if isinstance(step, dict):
                text = step.get("narrative", step.get("description", str(step)))
            else:
                text = str(step)
            story.append(Paragraph(f"<b>Step {i}.</b> {text}", body_style))
            story.append(Spacer(1, 3))
    else:
        story.append(Paragraph("<i>No attack path generated.</i>", body_style))

    def _bg_fill(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(BG)
        canvas.rect(0, 0, doc.pagesize[0], doc.pagesize[1], fill=1, stroke=0)
        canvas.restoreState()

    doc.build(
        story,
        onFirstPage=_bg_fill,
        onLaterPages=_bg_fill,
    )
    return buffer.getvalue()


def _footer(canvas, doc):
    """Draw footer with branding and page number."""
    from reportlab.lib import colors as rl_colors
    from reportlab.lib.units import inch
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(rl_colors.HexColor("#8B8FA3"))
    canvas.drawString(0.75 * inch, 0.4 * inch, "Hyperion Security Engine")
    canvas.drawRightString(
        7.75 * inch, 0.4 * inch, f"Page {doc.page}",
    )
    canvas.restoreState()


# ---------------------------------------------------------------------------
# Placeholder tabs
# ---------------------------------------------------------------------------

def render_coming_soon_tab(tab_name):
    """Render a placeholder for incomplete tabs."""
    _md(
        f'<div class="empty-state">The {tab_name} feature is under development.</div>')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    st.set_page_config(page_title="Hyperion Security Engine", layout="wide")

    inject_custom_css()

    _md(
        '''
        <div class="hyperion-topbar">
            <div class="hyperion-brand">
                <span class="hyperion-brand-mark">H//</span>
                <span class="hyperion-brand-name">Hyperion Security Engine</span>
            </div>
            <span class="hyperion-brand-tag">Static analysis · Threat modeling · AI remediation</span>
        </div>
        ''')

    mode, code, filename, repo_url, scan_clicked, load_demo_clicked = render_input_panel()

    if load_demo_clicked:
        cached = demo_cache.load_cache("demo_snippet")
        if cached:
            st.session_state["scan_results"] = cached
            st.success("Demo loaded from cache.")
            st.rerun()
        else:
            st.warning("No demo cache found. Run cache_demo_scan.py first.")
            st.stop()

    if scan_clicked:
        if mode == "Paste code snippet" and not code:
            st.warning("Please paste some code to scan.")
        elif mode == "Upload file" and code is None:
            st.warning("Please upload a Python file.")
        elif mode == "GitHub repo URL" and not repo_url:
            st.warning("Please enter a GitHub repository URL.")
        else:
            try:
                with st.spinner("Analyzing..."):
                    scan_findings = []
                    dep_findings = []
                    source_code = ""

                    if mode in ["Paste code snippet", "Upload file"]:
                        scan_started_at = time.perf_counter()
                        scan_findings = scan_source(code or "", filename=filename)
                        print(
                            f"[Hyperion] Scan completed in "
                            f"{time.perf_counter() - scan_started_at:.2f}s "
                            f"({len(scan_findings)} findings)"
                        )

                        # Auto-run dependency check on this project's own requirements.txt.
                        # The UI no longer accepts a requirements.txt upload - the engine
                        # scans its own declared dependencies (eat-your-own-dogfood pattern).
                        PROJECT_REQ = os.path.join(os.path.dirname(__file__), "requirements.txt")
                        if os.path.isfile(PROJECT_REQ):
                            dependency_started_at = time.perf_counter()
                            dep_findings = check_dependencies(PROJECT_REQ)
                            print(
                                f"[Hyperion] Dependency check completed in "
                                f"{time.perf_counter() - dependency_started_at:.2f}s"
                            )
                        else:
                            dep_findings = []

                        source_code = code or ""
                        analysis_started_at = time.perf_counter()
                        analysis = get_analysis(
                            scan_findings=scan_findings,
                            dep_findings=dep_findings,
                            source_code=source_code,
                        )
                        print(
                            f"[Hyperion] AI analysis completed in "
                            f"{time.perf_counter() - analysis_started_at:.2f}s"
                        )

                        output = {
                            "scan_findings": scan_findings,
                            "dep_findings": dep_findings,
                            "analysis": analysis,
                            "source_code": source_code,
                        }

                    elif mode == "GitHub repo URL":
                        repo_scan_started_at = time.perf_counter()
                        result = scan_repository(repo_url)
                        print(
                            f"[Hyperion] Repo scan completed in "
                            f"{time.perf_counter() - repo_scan_started_at:.2f}s "
                            f"({result['files_scanned']} files scanned)"
                        )
                        scan_findings = result["scan_findings"]
                        dep_findings = result["dep_findings"]

                        from ai_fallback import generate_fallback_analysis
                        repo_analysis = generate_fallback_analysis(
                            scan_findings=scan_findings,
                            dep_findings=dep_findings,
                            source_code="",
                        )

                        output = {
                            "scan_findings": scan_findings,
                            "dep_findings": dep_findings,
                            "files_scanned": result["files_scanned"],
                            "analysis": repo_analysis,
                        }

                        if result["error"]:
                            st.warning(f"Repository scan error: {result['error']}")

                    st.session_state["scan_results"] = output
                    st.success("Scan complete. View results in the tabs below.")

            except Exception as e:
                st.error(f"Unexpected error during scan: {e}")
                st.exception(e)

    st.markdown("---")
    _md('<div class="section-header">Results</div>')

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "Dashboard",
        "Threat Modeling & Attack Paths",
        "Recommendations & Hardening",
        "Code Refactoring",
        "Export Report",
    ])

    with tab1:
        render_dashboard_tab()

    with tab2:
        render_threat_modeling_tab()

    with tab3:
        render_recommendations_tab()

    with tab4:
        render_code_refactoring_tab()

    with tab5:
        render_export_tab()


if __name__ == "__main__":
    main()
