#!/usr/bin/env python3
"""
Real-Time IDPS Dashboard with Dash + Plotly
Shows live ingestion logs, threat maps, and triage controls
"""

import dash
from dash import dcc, html, Input, Output, State, ctx, MATCH, ALL
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import pandas as pd
import sys
import logging
from pathlib import Path
import json
import threading
from collections import deque
from custom_styles import CUSTOM_STYLE
import kpi

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add project root to Python path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from utils.threat_actions import threat_actions
from utils.geo_location import geo_service
from Autobot.VectorDB.NullPoint_Vector import connect_db

# Global real-time log buffer (thread-safe)
RT_LOGS = deque(maxlen=500)  # Keep last 500 log entries
RT_LOGS_LOCK = threading.Lock()

def add_realtime_log(level, message, metadata=None):
    """Add log entry with timestamp to real-time buffer."""
    with RT_LOGS_LOCK:
        RT_LOGS.append({
            'timestamp': datetime.now().isoformat(),
            'level': level,  # 'info', 'warning', 'error', 'success'
            'message': message,
            'metadata': metadata or {}
        })

# Set global realtime logger for ingestion engine
try:
    from Autobot.email_ingestion import set_realtime_logger
    set_realtime_logger(add_realtime_log)
    logger.info("✅ Real-time logging initialized")
except Exception as e:
    logger.error(f"Failed to initialize realtime logging: {e}")

# Initialize Dash app with Bootstrap theme
app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.BOOTSTRAP],
    suppress_callback_exceptions=True
)

app.index_string = f"""
<!DOCTYPE html>
<html>
    <head>
        {{%metas%}}
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{{%title%}}</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;700;800&family=Sora:wght@500;600;700&display=swap" rel="stylesheet">
        {{%favicon%}}
        {{%css%}}
        {CUSTOM_STYLE}
    </head>
    <body>
        {{%app_entry%}}
        <footer>
            {{%config%}}
            {{%scripts%}}
            {{%renderer%}}
        </footer>
    </body>
</html>
"""

# ============================================================================
# LAYOUT
# ============================================================================

app.layout = dbc.Container([
    # Header
    dbc.Row([
        dbc.Col([
            html.Div([
                html.Span("Threat Command Center", className="hero-kicker"),
                html.H1("NullPointVector Security Console", className="hero-title"),
                html.P(
                    "Live threat operations across phishing, smishing, and vishing with real-time response controls.",
                    className="hero-subtitle"
                )
            ], className="hero-panel")
        ], width=12)
    ], className="mb-4"),
    
    # Navigation Tabs (Order: Monitor → Scanner → Geo → Raw Data)
    dbc.Row([
        dbc.Col([
            dbc.Tabs([
                dbc.Tab(label="🎯 Live Monitor", tab_id="monitor"),
                dbc.Tab(label="📈 KPIs & Metrics", tab_id="kpi"),
                dbc.Tab(label="🔍 Email Scanner", tab_id="scanner"),
                dbc.Tab(label="📱 Smishing (SMS)", tab_id="smish"),
                dbc.Tab(label="📞 Vishing (Voice)", tab_id="vish"),
                dbc.Tab(label="🌍 Geo Intelligence", tab_id="geo-intel"),
                dbc.Tab(label="🔒 Security Score", tab_id="security"),
                dbc.Tab(label="📊 Raw Data", tab_id="raw-data"),
            ], id="tabs", active_tab="monitor")
        ], width=12)
    ], className="mb-4"),
    
    # Tab content container
    html.Div(id="tab-content", className="tab-content-shell"),
    
    # Auto-refresh interval (updates every 2 seconds)
    dcc.Interval(
        id='interval-component',
        interval=2000,  # 2 seconds
        n_intervals=0
    ),
    
    # Store for selected threat
    dcc.Store(id='selected-threat')
    
], fluid=True, className="app-shell")

# ============================================================================
# TAB CONTENT LAYOUTS
# ============================================================================

def render_monitor_tab():
    """Live monitoring dashboard with stats and threat list."""
    return html.Div([
        # Live Stats Row
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H4("📧 Total Emails", className="card-title"),
                        html.H2(id="total-emails", children="0", className="text-info")
                    ])
                ])
            ], xs=12, md=6, xl=3),
            
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H4("🚨 Threats Detected", className="card-title"),
                        html.H2(id="total-threats", children="0", className="text-danger")
                    ])
                ])
            ], xs=12, md=6, xl=3),
            
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H4("🔴 Blocked", className="card-title"),
                        html.H2(id="total-blocked", children="0", className="text-warning")
                    ])
                ])
            ], xs=12, md=6, xl=3),
            
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H4("⚡ Processing", className="card-title"),
                        html.H2(id="processing-rate", children="0/s", className="text-success")
                    ])
                ])
            ], xs=12, md=6, xl=3),
        ], className="mb-4"),
        
        # Live Log Stream
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("📜 Live Ingestion Logs"),
                    dbc.CardBody([
                        html.Div(
                            id="live-logs",
                            className="log-stream",
                            style={
                                "height": "300px",
                                "overflow-y": "scroll",
                                "padding": "10px",
                                "font-family": "monospace",
                                "font-size": "12px"
                            }
                        )
                    ])
                ])
            ], xs=12, lg=6),
            
            # Threat Map (Geo visualization)
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("🌍 Threat Origins (Last 24h)"),
                    dbc.CardBody([
                        dcc.Graph(id="threat-map", style={"height": "300px"})
                    ])
                ])
            ], xs=12, lg=6),
        ], className="mb-4"),
        
        # Threat List with Triage Buttons
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("🚨 Active Threats (Unprocessed)"),
                    dbc.CardBody([
                        html.Div(id="threat-list")
                    ])
                ])
            ])
        ])
    ])

def render_raw_data_tab():
    """Raw database viewer with filtering and drill-down capabilities."""
    return html.Div([
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("🗄️ Database Raw Data Viewer"),
                    dbc.CardBody([
                        dbc.Row([
                            dbc.Col([
                                dbc.Label("Filter:"),
                                dbc.RadioItems(
                                    id="raw-data-filter",
                                    options=[
                                        {"label": "All Messages", "value": "all"},
                                        {"label": "Threats Only", "value": "threats"},
                                        {"label": "Safe Only", "value": "safe"},
                                        {"label": "Unprocessed", "value": "unprocessed"}
                                    ],
                                    value="all",
                                    inline=True
                                )
                            ], width=6),
                            dbc.Col([
                                dbc.Label("Limit:"),
                                dbc.Input(id="raw-data-limit", type="number", value=50, min=1, max=1000)
                            ], width=3),
                            dbc.Col([
                                dbc.Button("🔄 Refresh", id="raw-data-refresh", color="primary", className="mt-4")
                            ], width=3)
                        ], className="mb-3"),
                        dbc.Row([
                            dbc.Col([
                                html.H6("📦 Ingestion Files (Raw JSON)", className="mt-2"),
                                dcc.Dropdown(id="raw-file-select", placeholder="Select ingestion file", persistence=True),
                                dbc.Button("🔁 Reload Files", id="raw-file-reload", size="sm", className="mt-2", color="secondary"),
                                html.Div(id="raw-file-meta", className="mt-2", style={"fontSize": "12px", "color": "#888"})
                            ], xs=12, lg=4),
                            dbc.Col([
                                html.H6("🧪 Raw File Preview"),
                                html.Div(id="raw-file-content", style={"height": "300px", "overflowY": "scroll", "padding": "8px", "fontFamily": "monospace", "fontSize": "11px"})
                            ], xs=12, lg=8)
                        ], className="mb-4"),
                        html.H6("📊 Messages (DB Query) - Click row for details"),
                        html.Div(id="raw-data-table", style={"maxHeight": "600px", "overflowY": "scroll"})
                    ])
                ])
            ])
        ]),
        
        # Message Detail Modal
        dbc.Modal([
            dbc.ModalHeader(dbc.ModalTitle("🔍 Message Details")),
            dbc.ModalBody(id="message-detail-modal-body"),
            dbc.ModalFooter(
                dbc.Button("Close", id="close-message-detail", className="ms-auto", n_clicks=0)
            )
        ], id="message-detail-modal", size="xl", scrollable=True)
    ])

def render_scanner_tab():
    """Enhanced email scanner with provider selection, batch ingestion, and REAL-TIME logs."""
    return html.Div([
        dbc.Row([
            # Left Column: Scanner Controls
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("🔍 Email Scanner & Ingestion"),
                    dbc.CardBody([
                        # Provider Selection Section
                        dbc.Row([
                            dbc.Col([
                                html.H5("📧 Live Email Ingestion", className="mb-3"),
                                dbc.Label("Email Provider:"),
                                dbc.Select(
                                    id="scanner-provider",
                                    options=[
                                        {"label": "📬 Yahoo Mail", "value": "yahoo"},
                                        {"label": "📮 Gmail", "value": "gmail"},
                                        {"label": "📭 Outlook", "value": "outlook"}
                                    ],
                                    value="yahoo"
                                )
                            ], xs=12, lg=4),
                            dbc.Col([
                                dbc.Label("Your Email (Receiver):"),
                                dbc.Input(
                                    id="scanner-user-email",
                                    type="email",
                                    placeholder="your-email@example.com",
                                    value="epinaman@yahoo.com"
                                )
                            ], xs=12, lg=4),
                            dbc.Col([
                                dbc.Label("Batch Size:"),
                                dbc.Select(
                                    id="scanner-batch-size",
                                    options=[
                                        {"label": "10 emails", "value": "10"},
                                        {"label": "50 emails", "value": "50"},
                                        {"label": "100 emails", "value": "100"},
                                        {"label": "500 emails", "value": "500"}
                                    ],
                                    value="50"
                                )
                            ], xs=12, lg=4)
                        ], className="mb-3"),
                        
                        dbc.Row([
                            dbc.Col([
                                dbc.Button(
                                    "🚀 Scan & Ingest Emails",
                                    id="scanner-ingest-btn",
                                    color="primary",
                                    size="lg",
                                    className="w-100"
                                )
                            ])
                        ], className="mb-3"),
                        
                        html.Div(id="scanner-ingestion-results"),
                        
                        html.Hr(),
                        
                        # Manual Analysis Section
                        html.H5("🔬 Manual Email Analysis", className="mb-3"),
                        dbc.Row([
                            dbc.Col([
                                dbc.Label("Sender Email:"),
                                dbc.Input(id="scanner-sender", type="email", placeholder="sender@example.com")
                            ], xs=12, lg=6),
                            dbc.Col([
                                dbc.Label("Subject:"),
                                dbc.Input(id="scanner-subject", type="text", placeholder="Email subject")
                            ], xs=12, lg=6)
                        ], className="mb-3"),
                        dbc.Row([
                            dbc.Col([
                                dbc.Label("Email Body/Content:"),
                                dbc.Textarea(
                                    id="scanner-body",
                                    placeholder="Paste email content here...",
                                    style={"height": "200px"}
                                )
                            ])
                        ], className="mb-3"),
                        dbc.Row([
                            dbc.Col([
                                dbc.Button("🚨 Analyze Threat", id="scanner-analyze", color="danger", size="lg", className="w-100")
                            ])
                        ]),
                        html.Hr(),
                        html.Div(id="scanner-results")
                    ])
                ])
            ], xs=12, xl=6),
            
            # Right Column: Real-Time Log Monitor
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader([
                        html.Span("📜 Real-Time Processing Logs", style={"float": "left"}),
                        dbc.Button("🔄 Clear", id="scanner-clear-logs", size="sm", color="secondary", 
                                 style={"float": "right"}, className="ms-2"),
                        dbc.ButtonGroup([
                            dbc.Button("All", id="log-filter-all", size="sm", color="info", className="me-1"),
                            dbc.Button("Errors", id="log-filter-errors", size="sm", color="danger", className="me-1"),
                            dbc.Button("Warnings", id="log-filter-warnings", size="sm", color="warning", className="me-1"),
                            dbc.Button("Success", id="log-filter-success", size="sm", color="success"),
                        ], style={"float": "right"})
                    ], style={"overflow": "hidden"}),
                    dbc.CardBody([
                        html.Div(
                            id="scanner-live-logs",
                            className="log-stream",
                            style={
                                "height": "650px",
                                "overflow-y": "scroll",
                                "padding": "10px",
                                "font-family": "'Courier New', monospace",
                                "font-size": "11px",
                                "border-radius": "6px"
                            },
                            children=[
                                html.Div("⏳ Waiting for ingestion to start...", 
                                       style={"color": "#8b949e", "font-style": "italic"})
                            ]
                        )
                    ])
                ])
            ], xs=12, xl=6)
        ])
    ])

# ============================================================================
# REAL-TIME INTERCEPT (RTI) TABS — Smishing (SMS) & Vishing (Voice)
# These channels are real-time, single-message intercepts (not batch email
# streams). They reuse the unified risk engine (classifier + anomaly) so they
# bootstrap directly off the PhishGuard architecture until dedicated
# Smish/Vish detectors are promoted.
# ============================================================================

# DRY config: everything that differs between the two RTI channels lives here.
RTI_CONFIG = {
    "smish": {
        "icon": "📱",
        "title": "Smishing (SMS) Intercept",
        "channel": "SMS",
        "threat_type": "smishing",
        "sender_label": "Sender Number / Short Code:",
        "sender_ph": "+1 (555) 123-4567 or 'VERIZON'",
        "text_label": "SMS Message Body:",
        "text_ph": "Paste the SMS text here…",
        "samples": [
            ("USPS: your package is held. Confirm address: http://bit.ly/usps-redeliver", "+18885551234"),
            ("Hey, running 5 min late — see you at the coffee shop!", "+15551230987"),
        ],
    },
    "vish": {
        "icon": "📞",
        "title": "Vishing (Voice) Intercept",
        "channel": "VOICE",
        "threat_type": "vishing",
        "sender_label": "Caller ID / Number:",
        "sender_ph": "+1 (555) 987-6543 or 'IRS'",
        "text_label": "Call Transcript (speech-to-text):",
        "text_ph": "Paste the live call transcript here…",
        "samples": [
            ("This is the IRS. A warrant is issued for your arrest. Press 1 to settle your tax debt immediately.", "+18005559999"),
            ("Hi, this is Dr. Lee's office confirming your appointment Thursday at 3pm. No action needed.", "+13105550111"),
        ],
    },
}


def _rti_sample_buttons(kind):
    cfg = RTI_CONFIG[kind]
    return dbc.ButtonGroup([
        dbc.Button(
            f"Load sample {i + 1} ({'malicious' if i == 0 else 'benign'})",
            id={"type": f"{kind}-sample", "index": i},
            size="sm",
            color="outline-secondary" if i else "outline-danger",
            className="me-1",
        )
        for i in range(len(cfg["samples"]))
    ], size="sm")


def render_rti_tab(kind):
    """Render a real-time intercept scanner tab for 'smish' or 'vish' (DRY)."""
    cfg = RTI_CONFIG[kind]
    return html.Div([
        dbc.Row([
            # Left: live intercept scanner
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader(f"{cfg['icon']} {cfg['title']}"),
                    dbc.CardBody([
                        dbc.Alert(
                            f"Real-time {cfg['channel']} intercept — single-message latency path. "
                            "Scored by the unified risk engine (classifier + anomaly).",
                            color="info", className="py-2",
                        ),
                        dbc.Row([
                            dbc.Col([
                                dbc.Label(cfg["sender_label"]),
                                dbc.Input(id=f"{kind}-sender", type="text",
                                          placeholder=cfg["sender_ph"]),
                            ], xs=12, lg=6),
                            dbc.Col([
                                dbc.Label("Received (optional):"),
                                dbc.Input(id=f"{kind}-time", type="text",
                                          placeholder="auto = now"),
                            ], xs=12, lg=6),
                        ], className="mb-3"),
                        dbc.Row([
                            dbc.Col([
                                dbc.Label(cfg["text_label"]),
                                dbc.Textarea(id=f"{kind}-body",
                                             placeholder=cfg["text_ph"],
                                             style={"height": "180px"}),
                            ])
                        ], className="mb-2"),
                        html.Div(_rti_sample_buttons(kind), className="mb-3"),
                        dbc.Button(f"{cfg['icon']} Intercept & Analyze",
                                   id=f"{kind}-analyze", color="danger",
                                   size="lg", className="w-100"),
                        html.Hr(),
                        dcc.Loading(html.Div(id=f"{kind}-results"), type="dot"),
                    ])
                ])
            ], xs=12, xl=7),

            # Right: recent intercepts for this channel
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader(f"🚨 Recent {cfg['channel']} Threats"),
                    dbc.CardBody([
                        html.Div(id=f"{kind}-threat-list",
                                 style={"maxHeight": "560px", "overflowY": "auto"},
                                 children=html.Div(
                                     "No intercepts yet. Analyze a message to populate.",
                                     className="text-muted")),
                    ])
                ])
            ], xs=12, xl=5),
        ])
    ])


def render_smish_tab():
    return render_rti_tab("smish")


def render_vish_tab():
    return render_rti_tab("vish")


# ============================================================================
# KPIs & METRICS TAB — every number is measured, not hardcoded
# ============================================================================
def _kpi_stat_card(title, value, sub, color="info"):
    return dbc.Card(dbc.CardBody([
        html.Div(title, className="card-title"),
        html.H2(value, className=f"text-{color}"),
        html.Small(sub, className="text-muted"),
    ]))


def _kpi_quality_table(quality: dict):
    header = html.Thead(html.Tr([html.Th(c) for c in
                                 ["Channel", "n", "Accuracy", "Precision",
                                  "Recall", "FPR", "F1", "Gate"]]))
    rows = []
    for ch in ("phishing", "smishing", "vishing"):
        m = quality.get(ch, {})
        if not m.get("available"):
            rows.append(html.Tr([html.Td(ch.title()),
                                  html.Td(m.get("reason", "n/a"), colSpan=7,
                                          className="text-muted")]))
            continue
        gate = m.get("gate_pass")
        rows.append(html.Tr([
            html.Td(ch.title()),
            html.Td(m["n"]),
            html.Td(f"{m['accuracy']:.0%}"),
            html.Td(f"{m['precision']:.0%}"),
            html.Td(f"{m['recall']:.0%}"),
            html.Td(f"{m['fpr']:.0%}", className="text-danger" if m["fpr"] > 0.10 else ""),
            html.Td(f"{m['f1']:.2f}"),
            html.Td(dbc.Badge("PASS" if gate else "FAIL",
                              color="success" if gate else "danger")),
        ]))
    return dbc.Table([header, html.Tbody(rows)], bordered=False, hover=True,
                     responsive=True, size="sm")


def _kpi_latency_table(bench: dict):
    header = html.Thead(html.Tr([html.Th(c) for c in
                                 ["Channel", "samples", "avg ms", "p50 ms",
                                  "p95 ms", "max ms"]]))
    rows = []
    for ch in ("phishing", "smishing", "vishing"):
        b = bench.get(ch)
        if not b:
            continue
        rows.append(html.Tr([
            html.Td(ch.title()), html.Td(b["n"]),
            html.Td(f"{b['avg_ms']}"), html.Td(f"{b['p50_ms']}"),
            html.Td(f"{b['p95_ms']}", className="text-warning" if b["p95_ms"] > 50 else ""),
            html.Td(f"{b['max_ms']}"),
        ]))
    return dbc.Table([header, html.Tbody(rows)], bordered=False, hover=True,
                     responsive=True, size="sm")


def _kpi_dist_figure(dist: dict, title: str):
    items = sorted(dist.items(), key=lambda kv: -kv[1]) if dist else []
    fig = go.Figure(go.Bar(x=[k for k, _ in items], y=[v for _, v in items],
                            marker_color="#0a84ff"))
    fig.update_layout(template="plotly_white", title=title, height=260,
                      margin=dict(l=10, r=10, t=40, b=10))
    return fig


def _kpi_body():
    """Build the full KPI view from live, measured sources."""
    ops = kpi.operational_kpis()
    quality = kpi.model_quality()
    bench = kpi.inference_benchmark()
    api = kpi.live_api_metrics()
    versions = kpi.model_versions()

    # --- top stat cards ---
    if ops:
        total, threats = ops["total"], ops["threats"]
        qrate = (ops["action_dist"].get("quarantine", 0) /
                 sum(ops["action_dist"].values())) if ops["action_dist"] else 0.0
        cards = dbc.Row([
            dbc.Col(_kpi_stat_card("Total Analyzed", f"{total:,}",
                                   "messages in DB", "info"), xs=6, xl=3),
            dbc.Col(_kpi_stat_card("Threats", f"{threats:,}",
                                   f"{(threats/total*100 if total else 0):.1f}% of total",
                                   "danger"), xs=6, xl=3),
            dbc.Col(_kpi_stat_card("Quarantine Rate", f"{qrate:.0%}",
                                   "of actioned items", "warning"), xs=6, xl=3),
            dbc.Col(_kpi_stat_card("API Requests",
                                   f"{api['total_requests']:,}" if api else "n/a",
                                   f"{api['in_flight'] if api else 0} in-flight",
                                   "success"), xs=6, xl=3),
        ], className="mb-4")
    else:
        cards = dbc.Alert("Database unavailable — operational KPIs hidden. "
                          "Model quality & latency below are still live.",
                          color="warning")

    # --- charts row ---
    charts = []
    if ops:
        ts = ops["threats_24h"]
        line = go.Figure(go.Scatter(x=[t[0] for t in ts], y=[t[1] for t in ts],
                                    mode="lines+markers", line=dict(color="#d64550")))
        line.update_layout(template="plotly_white", title="Threats / hour (24h)",
                           height=260, margin=dict(l=10, r=10, t=40, b=10))
        ch_dist = {c["channel"]: c["total"] for c in ops["by_channel"]}
        charts = dbc.Row([
            dbc.Col(dcc.Graph(figure=line), xs=12, lg=4),
            dbc.Col(dcc.Graph(figure=_kpi_dist_figure(ch_dist, "Volume by channel")),
                    xs=12, lg=4),
            dbc.Col(dcc.Graph(figure=_kpi_dist_figure(ops["anomaly_dist"],
                                                      "Anomaly levels (threats)")),
                    xs=12, lg=4),
        ], className="mb-4")

    # --- model version chips ---
    chips = []
    for ch, v in versions.items():
        ok = v.get("loaded")
        chips.append(dbc.Badge(
            f"{ch}: {'calibrated' if v.get('calibrated') else 'uncalibrated'} · "
            f"{v.get('features', '?')} struct-feats" if ok else f"{ch}: not loaded",
            color="secondary" if ok else "danger", className="me-2 mb-1"))

    return html.Div([
        cards,
        charts if charts else html.Div(),
        dbc.Row([
            dbc.Col(dbc.Card([
                dbc.CardHeader("🎯 Model Quality — held-out golden sets (CI harness)"),
                dbc.CardBody([
                    _kpi_quality_table(quality),
                    html.Small("Gate: accuracy ≥ 90%, FPR ≤ 10%, pump-fake recall "
                               "= 100% (phishing). These are the honest, "
                               "never-trained-on numbers.", className="text-muted"),
                ])
            ]), xs=12, xl=7),
            dbc.Col(dbc.Card([
                dbc.CardHeader("⚡ Inference Latency — measured now"),
                dbc.CardBody([
                    _kpi_latency_table(bench),
                    html.Small("Per-message verdict time (classifier + anomaly), "
                               "warm model, this host.", className="text-muted"),
                ])
            ]), xs=12, xl=5),
        ], className="mb-3"),
        dbc.Card(dbc.CardBody([html.Strong("Models: "), *chips])),
    ])


def render_kpi_tab():
    return html.Div([
        dbc.Row([
            dbc.Col(html.H4("📈 KPIs & Metrics", className="mb-0"), xs=8),
            dbc.Col(dbc.Button("🔄 Refresh", id="kpi-refresh", color="primary",
                               size="sm", className="float-end"), xs=4),
        ], className="align-items-center mb-3"),
        dcc.Loading(html.Div(id="kpi-body", children=_kpi_body()), type="default"),
    ])


def render_geo_intel_tab():
    """Geographic intelligence and IP tracking."""
    return html.Div([
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("🌍 Geographic Threat Intelligence"),
                    dbc.CardBody([
                        dbc.Row([
                            dbc.Col([
                                html.H5("📍 IP Lookup Tool"),
                                dbc.InputGroup([
                                    dbc.Input(id="geo-ip-input", placeholder="Enter IP address", type="text"),
                                    dbc.Button("🔍 Lookup", id="geo-lookup-btn", color="info")
                                ], className="mb-3"),
                                html.Div(id="geo-lookup-result")
                            ], xs=12, lg=6),
                            dbc.Col([
                                html.H5("🗺️ Threat Origin Statistics"),
                                html.Div(id="geo-stats")
                            ], xs=12, lg=6)
                        ]),
                        html.Hr(),
                        dbc.Row([
                            dbc.Col([
                                html.H5("📊 Top Threat Countries"),
                                html.Div([
                                    dcc.Graph(
                                        id="geo-country-chart",
                                        config={'displayModeBar': True, 'displaylogo': False},
                                        style={'height': '400px'}
                                    )
                                ], style={'minHeight': '400px'})
                            ])
                        ])
                    ])
                ])
            ])
        ])
    ])

def render_security_tab():
    """Security scorecard and configuration."""
    return html.Div([
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("🔒 Security Scorecard"),
                    dbc.CardBody([
                        dbc.Row([
                            dbc.Col([
                                html.H4("Overall Security Score", className="text-center"),
                                html.Div(id="security-score-display", className="text-center my-3"),
                                html.Hr(),
                                html.H5("📊 Metrics", className="mb-3"),
                                html.Div(id="security-metrics")
                            ], xs=12, lg=6),
                            dbc.Col([
                                html.H5("⚙️ Security Configuration", className="mb-3"),
                                dbc.ListGroup([
                                    dbc.ListGroupItem([
                                        html.Strong("ML Detection: "),
                                        dbc.Badge("Enabled", color="success")
                                    ]),
                                    dbc.ListGroupItem([
                                        html.Strong("Geo Intelligence: "),
                                        dbc.Badge("Enabled", color="success")
                                    ]),
                                    dbc.ListGroupItem([
                                        html.Strong("Vector DB: "),
                                        dbc.Badge("pgvector", color="info")
                                    ]),
                                    dbc.ListGroupItem([
                                        html.Strong("Auto-Refresh: "),
                                        dbc.Badge("2s", color="primary")
                                    ]),
                                ]),
                                html.Hr(),
                                html.H5("🛡️ Threat Actions", className="mb-3"),
                                html.Div(id="threat-action-stats")
                            ], xs=12, lg=6)
                        ])
                    ])
                ])
            ])
        ]),
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("📋 Recent Security Events"),
                    dbc.CardBody([
                        html.Div(id="security-events-list", style={"maxHeight": "300px", "overflowY": "scroll"})
                    ])
                ])
            ])
        ], className="mt-4")
    ])

@app.callback(
    Output("tab-content", "children"),
    Input("tabs", "active_tab")
)
def render_tab_content(active_tab):
    """Switch between different dashboard pages."""
    if active_tab == "monitor":
        return render_monitor_tab()
    elif active_tab == "raw-data":
        return render_raw_data_tab()
    elif active_tab == "kpi":
        return render_kpi_tab()
    elif active_tab == "scanner":
        return render_scanner_tab()
    elif active_tab == "smish":
        return render_smish_tab()
    elif active_tab == "vish":
        return render_vish_tab()
    elif active_tab == "geo-intel":
        return render_geo_intel_tab()
    elif active_tab == "security":
        return render_security_tab()
    return render_monitor_tab()

# ============================================================================
# CALLBACKS (Real-time updates)
# ============================================================================

def has_messages_table(conn):
    """Fast guard to avoid query spam when local DB exists but schema is not initialized."""
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT to_regclass('public.messages')")
        return cursor.fetchone()[0] is not None
    except Exception:
        return False

@app.callback(
    [
        Output("total-emails", "children"),
        Output("total-threats", "children"),
        Output("total-blocked", "children"),
        Output("processing-rate", "children")
    ],
    Input("interval-component", "n_intervals")
)
def update_stats(n):
    """Update top-level statistics every 2 seconds."""
    conn = connect_db()
    if not conn:
        blocked_count = len(threat_actions.get_blocked_senders())
        return ("N/A", "N/A", f"{blocked_count}", "N/A")

    if not has_messages_table(conn):
        conn.close()
        blocked_count = len(threat_actions.get_blocked_senders())
        return ("0", "0", f"{blocked_count}", "0.0/s")

    cursor = conn.cursor()
    
    # Query: Total emails
    cursor.execute("SELECT COUNT(*) FROM messages")
    total_emails = cursor.fetchone()[0]
    
    # Query: Total threats
    cursor.execute("SELECT COUNT(*) FROM messages WHERE is_threat = 1")
    total_threats = cursor.fetchone()[0]
    
    # Query: Blocked senders
    blocked_count = len(threat_actions.get_blocked_senders())
    
    # Calculate processing rate (emails in last 5 minutes)
    cursor.execute("""
        SELECT COUNT(*) FROM messages 
        WHERE timestamp > NOW() - INTERVAL '5 minutes'
    """)
    recent_emails = cursor.fetchone()[0]
    rate = recent_emails / 300  # emails per second
    
    conn.close()
    
    return (
        f"{total_emails:,}",
        f"{total_threats:,}",
        f"{blocked_count}",
        f"{rate:.1f}/s"
    )

@app.callback(
    Output("live-logs", "children"),
    Input("interval-component", "n_intervals")
)
def update_live_logs(n):
    """Stream last 50 log entries with geo data."""
    try:
        conn = connect_db()
        if not conn:
            return [
                html.Div(
                    "Database unavailable. Start PostgreSQL to see live ingestion logs.",
                    style={"color": "#f4c26b"}
                )
            ]

        if not has_messages_table(conn):
            conn.close()
            return [
                html.Div(
                    "No messages table yet. Run ingestion/bootstrap to populate live logs.",
                    style={"color": "#8db9ff"}
                )
            ]

        cursor = conn.cursor()
        
        # Get last 50 processed emails with metadata (including geo data)
        cursor.execute("""
            SELECT timestamp, sender, subject, is_threat, confidence, metadata
            FROM messages
            ORDER BY timestamp DESC
            LIMIT 50
        """)
        logs = cursor.fetchall()
        conn.close()
        
        # Format as detailed log lines
        log_lines = []
        for log in reversed(logs):  # Show oldest first
            timestamp, sender, subject, is_threat, confidence, metadata = log
            emoji = "🚨" if is_threat else "✅"
            color = "#ff4444" if is_threat else "#44ff44"
            
            # Extract geo info from metadata (stored as JSONB)
            geo_info = ""
            if metadata and isinstance(metadata, dict):
                geo = metadata.get('geo', {})
                ip_address = metadata.get('ip_address', '')
                
                if geo and isinstance(geo, dict):
                    country = geo.get('country', 'Unknown')
                    city = geo.get('city', '')
                    risk = geo.get('risk_score', 'UNKNOWN')
                    risk_colors = {'HIGH': '#ff0000', 'MEDIUM': '#ffaa00', 'LOW': '#00ff00', 'UNKNOWN': '#888'}
                    
                    location = f"{city}, {country}" if city else country
                    
                    geo_info = html.Span([
                        " 📍 ",
                        html.Span(f"{location}", style={"color": "#88ccff", "font-size": "0.9em"}),
                        " [",
                        html.Span(f"{risk}", style={"color": risk_colors.get(risk, '#888'), "font-weight": "bold"}),
                        "]",
                        html.Span(f" {ip_address[:15]}" if ip_address else "", style={"color": "#666", "font-size": "0.8em"})
                    ])
            
            log_lines.append(
                html.Div([
                    html.Span(
                        f"{timestamp.strftime('%H:%M:%S')} ",
                        style={"color": "#888", "font-size": "0.9em"}
                    ),
                    html.Span(
                        f"{emoji} ",
                        style={"color": color, "font-size": "1.2em"}
                    ),
                    html.Span(
                        f"{sender[:30]}: ",
                        style={"color": "#ccc", "font-weight": "500"}
                    ),
                    html.Span(
                        f"{subject[:40] if subject else 'No subject'}...",
                        style={"color": "#aaa"}
                    ),
                    html.Span(
                        f" ({confidence:.2f})" if is_threat else "",
                        style={"color": color, "font-weight": "bold"}
                    ),
                    geo_info  # Show geo data if available
                ], style={"margin-bottom": "5px", "padding": "3px", "border-left": f"3px solid {color}"})
            )
        
        return log_lines
    except Exception as e:
        logger.error(f"Error updating live logs: {e}")
        return [html.Div(f"Error loading logs: {e}", style={"color": "#ff4444"})]

@app.callback(
    Output("threat-map", "figure"),
    Input("interval-component", "n_intervals")
)
def update_threat_map(n):
    """Generate geographic threat map from stored geo data."""
    try:
        conn = connect_db()
        if not conn:
            fig = go.Figure()
            fig.update_layout(
                title="Database unavailable. Start PostgreSQL to load threat map.",
                template="plotly_dark",
                height=500
            )
            return fig

        if not has_messages_table(conn):
            conn.close()
            fig = go.Figure()
            fig.update_layout(
                title="No messages table yet. Threat map will populate after ingestion.",
                template="plotly_dark",
                height=500
            )
            return fig

        cursor = conn.cursor()
        
        # Get threats from last 24 hours with geo data (stored in metadata)
        cursor.execute("""
            SELECT sender, subject, confidence, metadata
            FROM messages
            WHERE is_threat = 1
              AND timestamp > NOW() - INTERVAL '24 hours'
              AND metadata IS NOT NULL
              AND metadata::text LIKE '%geo%'
            ORDER BY confidence DESC
            LIMIT 200
        """)
        threats = cursor.fetchall()
        conn.close()
        
        # Extract geolocation from metadata
        threat_locations = []
        for sender, subject, confidence, metadata in threats:
            if metadata and isinstance(metadata, dict):
                geo = metadata.get('geo', {})
                if geo and isinstance(geo, dict):
                    lat = geo.get('latitude')
                    lon = geo.get('longitude')
                    
                    if lat and lon:
                        threat_locations.append({
                            'lat': lat,
                            'lon': lon,
                            'city': geo.get('city', 'Unknown'),
                            'country': geo.get('country', 'Unknown'),
                            'risk': geo.get('risk_score', 'UNKNOWN'),
                            'confidence': confidence,
                            'sender': sender[:30],
                            'subject': subject[:40] if subject else 'No subject'
                        })
        
        if not threat_locations:
            # Empty map
            fig = go.Figure()
            fig.update_layout(
                title="No threats with geolocation in last 24 hours",
                template="plotly_dark",
                height=500
            )
            return fig
        
        # Create scatter map
        df = pd.DataFrame(threat_locations)
        
        # Add size based on confidence
        df['size'] = df['confidence'] * 20
        
        fig = px.scatter_geo(
            df,
            lat='lat',
            lon='lon',
            hover_name='city',
            hover_data={'country': True, 'risk': True, 'sender': True, 'subject': True, 'confidence': ':.2f', 'size': False, 'lat': False, 'lon': False},
            size='size',
            color='risk',
            color_discrete_map={'HIGH': '#ff0000', 'MEDIUM': '#ffaa00', 'LOW': '#ffff00', 'UNKNOWN': '#888888'},
            title=f"🌍 Global Threat Map (Last 24h) - {len(df)} threats detected"
        )
        
        fig.update_layout(
            template="plotly_dark",
            height=600,
            geo=dict(
                showland=True,
                landcolor='#1a1a1a',
                showcountries=True,
                countrycolor='#333',
                projection_type='natural earth'
            )
        )
        return fig
    except Exception as e:
        logger.error(f"Error updating threat map: {e}")
        fig = go.Figure()
        fig.update_layout(
            title=f"Error loading threat map: {str(e)}",
            template="plotly_dark"
        )
        return fig

@app.callback(
    Output("threat-list", "children"),
    [Input("interval-component", "n_intervals"),
     Input("selected-threat", "data")]
)
def update_threat_list(n, selected_threat):
    """
    Display unprocessed threats with triage buttons.
    
    SECURITY: Shows only threats (is_threat=1) that haven't been processed yet.
    Displays sender, subject, confidence score, geolocation, and IPs extracted from metadata.
    
    ERROR HANDLING: Wraps all DB operations with try-except and proper connection cleanup.
    """
    conn = None
    try:
        # Get fresh database connection (not pooled to avoid schema cache issues)
        conn = connect_db()
        if not conn:
            logger.error("Failed to establish database connection")
            return html.Div("⚠️ Database connection failed", className="text-warning")

        if not has_messages_table(conn):
            conn.close()
            return html.Div("ℹ️ No threat data yet. Run ingestion to create and populate messages.", className="text-info")
        
        cursor = conn.cursor()
        
        # Query unprocessed threats with all needed metadata
        # IMPORTANT: Check processed column explicitly (COALESCE handles NULL values from old data)
        query = """
            SELECT id, sender, subject, confidence, metadata, timestamp
            FROM messages
            WHERE is_threat = 1 
              AND COALESCE(processed, false) = false
            ORDER BY timestamp DESC
            LIMIT 20
        """
        logger.debug(f"Executing threat query: {query}")
        cursor.execute(query)
        threats = cursor.fetchall()
        
        if not threats:
            return html.Div("✅ No pending threats to triage", className="text-success")
        
        # Create threat cards with enhanced metadata display
        threat_cards = []
        for threat_id, sender, subject, confidence, metadata, timestamp in threats:
            # Extract geolocation and IP data from metadata
            geo_text = "🔍 No Geo Data"
            ip_addresses = []
            
            if metadata and isinstance(metadata, dict):
                # Parse geolocation info
                geo = metadata.get('geo', {})
                if geo and isinstance(geo, dict):
                    country = geo.get('country', 'Unknown')
                    city = geo.get('city', '')
                    region = geo.get('region', '')
                    risk = geo.get('risk_score', 'UNKNOWN')
                    risk_emoji = {'LOW': '🟢', 'MEDIUM': '🟡', 'HIGH': '🔴', 'UNKNOWN': '⚪'}
                    
                    # Build detailed location string
                    location_parts = [p for p in [city, region, country] if p]
                    location = ", ".join(location_parts) if location_parts else "Unknown"
                    geo_text = f"{location} {risk_emoji.get(risk, '⚪')} {risk}"
                
                # Extract IP addresses from metadata
                # IPs can be stored in multiple places depending on email provider
                ip_addresses = []
                
                # Primary: Check top-level ip_address field (Yahoo provider format)
                if 'ip_address' in metadata:
                    ip = metadata['ip_address']
                    if ip:
                        ip_addresses.append(ip)
                
                # Secondary: Check ips array (Gmail provider format)
                if 'ips' in metadata:
                    ips_list = metadata['ips']
                    if isinstance(ips_list, list):
                        ip_addresses.extend(ips_list)
                    elif ips_list:  # Single IP as string
                        ip_addresses.append(ips_list)
                
                # Tertiary: Extract from URL analysis (contains IPs from embedded URLs)
                url_analysis = metadata.get('url_analysis', [])
                if isinstance(url_analysis, list):
                    for url_data in url_analysis:
                        if isinstance(url_data, dict) and 'ip' in url_data:
                            url_ip = url_data['ip']
                            if url_ip and url_ip not in ip_addresses:
                                ip_addresses.append(url_ip)
                
                # Fallback: Check headers for IP extraction
                if not ip_addresses:
                    headers = metadata.get('headers', {})
                    if isinstance(headers, dict):
                        received_ips = headers.get('Received-IPs', [])
                        if received_ips:
                            ip_addresses = received_ips if isinstance(received_ips, list) else [received_ips]
            
            # Format IP display (show first 3 IPs to avoid clutter)
            ip_display = "No IPs extracted"
            if ip_addresses:
                displayed_ips = ip_addresses[:3]
                ip_display = ", ".join(displayed_ips)
                if len(ip_addresses) > 3:
                    ip_display += f" (+{len(ip_addresses) - 3} more)"
            
            # Handle confidence scoring with color coding
            # 0.00 = Not yet scored, 0.5-0.8 = Medium threat, >0.8 = High threat
            if confidence == 0.0:
                confidence_text = "⏳ Pending ML Analysis"
                confidence_color = "text-muted"
            else:
                confidence_text = f"{confidence:.1%}"
                if confidence > 0.8:
                    confidence_color = "text-danger"
                elif confidence > 0.5:
                    confidence_color = "text-warning"
                else:
                    confidence_color = "text-info"
            
            # Create enhanced threat card with IP and geo data
            card = dbc.Card([
                dbc.CardBody([
                    dbc.Row([
                        dbc.Col([
                            html.H5(f"🚨 {subject[:60] if subject else 'No Subject'}...", className="text-danger"),
                            html.P([
                                html.Strong("From: "),
                                html.Span(sender or "Unknown", className="text-info"),
                                html.Br(),
                                html.Strong("📍 Location: "),
                                html.Span(geo_text),
                                html.Br(),
                                html.Strong("🌐 IPs: "),
                                html.Span(ip_display, className="text-warning" if ip_addresses else "text-muted"),
                                html.Br(),
                                html.Strong("🎯 Confidence: "),
                                html.Span(confidence_text, className=confidence_color),
                                html.Br(),
                                html.Small(f"Detected: {timestamp.strftime('%Y-%m-%d %H:%M') if timestamp else 'N/A'}", className="text-muted")
                            ])
                        ], width=8),
                        
                        dbc.Col([
                            dbc.ButtonGroup([
                                dbc.Button(
                                    "🚫 Block & Report",
                                    id={"type": "block-report-btn", "index": threat_id},
                                    color="danger",
                                    size="sm",
                                    className="mb-1"
                                ),
                                dbc.Button(
                                    "🟡 Warn",
                                    id={"type": "warn-btn", "index": threat_id},
                                    color="warning",
                                    size="sm",
                                    className="mb-1"
                                ),
                                dbc.Button(
                                    "✅ Mark Safe",
                                    id={"type": "mark-safe-btn", "index": threat_id},
                                    color="success",
                                    size="sm"
                                )
                            ], vertical=True, className="w-100")
                        ], width=4)
                    ])
                ])
            ], className="mb-3", style={"border-left": f"4px solid {'#ff4444' if confidence > 0.8 else '#ffaa44'}"})
            
            threat_cards.append(card)
        
        logger.info(f"📊 Displaying {len(threat_cards)} unprocessed threats")
        return threat_cards
        
    except Exception as e:
        logger.error(f"❌ Error in update_threat_list: {e}", exc_info=True)
        return html.Div([
            html.H5("⚠️ Error Loading Threats", className="text-warning"),
            html.P(f"Technical details: {str(e)}", className="text-muted"),
            html.P("Check logs for full traceback", className="text-muted")
        ], className="alert alert-warning")
    finally:
        # CRITICAL: Always close connection to prevent leaks
        if conn:
            try:
                conn.close()
                logger.debug("Database connection closed successfully")
            except Exception as e:
                logger.error(f"Error closing connection: {e}")

# ============================================================================
# TRIAGE ACTION CALLBACKS
# ============================================================================

@app.callback(
    [
        Output({"type": "block-report-btn", "index": MATCH}, "children"),
        Output({"type": "block-report-btn", "index": MATCH}, "color"),
        Output({"type": "block-report-btn", "index": MATCH}, "disabled")
    ],
    Input({"type": "block-report-btn", "index": MATCH}, "n_clicks"),
    State({"type": "block-report-btn", "index": MATCH}, "id"),
    prevent_initial_call=True
)
def handle_block_and_report_action(n_clicks, btn_id):
    """
    Unified handler: blocks sender AND generates threat report AND trains ML model.
    
    USER FEEDBACK LOOP:
    1. User clicks "Block & Report" on threat
    2. Add sender to blocked list
    3. Generate forensic report
    4. **NEW**: Train ML model that this IS phishing (label=1)
    5. Mark as processed
    
    CONTINUOUS LEARNING:
    - Model learns from user's decision (partial_fit with label=1)
    - Future emails with similar patterns get auto-blocked
    - Reduces false negatives over time
    """
    if n_clicks is None:
        raise dash.exceptions.PreventUpdate
    
    threat_id = btn_id["index"]
    
    # Get threat data from database
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM messages WHERE id = %s", (threat_id,))
    threat = cursor.fetchone()
    
    if threat:
        # Convert tuple to dict for threat_actions
        columns = [desc[0] for desc in cursor.description]
        threat_dict = dict(zip(columns, threat))
        
        # 1. Block sender (adds to blocked list)
        threat_actions.block_sender(
            threat_dict,
            "🚫 Manual BLOCK+REPORT via dashboard"
        )
        
        # 2. Generate threat report (forensic analysis)
        report = threat_actions.report_threat(
            threat_dict,
            report_to="internal"
        )
        
        # 3. **NEW**: Train ML model with user feedback (this IS phishing)
        try:
            from PhishGuard.phish_mlm.phishing_detector import detector
            email_data = {
                'subject': threat_dict.get('subject', ''),
                'body': threat_dict.get('preprocessed_text', ''),
                'from': threat_dict.get('sender', '')
            }
            detector.learn_from_feedback(email_data, is_phishing=True)
            logger.info(f"🧠 ML model trained: {threat_dict.get('sender', 'unknown')} marked as PHISHING")
        except Exception as e:
            logger.error(f"ML training failed: {e}")
        
        logger.info(f"✅ Threat {threat_id} blocked & reported. Report ID: {report.get('report_id', 'N/A')}")
        
        # 4. Mark as processed
        cursor.execute("UPDATE messages SET processed = true WHERE id = %s", (threat_id,))
        conn.commit()
    
    conn.close()
    
    # Update button to show success
    return "✅ Blocked & Reported!", "success", True


@app.callback(
    [
        Output({"type": "warn-btn", "index": MATCH}, "children"),
        Output({"type": "warn-btn", "index": MATCH}, "color"),
        Output({"type": "warn-btn", "index": MATCH}, "disabled")
    ],
    Input({"type": "warn-btn", "index": MATCH}, "n_clicks"),
    State({"type": "warn-btn", "index": MATCH}, "id"),
    prevent_initial_call=True
)
def handle_warn_action(n_clicks, btn_id):
    """Handle warn button with visual feedback."""
    if n_clicks is None:
        raise dash.exceptions.PreventUpdate
    
    threat_id = btn_id["index"]
    
    # Get threat data from database
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM messages WHERE id = %s", (threat_id,))
    threat = cursor.fetchone()
    
    if threat:
        columns = [desc[0] for desc in cursor.description]
        threat_dict = dict(zip(columns, threat))
        
        # Warn sender
        threat_actions.warn_sender(
            threat_dict,
            "⚠️ Manual WARN via dashboard"
        )
        
        # Mark as processed
        cursor.execute("UPDATE messages SET processed = true WHERE id = %s", (threat_id,))
        conn.commit()
    
    conn.close()
    
    return "✅ Warned!", "warning", True


@app.callback(
    [
        Output({"type": "mark-safe-btn", "index": MATCH}, "children"),
        Output({"type": "mark-safe-btn", "index": MATCH}, "color"),
        Output({"type": "mark-safe-btn", "index": MATCH}, "disabled")
    ],
    Input({"type": "mark-safe-btn", "index": MATCH}, "n_clicks"),
    State({"type": "mark-safe-btn", "index": MATCH}, "id"),
    prevent_initial_call=True
)
def handle_mark_safe_action(n_clicks, btn_id):
    """
    Mark as Safe: User feedback that this is NOT a threat.
    
    USER FEEDBACK LOOP:
    1. User clicks "Mark Safe" on false positive
    2. Update database: is_threat=0, label=0
    3. **NEW**: Add sender to whitelist (future emails skip ML)
    4. **NEW**: Train ML model that this is SAFE (label=0)
    5. Mark as processed
    
    CONTINUOUS LEARNING:
    - Model learns this sender/pattern is legitimate
    - Future similar emails get classified as safe
    - Reduces false positives over time
    - Whitelist prevents wasted ML inference
    """
    if n_clicks is None:
        raise dash.exceptions.PreventUpdate
    
    threat_id = btn_id["index"]
    
    # Get threat data from database
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM messages WHERE id = %s", (threat_id,))
    threat = cursor.fetchone()
    
    if threat:
        columns = [desc[0] for desc in cursor.description]
        threat_dict = dict(zip(columns, threat))
        sender = threat_dict.get('sender', '')
        
        # 1. Update database: Mark as safe (not a threat)
        cursor.execute("""
            UPDATE messages 
            SET is_threat = 0, label = 0, processed = true, confidence = 0.0
            WHERE id = %s
        """, (threat_id,))
        conn.commit()
        
        # 2. Add sender to whitelist
        try:
            from utils.safe_sender_manager import SafeSenderManager
            safe_mgr = SafeSenderManager(conn)
            
            # Extract domain for pattern matching
            domain = sender.split('@')[-1] if '@' in sender else sender
            pattern = f"%@{domain}"
            
            safe_mgr.add_safe_sender(
                sender_email=pattern,
                reason=f"User marked as safe via dashboard (was false positive)",
                auto_learned=True
            )
            logger.info(f"✅ Added to whitelist: {pattern}")
        except Exception as e:
            logger.error(f"Failed to add to whitelist: {e}")
        
        # 3. Train ML model with user feedback (this is SAFE)
        try:
            from PhishGuard.phish_mlm.phishing_detector import detector
            email_data = {
                'subject': threat_dict.get('subject', ''),
                'body': threat_dict.get('preprocessed_text', ''),
                'from': sender
            }
            detector.learn_from_feedback(email_data, is_phishing=False)
            logger.info(f"🧠 ML model trained: {sender} marked as SAFE")
        except Exception as e:
            logger.error(f"ML training failed: {e}")
        
        logger.info(f"✅ Threat {threat_id} marked as SAFE by user")
    
    conn.close()
    
    return "✅ Marked Safe!", "success", True


# ============================================================================
# RAW DATA VIEWER CALLBACKS
# ============================================================================

# ============================================================================
# NEW FEATURE CALLBACKS
# ============================================================================

@app.callback(
    Output("raw-data-table", "children"),
    [Input("raw-data-refresh", "n_clicks"),
     Input("interval-component", "n_intervals")],
    [State("raw-data-filter", "value"),
     State("raw-data-limit", "value")]
)
def update_raw_data_table(n_clicks, n_intervals, filter_val, limit):
    """
    Display raw database records with clickable rows for drill-down.
    
    FEATURES:
    - Filterable by threat status and processing status
    - Clickable rows open detailed modal view
    - Shows key fields: ID, sender, subject, confidence, status
    - Auto-refreshes every 2 seconds
    
    SECURITY: Only displays sanitized data, full content requires explicit drill-down
    """
    conn = None
    try:
        conn = connect_db()
        if not conn:
            return html.Div("⚠️ Database connection failed", className="text-warning")
        
        cursor = conn.cursor()
        
        # Build query based on filter with COALESCE for processed column
        if filter_val == "threats":
            query = """SELECT id, sender, subject, confidence, is_threat, COALESCE(processed, false) as processed, timestamp 
                       FROM messages WHERE is_threat = 1 ORDER BY timestamp DESC LIMIT %s"""
        elif filter_val == "safe":
            query = """SELECT id, sender, subject, confidence, is_threat, COALESCE(processed, false) as processed, timestamp 
                       FROM messages WHERE is_threat = 0 ORDER BY timestamp DESC LIMIT %s"""
        elif filter_val == "unprocessed":
            query = """SELECT id, sender, subject, confidence, is_threat, COALESCE(processed, false) as processed, timestamp 
                       FROM messages WHERE COALESCE(processed, false) = false ORDER BY timestamp DESC LIMIT %s"""
        else:
            query = """SELECT id, sender, subject, confidence, is_threat, COALESCE(processed, false) as processed, timestamp 
                       FROM messages ORDER BY timestamp DESC LIMIT %s"""
        
        cursor.execute(query, (limit or 50,))
        rows = cursor.fetchall()
        
        if not rows:
            return html.Div("No data found", className="text-muted")
        
        # Create enhanced table with clickable rows
        table_header = [
            html.Thead(html.Tr([
                html.Th("ID"),
                html.Th("Sender"),
                html.Th("Subject"),
                html.Th("Confidence"),
                html.Th("Threat?"),
                html.Th("Processed?"),
                html.Th("Timestamp")
            ]))
        ]
        
        table_rows = []
        for row in rows:
            tid, sender, subject, conf, is_threat, processed, ts = row
            
            # Style row based on threat status
            row_class = "table-danger" if is_threat else "table-success"
            row_style = {"cursor": "pointer"}
            
            table_rows.append(html.Tr([
                html.Td(tid),
                html.Td(sender[:40] + "..." if sender and len(sender) > 40 else sender or ""),
                html.Td(subject[:50] + "..." if subject and len(subject) > 50 else subject or ""),
                html.Td(f"{conf:.2f}" if conf else "0.00"),
                html.Td("🚨 Yes" if is_threat else "✅ No"),
                html.Td("✅" if processed else "⏳"),
                html.Td(ts.strftime("%Y-%m-%d %H:%M") if ts else "")
            ], id={"type": "message-row", "index": tid}, className=row_class, style=row_style))
        
        table_body = [html.Tbody(table_rows)]
        
        logger.debug(f"Raw data table: Showing {len(rows)} records (filter={filter_val})")
        return dbc.Table(table_header + table_body, striped=True, bordered=True, hover=True, size="sm", className="table-dark")
    
    except Exception as e:
        logger.error(f"❌ Error updating raw data table: {e}", exc_info=True)
        return html.Div(f"⚠️ Error: {str(e)}", className="text-warning")
    finally:
        if conn:
            conn.close()

# =========================================================================
# RAW INGESTION FILE VIEWER CALLBACKS
# =========================================================================

@app.callback(
    [Output("raw-file-select", "options"),
     Output("raw-file-select", "value"),
     Output("raw-file-content", "children"),
     Output("raw-file-meta", "children")],
    [Input("raw-file-reload", "n_clicks"),
     Input("raw-file-select", "value"),
     Input("interval-component", "n_intervals")],
    prevent_initial_call=False
)
def update_raw_file_view(reload_clicks, selected_file, n_intervals):
    """Populate and display raw ingestion JSON files."""
    ingestion_dir = Path('data/ingestion')
    files = sorted(ingestion_dir.glob('*.json'))[-25:]
    options = [{"label": f.name, "value": str(f)} for f in files]
    if not selected_file and files:
        selected_file = str(files[-1])
    content_div = html.Div("No file selected", style={"color": "#888"})
    meta_div = ""
    if selected_file and Path(selected_file).exists():
        try:
            raw_text = Path(selected_file).read_text()[:500000]  # safety cap
            raw = json.loads(raw_text)
            preview = raw[:50] if isinstance(raw, list) else raw
            pretty = json.dumps(preview, indent=2, ensure_ascii=False)
            content_div = html.Pre(pretty, style={"whiteSpace": "pre-wrap", "wordBreak": "break-word"})
            meta_div = f"Showing {'list[' + str(len(preview)) + ']' if isinstance(preview, list) else 'object'} | File size: {Path(selected_file).stat().st_size} bytes"
        except Exception as e:
            content_div = html.Div(f"Failed to read file: {e}", style={"color": "#f85149"})
    return options, selected_file, content_div, meta_div


# ============================================================================
# MESSAGE DETAIL MODAL CALLBACKS (Drill-Down Feature)
# ============================================================================

@app.callback(
    [Output("message-detail-modal", "is_open"),
     Output("message-detail-modal-body", "children")],
    [Input({"type": "message-row", "index": ALL}, "n_clicks"),
     Input("close-message-detail", "n_clicks")],
    [State("message-detail-modal", "is_open"),
     State({"type": "message-row", "index": ALL}, "id")],
    prevent_initial_call=True
)
def toggle_message_detail_modal(row_clicks, close_clicks, is_open, row_ids):
    """
    Handle message row clicks to open detailed drill-down view.
    
    FEATURES:
    - Decrypts and displays full email content
    - Shows complete metadata (geo, IPs, headers, URLs)
    - Displays vector similarity analysis
    - Shows related messages from same sender
    - Provides threat intelligence context
    
    SECURITY: Decrypts content only when explicitly requested, validates user intent
    """
    from Autobot.VectorDB.NullPoint_Vector import decrypt_data
    
    trigger = ctx.triggered_id
    
    # Close modal if close button clicked
    if trigger == "close-message-detail":
        return False, ""
    
    # Prevent update if no valid trigger
    if not trigger or not isinstance(trigger, dict) or trigger.get("type") != "message-row":
        raise dash.exceptions.PreventUpdate
    
    # Check if any row was actually clicked (not just initial render)
    if not row_clicks or not any(row_clicks):
        raise dash.exceptions.PreventUpdate
    
    message_id = trigger.get("index")
    if not message_id:
        raise dash.exceptions.PreventUpdate
    
    logger.info(f"🔍 Opening drill-down view for message ID: {message_id}")
    
    conn = None
    try:
        conn = connect_db()
        cursor = conn.cursor()
        
        # Fetch complete message data
        cursor.execute("""
            SELECT id, message_type, sender, recipient, timestamp, subject, 
                   raw_content, preprocessed_text, is_threat, confidence, 
                   metadata, label, created_at, COALESCE(processed, false) as processed
            FROM messages
            WHERE id = %s
        """, (message_id,))
        
        row = cursor.fetchone()
        
        if not row:
            return True, html.Div("⚠️ Message not found", className="text-warning")
        
        # Unpack row data
        (msg_id, msg_type, sender, recipient, timestamp, enc_subject, enc_raw, 
         enc_preprocessed, is_threat, confidence, metadata, label, created_at, processed) = row
        
        # SECURITY: Decrypt sensitive fields with proper type handling
        def safe_decrypt(data):
            """Safely decrypt data handling both bytes and string types."""
            if not data:
                return ""
            try:
                # If it's already a string (not encrypted), return it
                if isinstance(data, str):
                    # Try to decrypt assuming it's base64 encoded
                    try:
                        return decrypt_data(data.encode('utf-8'))
                    except:
                        # If decrypt fails, it might be plain text
                        return data
                # If it's bytes, decrypt directly
                return decrypt_data(data)
            except Exception as e:
                logger.warning(f"Decrypt failed: {e}")
            return "[Could not decrypt - may be unencrypted]"
        
        subject = safe_decrypt(enc_subject) or "No Subject"
        raw_content = safe_decrypt(enc_raw) or "[No Content]"
        preprocessed = safe_decrypt(enc_preprocessed) or "[No Preprocessed Text]"
        
        # Parse metadata
        geo_info = "No geolocation data"
        ip_list = []
        url_list = []
        headers_info = "No headers"
        
        if metadata and isinstance(metadata, dict):
            # Geolocation
            geo = metadata.get('geo', {})
            if geo:
                geo_info = f"{geo.get('city', '')}, {geo.get('region', '')}, {geo.get('country', 'Unknown')} (Risk: {geo.get('risk_score', 'N/A')})"
            
            # IPs
            ip_list = metadata.get('ips', [])
            if not ip_list:
                headers = metadata.get('headers', {})
                if isinstance(headers, dict):
                    ip_list = headers.get('Received-IPs', [])
            
            # URLs
            url_list = metadata.get('urls', [])
            
            # Headers
            headers = metadata.get('headers', {})
            if headers and isinstance(headers, dict):
                headers_info = json.dumps(headers, indent=2)[:1000]
        
        # Find similar/related messages
        cursor.execute("""
            SELECT id, sender, subject, confidence, timestamp
            FROM messages
            WHERE sender = %s AND id != %s
            ORDER BY timestamp DESC
            LIMIT 5
        """, (sender, msg_id))
        related_messages = cursor.fetchall()
        
        # Build detailed view
        modal_content = html.Div([
            # Message Header
            dbc.Alert([
                html.H4(f"{'🚨 THREAT' if is_threat else '✅ SAFE'} - ID: {msg_id}"),
                html.P(f"Confidence: {confidence:.1%} | Processed: {'Yes' if processed else 'No'}")
            ], color="danger" if is_threat else "success"),
            
            # Basic Info Section
            dbc.Card([
                dbc.CardHeader("📧 Basic Information"),
                dbc.CardBody([
                    html.P([
                        html.Strong("Type: "), msg_type, html.Br(),
                        html.Strong("From: "), html.Span(sender, className="text-info"), html.Br(),
                        html.Strong("To: "), recipient or "N/A", html.Br(),
                        html.Strong("Subject: "), subject, html.Br(),
                        html.Strong("Timestamp: "), timestamp.strftime("%Y-%m-%d %H:%M:%S") if timestamp else "N/A", html.Br(),
                        html.Strong("Created: "), created_at.strftime("%Y-%m-%d %H:%M:%S") if created_at else "N/A"
                    ])
                ])
            ], className="mb-3"),
            
            # Content Section
            dbc.Card([
                dbc.CardHeader("📄 Content"),
                dbc.CardBody([
                    html.H6("Raw Content:"),
                    html.Pre(raw_content[:2000] + ("..." if len(raw_content) > 2000 else ""), 
                            style={"whiteSpace": "pre-wrap", "maxHeight": "300px", "overflow": "auto"}),
                    html.Hr(),
                    html.H6("Preprocessed (ML Input):"),
                    html.Pre(preprocessed[:1000], style={"whiteSpace": "pre-wrap"})
                ])
            ], className="mb-3"),
            
            # Threat Intelligence Section
            dbc.Card([
                dbc.CardHeader("🌐 Threat Intelligence"),
                dbc.CardBody([
                    html.H6("📍 Geolocation:"),
                    html.P(geo_info),
                    html.Hr(),
                    html.H6("🌐 IP Addresses:"),
                    html.Ul([html.Li(ip) for ip in ip_list]) if ip_list else html.P("None extracted"),
                    html.Hr(),
                    html.H6("🔗 URLs:"),
                    html.Ul([html.Li(html.Code(url)) for url in url_list[:10]]) if url_list else html.P("None found"),
                    html.Hr(),
                    html.H6("📋 Headers (truncated):"),
                    html.Pre(headers_info, style={"fontSize": "10px", "maxHeight": "200px", "overflow": "auto"})
                ])
            ], className="mb-3"),
            
            # Related Messages Section
            dbc.Card([
                dbc.CardHeader("🔗 Related Messages from Same Sender"),
                dbc.CardBody([
                    html.Div([
                        dbc.ListGroup([
                            dbc.ListGroupItem([
                                html.Strong(f"ID: {rid}"),
                                html.Br(),
                                html.Small(f"{safe_decrypt(rsub) or 'No Subject'}"),
                                html.Br(),
                                html.Small(f"Confidence: {rconf:.1%} | {rts.strftime('%Y-%m-%d %H:%M')}")
                            ])
                            for rid, rsender, rsub, rconf, rts in related_messages
                        ])
                    ]) if related_messages else html.P("No related messages found")
                ])
            ])
        ])
        
        return True, modal_content
        
    except Exception as e:
        logger.error(f"❌ Error loading message details: {e}", exc_info=True)
        return True, html.Div([
            html.H5("⚠️ Error Loading Details"),
            html.P(f"Technical error: {str(e)}"),
            html.Small("Check server logs for details")
        ], className="text-warning")
    finally:
        if conn:
            conn.close()
    
    return False, ""


# ============================================================================
# EMAIL SCANNER CALLBACKS
# ============================================================================

@app.callback(
    Output("scanner-ingestion-results", "children"),
    Input("scanner-ingest-btn", "n_clicks"),
    [State("scanner-provider", "value"),
     State("scanner-user-email", "value"),
     State("scanner-batch-size", "value")],
    prevent_initial_call=True
)
def handle_email_ingestion(n_clicks, provider, user_email, batch_size):
    """Handle live email ingestion with REAL-TIME log streaming."""
    if not n_clicks:
        raise dash.exceptions.PreventUpdate
    
    try:
        from PhishGuard.providers.email_fetcher.registry import EmailFetcherRegistry
        from Autobot.email_ingestion import EmailIngestionEngine, IngestionConfig
        
        # Clear previous logs
        with RT_LOGS_LOCK:
            RT_LOGS.clear()
        
        # Add initial log
        add_realtime_log('info', f'🚀 Starting ingestion from {provider.upper()}')
        add_realtime_log('info', f'📊 Batch size: {batch_size} emails')
        
        # Validate user email
        if not user_email or '@' not in user_email:
            add_realtime_log('error', '❌ Invalid email address')
            return dbc.Alert("⚠️ Please enter a valid email address", color="warning")
        
        add_realtime_log('info', f'📧 Receiver: {user_email}')
        add_realtime_log('info', f'🔌 Connecting to {provider.upper()}...')
        
        # Configure ingestion
        config = IngestionConfig(
            batch_size=int(batch_size),
            max_emails_per_provider=int(batch_size),
            parallel_providers=False,
            enable_intelligence=True,
            enable_ml_analysis=True
        )
        
        # Run ingestion in background thread (non-blocking for real-time updates)
        def _run_ingestion():
            try:
                engine = EmailIngestionEngine(config)
                stats = engine.ingest_all_providers(providers=[provider])
                add_realtime_log('success', f'✅ Completed: {stats.total_fetched} emails (threats={stats.total_threats})')
                add_realtime_log('info', f'⏱️  Processing time: {stats.processing_time:.2f}s')
            except Exception as ie:
                add_realtime_log('error', f'❌ Ingestion thread error: {ie}')
        threading.Thread(target=_run_ingestion, daemon=True).start()

        return dbc.Alert([
            html.H4("🚀 Ingestion Started", className="alert-heading"),
            html.Hr(),
            html.P([
                html.Strong("Provider: "), f"{provider.upper()}", html.Br(),
                html.Strong("Batch Size: "), f"{batch_size}", html.Br(),
                html.Strong("Mode: "), "Threaded Streaming", html.Br(),
                html.Strong("Status: "), "Running... (watch right panel)", html.Br(),
            ]),
            html.Hr(),
            html.P("📡 Live logs updating every 2s. You can navigate tabs.", className="mb-0")
        ], color="info")
        
    except Exception as e:
        logger.error(f"Ingestion error: {e}")
        add_realtime_log('error', f'❌ ERROR: {str(e)}')
        return dbc.Alert([
            html.H4("❌ Ingestion Failed", className="alert-heading"),
            html.Hr(),
            html.P(f"Error: {str(e)}")
        ], color="danger")


@app.callback(
    Output("scanner-results", "children"),
    Input("scanner-analyze", "n_clicks"),
    [State("scanner-sender", "value"),
     State("scanner-subject", "value"),
     State("scanner-body", "value")],
    prevent_initial_call=True
)
def analyze_email_scan(n_clicks, sender, subject, body):
    """
    Enhanced manual email scanner with full threat intelligence.
    
    FEATURES:
    - ML phishing prediction with confidence score
    - IP extraction from email headers and body
    - Geolocation lookup for extracted IPs
    - URL extraction and risk analysis
    - Vector similarity search against known threats
    - Detailed threat intelligence breakdown
    
    SECURITY: Sanitizes all inputs before analysis
    """
    if not body or not sender:
        return dbc.Alert("⚠️ Please provide at least sender and body content", color="warning")
    
    logger.info(f"📧 Manual email scan requested - Sender: {sender}, Subject: {subject or 'N/A'}")
    
    try:
        # Import dependencies
        from utils.security.input_validator import input_validator
        from utils.url_utils import extract_urls
        from common.streaming.channel_pipeline import process_one
        import re

        # SECURITY: Validate and sanitize inputs
        is_valid, validation_msg = input_validator.validate_email_data({
            'sender': sender,
            'subject': subject or '',
            'body': body
        })
        
        if not is_valid:
            logger.warning(f"⚠️ Invalid email data: {validation_msg}")
            return dbc.Alert(f"⚠️ Validation failed: {validation_msg}", color="warning")

        # 1. UNIFIED VERDICT (cached singleton classifier + email anomaly manifold).
        # NOTE: predict() expects a structured record, not a flat string — passing
        # a string silently fails to SAFE. process_one builds the correct record
        # and reuses the warm model (no per-click reload).
        verdict = process_one("phishing", {"subject": subject or "", "body": body,
                                            "from": sender})
        is_threat = verdict.is_threat
        confidence = verdict.classifier_conf
        logger.info(f"🎯 Verdict: {verdict.action.value} (conf {confidence:.2%}, "
                    f"risk {verdict.risk_score:.2%}, anomaly {verdict.anomaly_level})")
        
        # 2. IP EXTRACTION (from body and headers)
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        extracted_ips = list(set(ip_pattern.findall(body)))
        logger.info(f"🌐 Extracted {len(extracted_ips)} unique IP(s)")
        
        # 3. GEOLOCATION LOOKUP for each IP
        ip_geo_data = []
        for ip in extracted_ips[:5]:  # Limit to 5 IPs to avoid rate limiting
            try:
                geo = geo_service.get_location(ip)
                if geo and geo.get('country'):
                    ip_geo_data.append({
                        'ip': ip,
                        'location': f"{geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}",
                        'risk': geo.get('risk_score', 'UNKNOWN'),
                        'org': geo.get('org', 'N/A')
                    })
            except Exception as e:
                logger.warning(f"Failed to geolocate {ip}: {e}")
        
        # 4. URL EXTRACTION
        urls = extract_urls(body)
        logger.info(f"🔗 Extracted {len(urls)} URL(s)")
        
        # 5. VECTOR SIMILARITY SEARCH - Find similar threats
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT sender, subject, confidence, metadata
            FROM messages
            WHERE is_threat = 1
            ORDER BY timestamp DESC
            LIMIT 5
        """)
        similar_threats = cursor.fetchall()
        conn.close()
        
        # BUILD COMPREHENSIVE RESULT CARD
        _action_color = {"quarantine": "danger", "review": "warning",
                         "triage_novel": "info", "pass": "success"}
        result_color = _action_color.get(verdict.action.value, "secondary")
        result_icon = "🚨" if is_threat else ("🧪" if verdict.action.value == "triage_novel" else "✅")
        result_text = verdict.action.value.replace("_", " ").upper()

        return dbc.Card([
            dbc.CardHeader([
                html.H4(f"{result_icon} {result_text}", className="mb-0")
            ], style={"background-color": f"var(--bs-{result_color})", "color": "white"}),
            dbc.CardBody([
                # ML Analysis Section
                html.H5("🎯 ML Analysis", className="text-primary"),
                html.P([
                    html.Strong("Confidence Score: "),
                    html.Span(f"{confidence:.1%}", className=f"badge bg-{result_color}"),
                    html.Span(f"  Risk {verdict.risk_score:.0%}", className="badge bg-secondary ms-1"),
                    html.Span(f"  Anomaly {verdict.anomaly_level}", className="badge bg-dark ms-1"),
                    html.Br(),
                    html.Strong("Sender: "),
                    html.Span(sender, className="text-info"),
                    html.Br(),
                    html.Strong("Subject: "),
                    html.Span(subject or 'N/A'),
                ], className="mb-2"),
                html.Ul([html.Li(r) for r in (verdict.reasons or ["no signals"])],
                        className="small text-muted"),

                html.Hr(),
                
                # IP Intelligence Section
                html.H5("🌐 IP Intelligence", className="text-primary"),
                html.P(f"Found {len(extracted_ips)} unique IP address(es)" if extracted_ips else "No IPs found in email body"),
                html.Div([
                    dbc.ListGroup([
                        dbc.ListGroupItem([
                            html.Strong(ip_data['ip']),
                            html.Br(),
                            html.Small([
                                f"📍 {ip_data['location']} ",
                                dbc.Badge(ip_data['risk'], 
                                         color="danger" if ip_data['risk'] == 'HIGH' else 
                                               "warning" if ip_data['risk'] == 'MEDIUM' else 
                                               "success"),
                                html.Br(),
                                f"ISP: {ip_data['org']}"
                            ])
                        ])
                        for ip_data in ip_geo_data
                    ], className="mb-3")
                ]) if ip_geo_data else html.P("No geolocation data available", className="text-muted"),
                
                html.Hr(),
                
                # URL Analysis Section
                html.H5("🔗 URL Analysis", className="text-primary"),
                html.P(f"Found {len(urls)} URL(s)" if urls else "No URLs found"),
                html.Div([
                    html.Ul([html.Li(html.Code(url)) for url in urls[:10]])
                ]) if urls else None,
                
                html.Hr(),
                
                # Similar Threats Section
                html.H5("📋 Similar Known Threats", className="text-primary"),
                html.Div([
                    dbc.ListGroup([
                        dbc.ListGroupItem([
                            html.Strong(s),
                            html.Br(),
                            html.Small(f"{sub[:60]}..."),
                            html.Br(),
                            html.Small(f"Confidence: {c:.1%}", className="text-muted")
                        ])
                        for s, sub, c, _ in similar_threats
                    ])
                ]) if similar_threats else html.P("No similar threats found", className="text-muted")
            ])
        ], className="mt-3")
    
    except Exception as e:
        logger.error(f"❌ Error in email scanner: {e}", exc_info=True)
        return dbc.Alert([
            html.H5("❌ Analysis Error"),
            html.P(f"Technical details: {str(e)}"),
            html.Small("Check server logs for full traceback", className="text-muted")
        ], color="danger")


@app.callback(
    Output("geo-lookup-result", "children"),
    Input("geo-lookup-btn", "n_clicks"),
    State("geo-ip-input", "value"),
    prevent_initial_call=True
)
def lookup_ip_geo(n_clicks, ip):
    """Lookup IP geolocation."""
    if not ip:
        return dbc.Alert("⚠️ Enter an IP address", color="warning")
    
    try:
        geo = geo_service.get_location(ip, force_refresh=True)
        
        if not geo or not geo.get('country'):
            return dbc.Alert(f"❌ Could not resolve IP: {ip}", color="danger")
        
        risk_colors = {'LOW': 'success', 'MEDIUM': 'warning', 'HIGH': 'danger'}
        risk_score = geo.get('risk_score', 'UNKNOWN')
        
        return dbc.Card([
            dbc.CardBody([
                html.H5(f"📍 {geo.get('city')}, {geo.get('country')}", className="card-title"),
                html.P([
                    html.Strong("IP: "), html.Span(ip), html.Br(),
                    html.Strong("Region: "), html.Span(geo.get('region', 'N/A')), html.Br(),
                    html.Strong("Timezone: "), html.Span(geo.get('timezone', 'N/A')), html.Br(),
                    html.Strong("ISP: "), html.Span(geo.get('org', 'N/A')), html.Br(),
                    html.Strong("Coordinates: "), html.Span(f"{geo.get('lat', 'N/A')}, {geo.get('lon', 'N/A')}"), html.Br(),
                ], className="mb-2"),
                dbc.Badge(f"Risk: {risk_score}", color=risk_colors.get(risk_score, 'secondary'), className="me-1")
            ])
        ], color="dark", outline=True)
    
    except Exception as e:
        return dbc.Alert(f"❌ Error: {str(e)}", color="danger")


@app.callback(
    [Output("geo-stats", "children"),
     Output("geo-country-chart", "figure")],
    Input("interval-component", "n_intervals")
)
def update_geo_stats(n):
    """Update geographic threat statistics using stored geo data."""
    try:
        conn = connect_db()
        if not conn:
            stats_div = dbc.Alert("Database unavailable. Start PostgreSQL to load geo stats.", color="warning")
            empty_fig = go.Figure()
            empty_fig.update_layout(template="plotly_dark", title="Database unavailable")
            return stats_div, empty_fig

        if not has_messages_table(conn):
            conn.close()
            stats_div = dbc.Alert("No messages table yet. Geo stats will appear after ingestion.", color="info")
            empty_fig = go.Figure()
            empty_fig.update_layout(template="plotly_dark", title="No geo data available")
            return stats_div, empty_fig

        cursor = conn.cursor()
        
        # Get threats with geolocation (using stored geo data)
        cursor.execute("""
            SELECT 
                metadata
            FROM messages
            WHERE is_threat = 1
              AND timestamp > NOW() - INTERVAL '7 days'
              AND metadata IS NOT NULL
              AND metadata::text LIKE '%geo%'
        """)
        rows = cursor.fetchall()
        conn.close()
        
        # Extract geolocation from stored metadata
        country_counts = {}
        city_counts = {}
        risk_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
        
        for (metadata,) in rows:
            if metadata and isinstance(metadata, dict):
                geo = metadata.get('geo', {})
                if geo and isinstance(geo, dict):
                    country = geo.get('country', 'Unknown')
                    city = geo.get('city', 'Unknown')
                    risk = geo.get('risk_score', 'UNKNOWN')
                    
                    country_counts[country] = country_counts.get(country, 0) + 1
                    city_key = f"{city}, {country}"
                    city_counts[city_key] = city_counts.get(city_key, 0) + 1
                    risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        total_threats = sum(country_counts.values())
        
        if not country_counts:
            stats_div = dbc.Alert("📊 No geolocation data yet. New emails will include location info.", color="info")
            empty_fig = go.Figure()
            empty_fig.update_layout(template="plotly_dark", title="No geo data available")
            return stats_div, empty_fig
        
        # Stats summary
        unique_countries = len(country_counts)
        top_country = max(country_counts, key=country_counts.get) if country_counts else "N/A"
        high_risk_count = risk_counts['HIGH']
        
        stats_div = html.Div([
            html.P([html.Strong("🌍 Total Threats: "), f"{total_threats:,}"]),
            html.P([html.Strong("🗺️ Countries: "), f"{unique_countries}"]),
            html.P([html.Strong("🏆 Top Source: "), f"{top_country} ({country_counts.get(top_country, 0)} threats)"]),
            html.P([
                html.Strong("🔴 High Risk: "),
                html.Span(f"{high_risk_count} ({100*high_risk_count/total_threats:.1f}%)" if total_threats > 0 else "0", 
                         style={'color': '#ff4444', 'font-weight': 'bold'})
            ])
        ])
        
        # Country chart
        sorted_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        countries = [c[0] for c in sorted_countries]
        counts = [c[1] for c in sorted_countries]
        
        fig = go.Figure(data=[
            go.Bar(x=countries, y=counts, marker_color='#ff4444', hovertemplate='<b>%{x}</b><br>Threats: %{y}<extra></extra>')
        ])
        fig.update_layout(
            template="plotly_dark",
            title="Top 10 Threat Origin Countries (Last 7 Days)",
            xaxis_title="Country",
            yaxis_title="Threat Count",
            height=400,
            xaxis={'tickangle': -45},
            uirevision='geo-chart',  # Preserve zoom/pan state
            transition={'duration': 300, 'easing': 'cubic-in-out'},
            margin=dict(l=60, r=30, t=60, b=100)
        )
        
        return stats_div, fig
    except Exception as e:
        logger.error(f"Error updating geo stats: {e}")
        stats_div = dbc.Alert(f"Error loading geo stats: {e}", color="danger")
        empty_fig = go.Figure()
        empty_fig.update_layout(template="plotly_dark", title="Error loading data")
        return stats_div, empty_fig

# ============================================================================
# SECURITY TAB CALLBACKS
# ============================================================================

@app.callback(
    [Output("security-score-display", "children"),
     Output("security-metrics", "children"),
     Output("threat-action-stats", "children"),
     Output("security-events-list", "children")],
    Input("interval-component", "n_intervals")
)
def update_security_tab(n):
    """Update security scorecard metrics."""
    try:
        conn = connect_db()
        if not conn:
            score_display = html.Div([
                html.H1("N/A", className="text-warning display-1"),
                html.P("database offline", className="text-muted")
            ])
            metrics = dbc.ListGroup([
                dbc.ListGroupItem("Connect PostgreSQL to calculate security metrics.")
            ])
            action_stats = dbc.ListGroup([
                dbc.ListGroupItem([
                    html.Strong("🚫 Blocked Senders: "),
                    dbc.Badge(f"{len(threat_actions.get_blocked_senders())}", color="danger")
                ]),
                dbc.ListGroupItem([
                    html.Strong("⚠️ Warned Senders: "),
                    dbc.Badge(f"{len(threat_actions.get_warned_senders())}", color="warning")
                ]),
            ])
            events = [html.Div("DB unavailable: showing action counters only.", className="text-muted")]
            return score_display, metrics, action_stats, events

        if not has_messages_table(conn):
            conn.close()
            score_display = html.Div([
                html.H1("0", className="text-info display-1"),
                html.P("schema not initialized", className="text-muted")
            ])
            metrics = dbc.ListGroup([
                dbc.ListGroupItem("Messages table not found. Run ingestion/bootstrap to initialize schema.")
            ])
            action_stats = dbc.ListGroup([
                dbc.ListGroupItem([
                    html.Strong("🚫 Blocked Senders: "),
                    dbc.Badge(f"{len(threat_actions.get_blocked_senders())}", color="danger")
                ]),
                dbc.ListGroupItem([
                    html.Strong("⚠️ Warned Senders: "),
                    dbc.Badge(f"{len(threat_actions.get_warned_senders())}", color="warning")
                ]),
            ])
            events = [html.Div("No recent DB-backed events yet.", className="text-muted")]
            return score_display, metrics, action_stats, events

        cursor = conn.cursor()
        
        # Calculate security metrics
        cursor.execute("SELECT COUNT(*) FROM messages")
        total_emails = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM messages WHERE is_threat = 1")
        total_threats = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM messages WHERE processed = true")
        processed = cursor.fetchone()[0]
        
        # Threat detection rate
        detection_rate = (total_threats / total_emails * 100) if total_emails > 0 else 0
        
        # Processing efficiency
        process_rate = (processed / total_emails * 100) if total_emails > 0 else 0
        
        conn.close()
        
        # Get blocked/warned counts
        blocked_count = len(threat_actions.get_blocked_senders())
        warned_count = len(threat_actions.get_warned_senders())
        
        # Calculate security score (0-100)
        # Higher is better: penalize unprocessed threats, reward blocked/warned
        unprocessed_threats = total_threats - processed if total_threats > processed else 0
        score = 100 - min(unprocessed_threats * 5, 50)  # -5 per unprocessed, max -50
        score = max(score, 10)  # Minimum score of 10
        
        # Score display with color coding
        score_color = "success" if score >= 80 else "warning" if score >= 50 else "danger"
        score_display = html.Div([
            html.H1(f"{score}", className=f"text-{score_color} display-1"),
            html.P("out of 100", className="text-muted")
        ])
        
        # Metrics list
        metrics = dbc.ListGroup([
            dbc.ListGroupItem([
                html.Strong("📧 Total Emails Scanned: "),
                html.Span(f"{total_emails:,}")
            ]),
            dbc.ListGroupItem([
                html.Strong("🚨 Threats Detected: "),
                html.Span(f"{total_threats:,}", className="text-danger")
            ]),
            dbc.ListGroupItem([
                html.Strong("📊 Detection Rate: "),
                html.Span(f"{detection_rate:.1f}%")
            ]),
            dbc.ListGroupItem([
                html.Strong("✅ Processing Rate: "),
                html.Span(f"{process_rate:.1f}%", className="text-success")
            ]),
        ])
        
        # Threat action stats
        action_stats = dbc.ListGroup([
            dbc.ListGroupItem([
                html.Strong("🚫 Blocked Senders: "),
                dbc.Badge(f"{blocked_count}", color="danger")
            ]),
            dbc.ListGroupItem([
                html.Strong("⚠️ Warned Senders: "),
                dbc.Badge(f"{warned_count}", color="warning")
            ]),
        ])
        
        # Recent security events (last 10 blocked/warned)
        events = []
        blocked = threat_actions.get_blocked_senders()
        for sender, info in list(blocked.items())[:5]:
            events.append(
                html.Div([
                    dbc.Badge("BLOCKED", color="danger", className="me-2"),
                    html.Span(sender[:40], className="text-info"),
                    html.Small(f" - {info.get('reason', 'N/A')[:30]}", className="text-muted")
                ], className="mb-2")
            )
        
        warned = threat_actions.get_warned_senders()
        for sender, info in list(warned.items())[:5]:
            events.append(
                html.Div([
                    dbc.Badge("WARNED", color="warning", className="me-2"),
                    html.Span(sender[:40], className="text-info"),
                    html.Small(f" - {info.get('reason', 'N/A')[:30]}", className="text-muted")
                ], className="mb-2")
            )
        
        if not events:
            events = [html.Div("No recent security events", className="text-muted")]
        
        return score_display, metrics, action_stats, events
        
    except Exception as e:
        logger.error(f"Error updating security tab: {e}")
        error_div = dbc.Alert(f"Error: {e}", color="danger")
        return error_div, error_div, error_div, error_div

# ============================================================================
# REAL-TIME LOG CALLBACKS
# ============================================================================

@app.callback(
    Output("scanner-live-logs", "children"),
    [Input("interval-component", "n_intervals"),
     Input("log-filter-all", "n_clicks"),
     Input("log-filter-errors", "n_clicks"),
     Input("log-filter-warnings", "n_clicks"),
     Input("log-filter-success", "n_clicks"),
     Input("scanner-clear-logs", "n_clicks")]
)
def update_scanner_logs(n_intervals, all_clicks, error_clicks, warn_clicks, success_clicks, clear_clicks):
    """Update real-time processing logs with timestamp filtering."""
    triggered_id = ctx.triggered_id
    
    # Clear logs if clear button clicked
    if triggered_id == "scanner-clear-logs":
        with RT_LOGS_LOCK:
            RT_LOGS.clear()
        return [html.Div("⏳ Logs cleared. Waiting for next ingestion...", 
                        style={"color": "#8b949e", "font-style": "italic"})]
    
    # Determine filter level
    filter_level = None
    if triggered_id == "log-filter-errors":
        filter_level = "error"
    elif triggered_id == "log-filter-warnings":
        filter_level = "warning"
    elif triggered_id == "log-filter-success":
        filter_level = "success"
    
    # Get logs (thread-safe)
    with RT_LOGS_LOCK:
        logs = list(RT_LOGS)
    
    if not logs:
        return [html.Div("⏳ Waiting for ingestion to start...", 
                        style={"color": "#8b949e", "font-style": "italic"})]
    
    # Filter logs if needed
    if filter_level:
        logs = [log for log in logs if log['level'] == filter_level]
    
    # Reverse to show newest first
    logs = list(reversed(logs))
    
    # Format logs with timestamps
    log_elements = []
    for log in logs:
        timestamp = datetime.fromisoformat(log['timestamp']).strftime('%H:%M:%S.%f')[:-3]
        level = log['level']
        message = log['message']
        
        # Color coding
        color_map = {
            'info': '#58a6ff',
            'success': '#3fb950',
            'warning': '#d29922',
            'error': '#f85149'
        }
        color = color_map.get(level, '#8b949e')
        
        # Icon mapping
        icon_map = {
            'info': 'ℹ️',
            'success': '✅',
            'warning': '⚠️',
            'error': '❌'
        }
        icon = icon_map.get(level, '•')
        
        log_elements.append(
            html.Div([
                html.Span(f"[{timestamp}] ", style={"color": "#6e7681", "font-weight": "bold"}),
                html.Span(f"{icon} ", style={"color": color}),
                html.Span(message, style={"color": color})
            ], style={"margin-bottom": "2px"})
        )
    
    return log_elements


@app.callback(
    Output("log-filter-all", "color"),
    Output("log-filter-errors", "color"),
    Output("log-filter-warnings", "color"),
    Output("log-filter-success", "color"),
    [Input("log-filter-all", "n_clicks"),
     Input("log-filter-errors", "n_clicks"),
     Input("log-filter-warnings", "n_clicks"),
     Input("log-filter-success", "n_clicks")]
)
def update_filter_button_colors(all_clicks, error_clicks, warn_clicks, success_clicks):
    """Update filter button colors based on active filter."""
    triggered_id = ctx.triggered_id
    
    # Reset all to outline
    colors = ["outline-info", "outline-danger", "outline-warning", "outline-success"]
    
    # Highlight active filter
    if triggered_id == "log-filter-all":
        colors[0] = "info"
    elif triggered_id == "log-filter-errors":
        colors[1] = "danger"
    elif triggered_id == "log-filter-warnings":
        colors[2] = "warning"
    elif triggered_id == "log-filter-success":
        colors[3] = "success"
    else:
        colors[0] = "info"  # Default to "All"
    
    return colors

# ============================================================================
# RTI (Smish/Vish) CALLBACKS — unified risk engine, single-message latency path
# ============================================================================
RTI_RECENT = {"smish": deque(maxlen=25), "vish": deque(maxlen=25)}
RTI_RECENT_LOCK = threading.Lock()

# action.value -> (bootstrap color, icon, label)
_RTI_ACTION_STYLE = {
    "quarantine": ("danger", "🚫", "QUARANTINE"),
    "review": ("warning", "🔎", "REVIEW"),
    "triage_novel": ("info", "🧪", "TRIAGE — NOVEL"),
    "pass": ("success", "✅", "PASS"),
}


def _rti_action_value(action):
    return action.value if hasattr(action, "value") else action


_RTI_CHANNEL = {"smish": "smishing", "vish": "vishing"}


def _rti_assess(kind, body, sender):
    """Run the unified risk engine for one RTI message via the channel pipeline.

    process_one is the single source of truth: it routes to the channel detector
    (SmishGuard/VishGuard) and applies that channel's OWN anomaly manifold.
    """
    from common.streaming.channel_pipeline import process_one
    record = {"body": body or "", "transcript": body or "",
              "from": sender or "", "caller_id": sender or ""}
    return process_one(_RTI_CHANNEL[kind], record)


def _rti_metric(label, value, color):
    return dbc.Card(dbc.CardBody([
        html.Div(label, className="text-muted", style={"fontSize": "11px"}),
        html.Div(value, className=f"text-{color}",
                 style={"fontWeight": "bold", "fontSize": "18px"}),
    ]), className="text-center")


def _rti_verdict_card(kind, sender, verdict):
    cfg = RTI_CONFIG[kind]
    action = _rti_action_value(verdict.action)
    color, icon, label = _RTI_ACTION_STYLE.get(action, ("secondary", "•", "UNKNOWN"))
    return dbc.Card([
        dbc.CardHeader(html.H4(f"{icon} {label}", className="mb-0"),
                       style={"backgroundColor": f"var(--bs-{color})", "color": "white"}),
        dbc.CardBody([
            dbc.Row([
                dbc.Col(_rti_metric("Risk Score", f"{verdict.risk_score:.0%}", color), xs=6, md=3),
                dbc.Col(_rti_metric("Classifier", "PHISH" if verdict.classifier_pred else "SAFE",
                                    "danger" if verdict.classifier_pred else "success"), xs=6, md=3),
                dbc.Col(_rti_metric("Confidence", f"{verdict.classifier_conf:.0%}", color), xs=6, md=3),
                dbc.Col(_rti_metric("Anomaly", verdict.anomaly_level, "info"), xs=6, md=3),
            ], className="mb-3"),
            html.H6("Why this verdict", className="text-primary"),
            html.Ul([html.Li(r) for r in (verdict.reasons or ["no signals"])]),
            html.Hr(),
            html.Small([html.Strong(f"{cfg['channel']} from: "), sender or "unknown"],
                       className="text-muted"),
        ])
    ])


def _rti_recent_list(kind):
    with RTI_RECENT_LOCK:
        items = list(RTI_RECENT[kind])
    if not items:
        return html.Div("No intercepts yet. Analyze a message to populate.",
                        className="text-muted")
    rows = []
    for it in reversed(items):
        color, icon, label = _RTI_ACTION_STYLE.get(it["action"], ("secondary", "•", it["action"]))
        rows.append(dbc.ListGroupItem([
            html.Div([
                dbc.Badge(f"{icon} {label}", color=color, className="me-2"),
                html.Small(it["time"], className="text-muted"),
            ]),
            html.Div(html.Strong(it["sender"] or "unknown"), style={"fontSize": "12px"}),
            html.Div(it["preview"], className="text-muted", style={"fontSize": "11px"}),
        ]))
    return dbc.ListGroup(rows, flush=True)


def _register_rti_callbacks(kind):
    """Register sample-loader + analyze callbacks for one RTI channel (DRY)."""
    cfg = RTI_CONFIG[kind]

    @app.callback(
        Output(f"{kind}-sender", "value"),
        Output(f"{kind}-body", "value"),
        Input({"type": f"{kind}-sample", "index": ALL}, "n_clicks"),
        prevent_initial_call=True,
    )
    def _load_sample(clicks):
        trig = ctx.triggered_id
        if not trig or not any(c for c in (clicks or []) if c):
            raise dash.exceptions.PreventUpdate
        text, sender = cfg["samples"][trig["index"]]
        return sender, text

    @app.callback(
        Output(f"{kind}-results", "children"),
        Output(f"{kind}-threat-list", "children"),
        Input(f"{kind}-analyze", "n_clicks"),
        State(f"{kind}-sender", "value"),
        State(f"{kind}-body", "value"),
        prevent_initial_call=True,
    )
    def _analyze(n_clicks, sender, body):
        if not n_clicks:
            raise dash.exceptions.PreventUpdate
        if not body:
            return (dbc.Alert(f"⚠️ Paste a {cfg['channel']} message to analyze.",
                              color="warning"), dash.no_update)
        try:
            verdict = _rti_assess(kind, body, sender)
        except Exception as e:
            logger.error(f"{kind} analyze error: {e}")
            return (dbc.Alert(f"❌ Analysis failed: {e}", color="danger"), dash.no_update)

        action = _rti_action_value(verdict.action)
        with RTI_RECENT_LOCK:
            RTI_RECENT[kind].append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "sender": sender, "action": action,
                "preview": (body[:80] + "…") if len(body) > 80 else body,
            })
        return _rti_verdict_card(kind, sender, verdict), _rti_recent_list(kind)


for _rti_kind in ("smish", "vish"):
    _register_rti_callbacks(_rti_kind)


@app.callback(
    Output("kpi-body", "children"),
    Input("kpi-refresh", "n_clicks"),
    prevent_initial_call=True,
)
def _refresh_kpis(n_clicks):
    if not n_clicks:
        raise dash.exceptions.PreventUpdate
    # Force a fresh compute (bypass the TTL cache) so Refresh is meaningful.
    kpi._CACHE.clear()
    return _kpi_body()


# ============================================================================
# RUN SERVER
# ============================================================================

if __name__ == "__main__":
    import os

    # 12-factor config. debug MUST be off whenever the app is reachable beyond
    # localhost (Werkzeug's debugger allows remote code execution). Default off.
    host = os.getenv("DASH_HOST", "0.0.0.0")
    port = int(os.getenv("DASH_PORT", "8050"))
    debug = os.getenv("DASH_DEBUG", "false").lower() in ("1", "true", "yes")

    if debug and host == "0.0.0.0":
        logger.warning("DASH_DEBUG=true while bound to 0.0.0.0 — the Werkzeug "
                       "debugger is exposed. Only do this on a trusted LAN.")

    print("=" * 70)
    print("🛡️  YAHOO_PHISH IDPS DASHBOARD")
    print("=" * 70)
    print(f"🌐 Binding: {host}:{port}  (debug={debug})")
    print("📍 Local:   http://localhost:8050")
    print("🌍 LAN:     http://<this-host-LAN-IP>:8050  (behind reverse proxy in prod)")
    print("=" * 70)

    app.run(debug=debug, host=host, port=port)
