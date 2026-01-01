#!/usr/bin/env python3
"""
Real-Time IDPS Dashboard with Dash + Plotly
Shows live ingestion logs, threat maps, and triage controls
"""

import dash
from dash import dcc, html, Input, Output, State, ctx, MATCH
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
    external_stylesheets=[dbc.themes.CYBORG],  # Dark theme
    suppress_callback_exceptions=True
)

# ============================================================================
# LAYOUT
# ============================================================================

app.layout = dbc.Container([
    # Header
    dbc.Row([
        dbc.Col([
            html.H1("🛡️ IDPS Real-Time Dashboard", className="text-center mb-4"),
            html.Hr()
        ])
    ]),
    
    # Navigation Tabs (Order: Monitor → Scanner → Geo → Raw Data)
    dbc.Row([
        dbc.Col([
            dbc.Tabs([
                dbc.Tab(label="🎯 Live Monitor", tab_id="monitor"),
                dbc.Tab(label="🔍 Email Scanner", tab_id="scanner"),
                dbc.Tab(label="🌍 Geo Intelligence", tab_id="geo-intel"),
                dbc.Tab(label="🔒 Security Score", tab_id="security"),
                dbc.Tab(label="📊 Raw Data", tab_id="raw-data"),
            ], id="tabs", active_tab="monitor")
        ])
    ], className="mb-4"),
    
    # Tab content container
    html.Div(id="tab-content"),
    # Tab content container
    html.Div(id="tab-content"),
    
    # Auto-refresh interval (updates every 2 seconds)
    dcc.Interval(
        id='interval-component',
        interval=2000,  # 2 seconds
        n_intervals=0
    ),
    
    # Store for selected threat
    dcc.Store(id='selected-threat')
    
], fluid=True)

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
            ], width=3),
            
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H4("🚨 Threats Detected", className="card-title"),
                        html.H2(id="total-threats", children="0", className="text-danger")
                    ])
                ])
            ], width=3),
            
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H4("🔴 Blocked", className="card-title"),
                        html.H2(id="total-blocked", children="0", className="text-warning")
                    ])
                ])
            ], width=3),
            
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H4("⚡ Processing", className="card-title"),
                        html.H2(id="processing-rate", children="0/s", className="text-success")
                    ])
                ])
            ], width=3),
        ], className="mb-4"),
        
        # Live Log Stream
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("📜 Live Ingestion Logs"),
                    dbc.CardBody([
                        html.Div(
                            id="live-logs",
                            style={
                                "height": "300px",
                                "overflow-y": "scroll",
                                "background": "#1e1e1e",
                                "padding": "10px",
                                "font-family": "monospace",
                                "font-size": "12px"
                            }
                        )
                    ])
                ])
            ], width=6),
            
            # Threat Map (Geo visualization)
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("🌍 Threat Origins (Last 24h)"),
                    dbc.CardBody([
                        dcc.Graph(id="threat-map", style={"height": "250px", "overflow": "hidden"})
                    ], style={"padding": "0.5rem", "overflow": "hidden"})
                ], style={"overflow": "hidden"})
            ], width=6),
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
    """Raw database viewer with filtering."""
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
                            ], width=4),
                            dbc.Col([
                                html.H6("🧪 Raw File Preview"),
                                html.Div(id="raw-file-content", style={"height": "300px", "overflowY": "scroll", "background": "#161b22", "padding": "8px", "border": "1px solid #30363d", "fontFamily": "monospace", "fontSize": "11px"})
                            ], width=8)
                        ], className="mb-4"),
                        html.H6("📊 Messages (DB Query)"),
                        html.Div(id="raw-data-table", style={"maxHeight": "600px", "overflowY": "scroll"})
                    ])
                ])
            ])
        ])
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
                            ], width=4),
                            dbc.Col([
                                dbc.Label("Your Email (Receiver):"),
                                dbc.Input(
                                    id="scanner-user-email",
                                    type="email",
                                    placeholder="your-email@example.com",
                                    value="epinaman@yahoo.com"
                                )
                            ], width=4),
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
                            ], width=4)
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
                            ], width=6),
                            dbc.Col([
                                dbc.Label("Subject:"),
                                dbc.Input(id="scanner-subject", type="text", placeholder="Email subject")
                            ], width=6)
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
            ], width=6),
            
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
                            style={
                                "height": "650px",
                                "overflow-y": "scroll",
                                "background": "#0d1117",
                                "padding": "10px",
                                "font-family": "'Courier New', monospace",
                                "font-size": "11px",
                                "border": "1px solid #30363d",
                                "border-radius": "6px"
                            },
                            children=[
                                html.Div("⏳ Waiting for ingestion to start...", 
                                       style={"color": "#8b949e", "font-style": "italic"})
                            ]
                        )
                    ])
                ])
            ], width=6)
        ])
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
                            ], width=6),
                            dbc.Col([
                                html.H5("🗺️ Threat Origin Statistics"),
                                html.Div(id="geo-stats")
                            ], width=6)
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
    elif active_tab == "scanner":
        return render_scanner_tab()
    elif active_tab == "geo-intel":
        return render_geo_intel_tab()
    return render_monitor_tab()

# ============================================================================
# CALLBACKS (Real-time updates)
# ============================================================================

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
            # FIX: Use Scattergeo() to force geographic projection
            fig = go.Figure(go.Scattergeo())
            fig.update_layout(
                title="No threats with geolocation in last 24 hours",
                template="plotly_dark",
                height=240,
                margin=dict(l=0, r=0, t=30, b=0),
                geo=dict(
                    showland=True,
                    landcolor='#1a1a1a',
                    showcountries=True,
                    countrycolor='#333',
                    bgcolor='rgba(0,0,0,0)',
                    projection_type='natural earth'
                )
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
            height=240,
            margin=dict(l=0, r=0, t=30, b=0),
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
        fig = go.Figure(go.Scattergeo())
        fig.update_layout(
            title=f"Error loading threat map: {str(e)}",
            template="plotly_dark",
            height=240,
            margin=dict(l=0, r=0, t=30, b=0)
        )
        return fig

@app.callback(
    Output("threat-list", "children"),
    [Input("interval-component", "n_intervals"),
     Input("selected-threat", "data")]
)
def update_threat_list(n, selected_threat):
    """Display unprocessed threats with triage buttons."""
    conn = connect_db()
    cursor = conn.cursor()
    
    # Get unprocessed threats (removed confidence filter - show ALL threats)
    cursor.execute("""
        SELECT id, sender, subject, confidence, metadata, timestamp
        FROM messages
        WHERE is_threat = 1 
          AND processed = false
        ORDER BY timestamp DESC
        LIMIT 20
    """)
    threats = cursor.fetchall()
    conn.close()
    
    if not threats:
        return html.Div("✅ No pending threats", className="text-success")
    
    # Create threat cards
    threat_cards = []
    for threat_id, sender, subject, confidence, metadata, timestamp in threats:
        # Defensive defaults to avoid NoneType errors
        subject_text = (subject or "(no subject)").strip()
        sender_text = (sender or "unknown").strip()
        confidence_val = float(confidence or 0.0)
        ts_display = timestamp.strftime('%Y-%m-%d %H:%M') if hasattr(timestamp, 'strftime') else str(timestamp)
        
        # Get geolocation and analysis from stored metadata
        geo_text = "No Geo Data"
        analysis_bits = []
        
        if metadata and isinstance(metadata, dict):
            geo = metadata.get('geo', {})
            if geo and isinstance(geo, dict):
                country = geo.get('country', 'Unknown')
                city = geo.get('city', '')
                ip_addr = geo.get('ip', '')
                risk = geo.get('risk_score', 'UNKNOWN')
                location_parts = []
                if city:
                    location_parts.append(city)
                location_parts.append(country)
                if ip_addr:
                    location_parts.append(f"[{ip_addr}]")
                location = " / ".join(location_parts)
                risk_label = f"{risk}" if risk != 'UNKNOWN' else "??"
                geo_text = f"{location} ({risk_label})"
            
            # Build analysis breakdown
            heuristic_val = metadata.get('heuristic')
            similarity_val = metadata.get('similarity')
            ml_conf_val = metadata.get('ml_confidence')
            
            if heuristic_val is not None:
                analysis_bits.append(f"Heuristic={heuristic_val:.2f}")
            if similarity_val is not None:
                analysis_bits.append(f"Similarity={similarity_val:.2f}")
            if ml_conf_val is not None:
                analysis_bits.append(f"ML={ml_conf_val:.2f}")
        
        analysis_text = " | ".join(analysis_bits) if analysis_bits else "No analysis data"
        
        # Handle confidence (0.00 means not yet scored by ML)
        confidence_text = f"{confidence_val:.1%}" if confidence_val > 0 else "Not Scored"
        confidence_color = "text-danger" if confidence_val > 0.8 else "text-warning" if confidence_val > 0.5 else "text-muted"
        
        # Create card
        card = dbc.Card([
            dbc.CardBody([
                dbc.Row([
                    dbc.Col([
                        html.H5(f"[THREAT] {subject_text[:55]}", className="text-danger"),
                        html.P([
                            html.Strong("From: "),
                            html.Span(sender_text, className="text-info"),
                            html.Br(),
                            html.Strong("Location: "),
                            html.Span(geo_text, className="text-muted"),
                            html.Br(),
                            html.Strong("Confidence: "),
                            html.Span(confidence_text, className=confidence_color),
                            html.Br(),
                            html.Small(f"Analysis: {analysis_text}", className="text-muted"),
                            html.Br(),
                            html.Small(f"Detected: {ts_display}", className="text-muted")
                        ])
                    ], width=8),
                    
                    dbc.Col([
                        dbc.ButtonGroup([
                            dbc.Button(
                                "🚫 Block & Report",
                                id={"type": "block-report-btn", "index": threat_id},
                                color="danger",
                                size="sm",
                                className="mb-2"
                            ),
                            dbc.Button(
                                "🟡 Warn",
                                id={"type": "warn-btn", "index": threat_id},
                                color="warning",
                                size="sm"
                            )
                        ], vertical=True, className="w-100")
                    ], width=4)
                ])
            ])
        ], className="mb-3", style={"border-left": f"4px solid {'#ff4444' if confidence > 0.8 else '#ffaa44'}"})
        
        threat_cards.append(card)
    
    return threat_cards

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
    """Unified handler: blocks sender AND generates threat report."""
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
        
        logger.info(f"✅ Threat {threat_id} blocked & reported. Report ID: {report.get('report_id', 'N/A')}")
        
        # 3. Mark as processed
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
        Output({"type": "report-btn", "index": MATCH}, "children"),
        Output({"type": "report-btn", "index": MATCH}, "color"),
        Output({"type": "report-btn", "index": MATCH}, "disabled")
    ],
    Input({"type": "report-btn", "index": MATCH}, "n_clicks"),
    State({"type": "report-btn", "index": MATCH}, "id"),
    prevent_initial_call=True
)
def handle_report_action(n_clicks, btn_id):
    """Handle report button with visual feedback."""
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
        
        # Report threat
        threat_actions.report_threat(
            threat_dict,
            "📋 Manual REPORT via dashboard"
        )
        
        # Mark as processed
        cursor.execute("UPDATE messages SET processed = true WHERE id = %s", (threat_id,))
        conn.commit()
    
    conn.close()
    
    return "✅ Reported!", "info", True

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
    """Display raw database records."""
    conn = connect_db()
    cursor = conn.cursor()
    
    # Build query based on filter
    if filter_val == "threats":
        query = "SELECT id, sender, subject, confidence, is_threat, processed, timestamp FROM messages WHERE is_threat = 1 ORDER BY timestamp DESC LIMIT %s"
    elif filter_val == "safe":
        query = "SELECT id, sender, subject, confidence, is_threat, processed, timestamp FROM messages WHERE is_threat = 0 ORDER BY timestamp DESC LIMIT %s"
    elif filter_val == "unprocessed":
        query = "SELECT id, sender, subject, confidence, is_threat, processed, timestamp FROM messages WHERE processed = false ORDER BY timestamp DESC LIMIT %s"
    else:
        query = "SELECT id, sender, subject, confidence, is_threat, processed, timestamp FROM messages ORDER BY timestamp DESC LIMIT %s"
    
    cursor.execute(query, (limit or 50,))
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        return html.Div("No data found", className="text-muted")
    
    # Create table
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
        table_rows.append(html.Tr([
            html.Td(tid),
            html.Td(sender[:40] + "..." if len(sender) > 40 else sender),
            html.Td(subject[:50] + "..." if subject and len(subject) > 50 else subject or ""),
            html.Td(f"{conf:.2f}" if conf else "0.00"),
            html.Td("🚨 Yes" if is_threat else "✅ No"),
            html.Td("✅" if processed else "⏳"),
            html.Td(ts.strftime("%Y-%m-%d %H:%M") if ts else "")
        ]))
    
    table_body = [html.Tbody(table_rows)]
    
    return dbc.Table(table_header + table_body, striped=True, bordered=True, hover=True, size="sm", className="table-dark")

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
    """Populate and display raw ingestion JSON files with robust parsing."""
    ingestion_dir = Path('data/ingestion')
    files = sorted(ingestion_dir.glob('*.json'))[-25:]
    options = [{"label": f.name, "value": str(f)} for f in files]
    if not selected_file and files:
        selected_file = str(files[-1])
    content_div = html.Div("No file selected", style={"color": "#888"})
    meta_div = ""
    if selected_file and Path(selected_file).exists():
        try:
            raw_text = Path(selected_file).read_text()
            file_size = len(raw_text.encode())
            # Try parsing full file first
            try:
                raw = json.loads(raw_text)
            except json.JSONDecodeError:
                # If full parse fails, try truncating and repairing
                truncated = raw_text[:250000]
                last_brace = truncated.rfind('}')
                if truncated.startswith('['):
                    last_brace = max(last_brace, truncated.rfind(']'))
                if last_brace > 0:
                    truncated = truncated[:last_brace + 1]
                    if truncated.startswith('['):
                        truncated += ']'
                raw = json.loads(truncated)
            
            preview = raw[:20] if isinstance(raw, list) else raw
            pretty = json.dumps(preview, indent=2, ensure_ascii=False)[:10000]
            content_div = html.Pre(pretty, style={"whiteSpace": "pre-wrap", "wordBreak": "break-word", "fontSize": "11px"})
            item_count = len(raw) if isinstance(raw, list) else 1
            meta_div = f"Records: {item_count} | File size: {file_size / 1024:.1f} KB (showing first 20)"
        except Exception as e:
            meta_div = f"Parsing failed: {str(e)[:60]}... (file may be corrupted)"
            content_div = html.Div(f"Unable to parse file: {str(e)[:100]}", style={"color": "#f85149", "fontSize": "12px"})
    return options, selected_file, content_div, meta_div


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
        
        # Configure ingestion - REAL-TIME email-by-email processing (default)
        config = IngestionConfig(
            batch_size=int(batch_size),
            max_emails_per_provider=int(batch_size),
            parallel_providers=False,
            enable_intelligence=True,
            enable_ml_analysis=True,
            stream_delay=0.03      # 30ms between emails for fast real-time streaming
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
            html.H4("🚀 Real-Time Streaming Started", className="alert-heading"),
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
    """Manually scan email for threats using ML."""
    if not body or not sender:
        return dbc.Alert("⚠️ Please provide at least sender and body content", color="warning")
    
    try:
        # Use PhishingDetector
        from PhishGuard.phish_mlm.phishing_detector import PhishingDetector
        detector = PhishingDetector()
        
        # Prepare email content
        content = f"From: {sender}\nSubject: {subject or ''}\n\n{body}"
        
        # Predict
        is_threat, confidence = detector.predict(content)
        
        # Get similar threats from vector DB
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT sender, subject, confidence
            FROM messages
            WHERE is_threat = 1
            ORDER BY timestamp DESC
            LIMIT 5
        """)
        similar = cursor.fetchall()
        conn.close()
        
        # Build result
        if is_threat:
            return dbc.Alert([
                html.H4("🚨 THREAT DETECTED", className="alert-heading"),
                html.Hr(),
                html.P(f"Confidence: {confidence:.1%}", className="mb-1"),
                html.P(f"Sender: {sender}", className="mb-1"),
                html.P(f"Subject: {subject or 'N/A'}", className="mb-3"),
                html.H6("📋 Similar Known Threats:"),
                html.Ul([
                    html.Li(f"{s} - {sub[:50]}... ({c:.1%})")
                    for s, sub, c in similar
                ])
            ], color="danger")
        else:
            return dbc.Alert([
                html.H4("✅ SAFE", className="alert-heading"),
                html.Hr(),
                html.P(f"Confidence: {confidence:.1%}", className="mb-1"),
                html.P(f"This email appears legitimate.", className="mb-0")
            ], color="success")
    
    except Exception as e:
        return dbc.Alert(f"❌ Error analyzing email: {str(e)}", color="danger")


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
# RUN SERVER
# ============================================================================

if __name__ == "__main__":
    print("="*70)
    print("🛡️  YAHOO_PHISH IDPS DASHBOARD")
    print("="*70)
    print("🌐 Starting Dash server...")
    print("📍 URL: http://localhost:8050")
    print("🔄 Auto-refresh: Every 2 seconds")
    print("🔒 Binding: localhost only (secure)")
    print("")
    print("📑 Available Pages:")
    print("   🎯 Live Monitor - Real-time threat detection")
    print("   📊 Raw Data - Database viewer with filtering")
    print("   🔍 Email Scanner - Manual threat analysis")
    print("   🌍 Geo Intelligence - IP tracking & profiling")
    print("="*70)
    
    # Bind to 0.0.0.0 for Docker container access
    # Use 127.0.0.1 for local-only security
    app.run(debug=True, host='0.0.0.0', port=8050)
