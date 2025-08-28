#!/usr/bin/env python3
"""
IDPS Dashboard - Real-time monitoring and analysis interface
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
from pathlib import Path
import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Autobot.email_ingestion import EmailIngestionEngine, IngestionConfig
from utils.offensive_intel import OffensiveIntelligence
from PhishGuard.providers.email_fetcher.registry import EmailFetcherRegistry

# Page config
st.set_page_config(
    page_title="IDPS Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    .threat-alert {
        background-color: #ffebee;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #f44336;
    }
    .success-card {
        background-color: #e8f5e8;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #4caf50;
    }
</style>
""", unsafe_allow_html=True)

class IDPSDashboard:
    """Main dashboard class."""
    
    def __init__(self):
        self.intelligence = OffensiveIntelligence()
        self.data_dir = Path('data/ingestion')
        
    def render_header(self):
        """Render dashboard header."""
        st.markdown('<h1 class="main-header">🛡️ IDPS Security Dashboard</h1>', unsafe_allow_html=True)
        st.markdown("---")
    
    def render_sidebar(self):
        """Render sidebar controls."""
        st.sidebar.title("🎛️ Controls")
        
        # Ingestion controls
        st.sidebar.subheader("📥 Email Ingestion")
        
        batch_size = st.sidebar.slider("Batch Size", 25, 100, 75, help="Emails per batch")
        max_emails = st.sidebar.slider("Max Emails per Provider", 50, 500, 200, help="Maximum emails to fetch")
        
        providers = EmailFetcherRegistry.get_available_providers()
        selected_providers = st.sidebar.multiselect(
            "Select Providers",
            providers,
            default=providers,
            help="Choose which email providers to monitor"
        )
        
        # Analysis options
        st.sidebar.subheader("🔍 Analysis Options")
        enable_intel = st.sidebar.checkbox("Enable Intelligence", value=True)
        enable_ml = st.sidebar.checkbox("Enable ML Analysis", value=True)
        parallel_processing = st.sidebar.checkbox("Parallel Processing", value=True)
        
        # Start ingestion button
        if st.sidebar.button("🚀 Start Ingestion", type="primary"):
            return self._start_ingestion(
                batch_size, max_emails, selected_providers,
                enable_intel, enable_ml, parallel_processing
            )
        
        return None
    
    def _start_ingestion(self, batch_size, max_emails, providers, enable_intel, enable_ml, parallel):
        """Start email ingestion process."""
        with st.spinner("🔄 Starting email ingestion..."):
            config = IngestionConfig(
                batch_size=batch_size,
                max_emails_per_provider=max_emails,
                parallel_providers=parallel,
                enable_intelligence=enable_intel,
                enable_ml_analysis=enable_ml
            )
            
            engine = EmailIngestionEngine(config)
            stats = engine.ingest_all_providers(providers)
            
            # Store results in session state
            st.session_state['last_ingestion'] = {
                'stats': stats,
                'metrics': engine.get_performance_metrics(),
                'timestamp': datetime.now()
            }
            
            return stats
    
    def render_overview_metrics(self):
        """Render overview metrics."""
        st.subheader("📊 Overview Metrics")
        
        col1, col2, col3, col4 = st.columns(4)
        
        if 'last_ingestion' in st.session_state:
            stats = st.session_state['last_ingestion']['stats']
            metrics = st.session_state['last_ingestion']['metrics']
            
            with col1:
                st.metric(
                    "Total Emails",
                    f"{stats.total_emails:,}",
                    help="Total emails processed"
                )
            
            with col2:
                st.metric(
                    "Threats Detected",
                    f"{stats.threats_detected}",
                    delta=f"{stats.threats_detected} new",
                    delta_color="inverse"
                )
            
            with col3:
                st.metric(
                    "Processing Speed",
                    f"{metrics.get('emails_per_second', 0):.1f}/s",
                    help="Emails processed per second"
                )
            
            with col4:
                st.metric(
                    "Intelligence Profiles",
                    f"{stats.intelligence_profiles}",
                    help="Sender profiles created"
                )
        else:
            with col1:
                st.metric("Total Emails", "0")
            with col2:
                st.metric("Threats Detected", "0")
            with col3:
                st.metric("Processing Speed", "0/s")
            with col4:
                st.metric("Intelligence Profiles", "0")
    
    def render_threat_analysis(self):
        """Render threat analysis section."""
        st.subheader("🚨 Threat Analysis")
        
        if 'last_ingestion' in st.session_state:
            # Get threat profiles
            threat_profiles = self.intelligence.get_threat_profiles(0.3)
            
            if threat_profiles:
                # Create threat dataframe
                threat_data = []
                for profile in threat_profiles:
                    threat_data.append({
                        'Sender': profile.email,
                        'Domain': profile.domain,
                        'Threat Score': profile.threat_score,
                        'Email Count': profile.email_count,
                        'Country': profile.geolocation.get('country', 'Unknown'),
                        'ISP': profile.geolocation.get('isp', 'Unknown'),
                        'First Seen': profile.first_seen.strftime('%Y-%m-%d %H:%M'),
                        'Last Seen': profile.last_seen.strftime('%Y-%m-%d %H:%M')
                    })
                
                df = pd.DataFrame(threat_data)
                
                # Threat score distribution
                col1, col2 = st.columns(2)
                
                with col1:
                    fig = px.histogram(
                        df, x='Threat Score',
                        title="Threat Score Distribution",
                        nbins=20
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    fig = px.scatter(
                        df, x='Email Count', y='Threat Score',
                        title="Threat Score vs Email Count",
                        hover_data=['Sender', 'Domain']
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                # Threat table
                st.subheader("🔍 Detailed Threat Analysis")
                st.dataframe(
                    df.sort_values('Threat Score', ascending=False),
                    use_container_width=True
                )
            else:
                st.success("✅ No threats detected in recent ingestion!")
        else:
            st.info("📥 Run an ingestion to see threat analysis")
    
    def render_intelligence_report(self):
        """Render intelligence report."""
        st.subheader("🕵️ Intelligence Report")
        
        if 'last_ingestion' in st.session_state:
            report = self.intelligence.generate_intelligence_report()
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.metric("Total Profiles", report['total_profiles'])
                st.metric("Threat Profiles", report['threat_profiles'])
            
            with col2:
                high_risk = report['reputation_summary']['high_risk']
                medium_risk = report['reputation_summary']['medium_risk']
                low_risk = report['reputation_summary']['low_risk']
                
                st.metric("High Risk", high_risk)
                st.metric("Medium Risk", medium_risk)
                st.metric("Low Risk", low_risk)
            
            # Geographic distribution
            if report['domains_by_country']:
                country_data = pd.DataFrame([
                    {'Country': k, 'Count': v} 
                    for k, v in report['domains_by_country'].items()
                ])
                
                fig = px.pie(
                    country_data, values='Count', names='Country',
                    title="Email Domains by Country"
                )
                st.plotly_chart(fig, use_container_width=True)
            
            # Common patterns
            if report['common_patterns']:
                pattern_data = pd.DataFrame([
                    {'Pattern': k, 'Count': v} 
                    for k, v in report['common_patterns'].items()
                ])
                
                fig = px.bar(
                    pattern_data, x='Pattern', y='Count',
                    title="Common Sender Patterns"
                )
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("📥 Run an ingestion to see intelligence report")
    
    def render_performance_metrics(self):
        """Render performance metrics."""
        st.subheader("⚡ Performance Metrics")
        
        if 'last_ingestion' in st.session_state:
            metrics = st.session_state['last_ingestion']['metrics']
            stats = st.session_state['last_ingestion']['stats']
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.metric("Processing Time", f"{metrics['processing_time']:.2f}s")
                st.metric("Emails/Second", f"{metrics['emails_per_second']:.1f}")
                st.metric("Threat Detection Rate", f"{metrics['threat_detection_rate']:.2%}")
            
            with col2:
                st.metric("Providers Processed", metrics['providers_processed'])
                st.metric("Errors", metrics['errors'])
                st.metric("Success Rate", f"{(1 - metrics['errors']/max(metrics['providers_processed'], 1)):.1%}")
            
            # Performance chart
            if stats.processing_time > 0:
                fig = go.Figure()
                fig.add_trace(go.Indicator(
                    mode="gauge+number+delta",
                    value=metrics['emails_per_second'],
                    domain={'x': [0, 1], 'y': [0, 1]},
                    title={'text': "Emails/Second"},
                    delta={'reference': 50},
                    gauge={
                        'axis': {'range': [None, 100]},
                        'bar': {'color': "darkblue"},
                        'steps': [
                            {'range': [0, 25], 'color': "lightgray"},
                            {'range': [25, 50], 'color': "gray"},
                            {'range': [50, 75], 'color': "lightgreen"},
                            {'range': [75, 100], 'color': "green"}
                        ],
                        'threshold': {
                            'line': {'color': "red", 'width': 4},
                            'thickness': 0.75,
                            'value': 90
                        }
                    }
                ))
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("📥 Run an ingestion to see performance metrics")
    
    def render_raw_data(self):
        """Render raw data section."""
        st.subheader("📁 Raw Data")
        
        if self.data_dir.exists():
            files = list(self.data_dir.glob("*.json"))
            if files:
                selected_file = st.selectbox(
                    "Select data file",
                    [f.name for f in files],
                    help="Choose a raw data file to view"
                )
                
                if selected_file:
                    file_path = self.data_dir / selected_file
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                    
                    st.json(data[:5])  # Show first 5 emails
                    st.info(f"Showing 5 of {len(data)} emails from {selected_file}")
            else:
                st.info("No raw data files found")
        else:
            st.info("No data directory found")
    
    def run(self):
        """Run the dashboard."""
        self.render_header()
        
        # Sidebar
        ingestion_result = self.render_sidebar()
        
        # Main content
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📊 Overview", "🚨 Threats", "🕵️ Intelligence", "⚡ Performance", "📁 Data"
        ])
        
        with tab1:
            self.render_overview_metrics()
            
            if ingestion_result:
                st.success("✅ Ingestion completed successfully!")
        
        with tab2:
            self.render_threat_analysis()
        
        with tab3:
            self.render_intelligence_report()
        
        with tab4:
            self.render_performance_metrics()
        
        with tab5:
            self.render_raw_data()

if __name__ == "__main__":
    dashboard = IDPSDashboard()
    dashboard.run()
