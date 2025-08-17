import streamlit as st
import pandas as pd
from datetime import datetime
import plotly.express as px
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)

class AdminUI:
    def __init__(self):
        """Initialize the admin UI."""
        st.set_page_config(
            page_title="PhishGuard Admin",
            page_icon="🛡️",
            layout="wide"
        )
        
    def render_dashboard(self, stats: Dict[str, Any]):
        """Render the main dashboard.
        
        Args:
            stats: Dictionary containing system statistics
        """
        st.title("PhishGuard Admin Dashboard")
        
        # Security Status
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Active Threats", stats.get('active_threats', 0))
        with col2:
            st.metric("Protected Emails", stats.get('protected_emails', 0))
        with col3:
            st.metric("System Health", f"{stats.get('system_health', 0)}%")
            
        # Recent Activity
        st.subheader("Recent Activity")
        if 'recent_activity' in stats:
            df = pd.DataFrame(stats['recent_activity'])
            st.dataframe(df)
            
        # Threat Distribution
        st.subheader("Threat Distribution")
        if 'threat_distribution' in stats:
            fig = px.pie(
                stats['threat_distribution'],
                values='count',
                names='type',
                title='Threat Types'
            )
            st.plotly_chart(fig)
            
        # System Logs
        st.subheader("System Logs")
        if 'system_logs' in stats:
            st.text_area("Logs", stats['system_logs'], height=200)
            
    def render_settings(self, settings: Dict[str, Any]):
        """Render the settings page.
        
        Args:
            settings: Dictionary containing system settings
        """
        st.title("System Settings")
        
        # Security Settings
        st.subheader("Security Settings")
        with st.form("security_settings"):
            st.checkbox("Enable Real-time Scanning", value=settings.get('real_time_scanning', True))
            st.checkbox("Enable ML Model Updates", value=settings.get('ml_updates', True))
            st.checkbox("Enable Threat Intelligence", value=settings.get('threat_intel', True))
            st.slider("Scanning Threshold", 0, 100, settings.get('scan_threshold', 80))
            st.form_submit_button("Save Settings")
            
        # ML Model Settings
        st.subheader("ML Model Settings")
        with st.form("ml_settings"):
            st.number_input("Retraining Interval (days)", value=settings.get('retrain_interval', 7))
            st.number_input("Model Confidence Threshold", value=settings.get('confidence_threshold', 0.85))
            st.form_submit_button("Update Model Settings")
            
        # System Configuration
        st.subheader("System Configuration")
        with st.form("system_config"):
            st.text_input("API Key", value=settings.get('api_key', ''), type="password")
            st.text_input("Database URL", value=settings.get('db_url', ''))
            st.form_submit_button("Update Configuration")
            
    def render_analytics(self, analytics: Dict[str, Any]):
        """Render the analytics page.
        
        Args:
            analytics: Dictionary containing system analytics
        """
        st.title("System Analytics")
        
        # Performance Metrics
        st.subheader("Performance Metrics")
        if 'performance' in analytics:
            df = pd.DataFrame(analytics['performance'])
            st.line_chart(df)
            
        # Threat Analytics
        st.subheader("Threat Analytics")
        if 'threats' in analytics:
            df = pd.DataFrame(analytics['threats'])
            st.bar_chart(df)
            
        # Model Performance
        st.subheader("ML Model Performance")
        if 'model_performance' in analytics:
            df = pd.DataFrame(analytics['model_performance'])
            st.line_chart(df)
            
    def render_logs(self, logs: List[Dict[str, Any]]):
        """Render the logs page.
        
        Args:
            logs: List of log entries
        """
        st.title("System Logs")
        
        # Log Filters
        col1, col2 = st.columns(2)
        with col1:
            log_level = st.selectbox(
                "Log Level",
                ["ALL", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
            )
        with col2:
            date_range = st.date_input(
                "Date Range",
                value=(datetime.now().date(), datetime.now().date())
            )
            
        # Log Display
        if logs:
            df = pd.DataFrame(logs)
            st.dataframe(df)
            
        # Log Export
        if st.button("Export Logs"):
            df.to_csv("system_logs.csv", index=False)
            st.success("Logs exported successfully!")
            
    def run(self):
        """Run the admin UI."""
        st.sidebar.title("Navigation")
        page = st.sidebar.radio(
            "Go to",
            ["Dashboard", "Settings", "Analytics", "Logs"]
        )
        
        # Mock data for demonstration
        stats = {
            'active_threats': 5,
            'protected_emails': 1000,
            'system_health': 98,
            'recent_activity': [
                {'timestamp': '2024-03-20 10:00:00', 'event': 'Threat Detected', 'severity': 'High'},
                {'timestamp': '2024-03-20 09:45:00', 'event': 'Model Updated', 'severity': 'Info'},
            ],
            'threat_distribution': [
                {'type': 'Phishing', 'count': 60},
                {'type': 'Malware', 'count': 30},
                {'type': 'Spam', 'count': 10},
            ],
            'system_logs': "System running normally..."
        }
        
        settings = {
            'real_time_scanning': True,
            'ml_updates': True,
            'threat_intel': True,
            'scan_threshold': 80,
            'retrain_interval': 7,
            'confidence_threshold': 0.85,
            'api_key': '********',
            'db_url': 'postgresql://user:pass@localhost:5432/phishguard'
        }
        
        analytics = {
            'performance': pd.DataFrame({
                'timestamp': pd.date_range(start='2024-03-20', periods=24, freq='H'),
                'cpu_usage': [50, 55, 60, 65, 70, 75, 80, 85, 90, 85, 80, 75, 70, 65, 60, 55, 50, 45, 40, 35, 30, 25, 20, 15]
            }),
            'threats': pd.DataFrame({
                'type': ['Phishing', 'Malware', 'Spam'],
                'count': [60, 30, 10]
            }),
            'model_performance': pd.DataFrame({
                'timestamp': pd.date_range(start='2024-03-20', periods=24, freq='H'),
                'accuracy': [0.95, 0.96, 0.97, 0.98, 0.99, 0.98, 0.97, 0.96, 0.95, 0.94, 0.93, 0.92, 0.91, 0.90, 0.89, 0.88, 0.87, 0.86, 0.85, 0.84, 0.83, 0.82, 0.81, 0.80]
            })
        }
        
        logs = [
            {'timestamp': '2024-03-20 10:00:00', 'level': 'INFO', 'message': 'System started'},
            {'timestamp': '2024-03-20 10:01:00', 'level': 'WARNING', 'message': 'High CPU usage detected'},
            {'timestamp': '2024-03-20 10:02:00', 'level': 'ERROR', 'message': 'Database connection failed'}
        ]
        
        if page == "Dashboard":
            self.render_dashboard(stats)
        elif page == "Settings":
            self.render_settings(settings)
        elif page == "Analytics":
            self.render_analytics(analytics)
        elif page == "Logs":
            self.render_logs(logs)

if __name__ == "__main__":
    ui = AdminUI()
    ui.run() 