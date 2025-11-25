import logging
import json
import subprocess
import smtplib
import os
import requests
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AlertManager:
    """
    Unified Alert System.
    Supports:
    1. Local Desktop Notifications (macOS Native)
    2. Email Alerts (SMTP)
    3. Webhooks (Slack/Discord/API)
    4. JSON History Log
    """
    
    def __init__(self):
        load_dotenv()
        self.alert_levels = {
            'critical': 3,
            'high': 2,
            'medium': 1,
            'low': 0
        }
        
        # Persistence
        self.alert_history_file = Path('data/intel_analytics/alert_history.json')
        self.alert_history_file.parent.mkdir(parents=True, exist_ok=True)
        self._load_alert_history()
        
        # Configuration
        self.enable_local = os.getenv('ALERT_ENABLE_LOCAL', 'true').lower() == 'true'
        self.enable_email = os.getenv('ALERT_ENABLE_EMAIL', 'false').lower() == 'true'
        self.enable_webhook = os.getenv('ALERT_ENABLE_WEBHOOK', 'false').lower() == 'true'

        # Email Config
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
        self.smtp_username = os.getenv('SMTP_USERNAME')
        self.smtp_password = os.getenv('SMTP_PASSWORD')
        self.alert_recipients = os.getenv('ALERT_RECIPIENTS', '').split(',')
        
        # Webhook Config
        self.webhook_url = os.getenv('ALERT_WEBHOOK_URL')
    
    def _load_alert_history(self):
        """Load alert history from file."""
        if self.alert_history_file.exists():
            try:
                with open(self.alert_history_file, 'r') as f:
                    self.alert_history = json.load(f)
            except json.JSONDecodeError:
                self.alert_history = []
        else:
            self.alert_history = []
    
    def _save_alert_history(self):
        """Save alert history to file."""
        try:
            with open(self.alert_history_file, 'w') as f:
                json.dump(self.alert_history, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save alert history: {e}")
    
    def create_alert(self, 
                    level: str,
                    source: str,
                    message: str,
                    details: Dict[str, Any],
                    timestamp: Optional[str] = None) -> Dict[str, Any]:
        """Create and dispatch a new alert."""
        if level not in self.alert_levels:
            level = 'medium' # Fallback
        
        alert = {
            'id': len(self.alert_history) + 1,
            'level': level,
            'source': source,
            'message': message,
            'details': details,
            'timestamp': timestamp or datetime.now().isoformat(),
            'status': 'new'
        }
        
        # 1. Save to History
        self.alert_history.append(alert)
        self._save_alert_history()
        
        # 2. Dispatch Notifications
        self._dispatch_notifications(alert)
        
        return alert
    
    def _dispatch_notifications(self, alert: Dict[str, Any]):
        """Route alert to enabled channels."""
        
        # Always log to console
        logger.info(f"🚨 ALERT [{alert['level'].upper()}]: {alert['message']}")

        # Channel 1: Local Desktop (macOS)
        if self.enable_local:
            self._send_local_notification(alert)

        # Channel 2: Email
        if self.enable_email and self.smtp_username:
            self._send_email_alert(alert)
        
        # Channel 3: Webhook
        if self.enable_webhook and self.webhook_url:
            self._send_webhook_alert(alert)

    def _send_local_notification(self, alert: Dict[str, Any]):
        """Send native macOS desktop notification."""
        try:
            # Escape quotes for AppleScript
            title = f"[{alert['level'].upper()}] {alert['source']}"
            msg = alert['message'].replace('"', '\\"')
            title = title.replace('"', '\\"')
            
            # Determine sound based on severity
            sound = "Ping"
            if alert['level'] == 'critical': sound = "Sosumi"
            elif alert['level'] == 'high': sound = "Glass"

            # Execute AppleScript via osascript
            script = f'display notification "{msg}" with title "{title}" sound name "{sound}"'
            subprocess.run(["osascript", "-e", script], check=False)
            
        except Exception as e:
            logger.error(f"Error sending local notification: {e}")

    def _send_email_alert(self, alert: Dict[str, Any]):
        """Send alert via email."""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.smtp_username
            msg['To'] = ', '.join(self.alert_recipients)
            msg['Subject'] = f"[{alert['level'].upper()}] Security Alert: {alert['source']}"
            
            body = f"""
            Security Alert Details:
            ---------------------
            Level: {alert['level']}
            Source: {alert['source']}
            Time: {alert['timestamp']}
            Message: {alert['message']}
            
            Details:
            {json.dumps(alert['details'], indent=2)}
            """
            msg.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
                
            logger.info(f"Email alert sent for ID {alert['id']}")
        except Exception as e:
            logger.error(f"Error sending email alert: {e}")
    
    def _send_webhook_alert(self, alert: Dict[str, Any]):
        """Send alert via webhook."""
        try:
            response = requests.post(
                self.webhook_url,
                json=alert,
                headers={'Content-Type': 'application/json'},
                timeout=5
            )
            response.raise_for_status()
        except Exception as e:
            logger.error(f"Error sending webhook alert: {e}")

    # --- Analytics Helpers ---

    def get_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent alerts."""
        return sorted(self.alert_history, key=lambda x: x['timestamp'], reverse=True)[:limit]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get simple alert statistics."""
        return {
            'total': len(self.alert_history),
            'critical': sum(1 for a in self.alert_history if a['level'] == 'critical'),
            'high': sum(1 for a in self.alert_history if a['level'] == 'high')
        }

# Singleton instance
alert_manager = AlertManager()