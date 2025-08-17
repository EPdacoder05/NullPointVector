import logging
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from dotenv import load_dotenv
import os

logger = logging.getLogger(__name__)

class AlertManager:
    def __init__(self):
        load_dotenv()
        self.alert_levels = {
            'critical': 3,
            'high': 2,
            'medium': 1,
            'low': 0
        }
        self.alert_history_file = Path('intel_analytics/alert_history.json')
        self.alert_history_file.parent.mkdir(exist_ok=True)
        self._load_alert_history()
        
        # Email configuration
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
        self.smtp_username = os.getenv('SMTP_USERNAME')
        self.smtp_password = os.getenv('SMTP_PASSWORD')
        self.alert_recipients = os.getenv('ALERT_RECIPIENTS', '').split(',')
        
        # Webhook configuration
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
        with open(self.alert_history_file, 'w') as f:
            json.dump(self.alert_history, f, indent=2)
    
    def create_alert(self, 
                    level: str,
                    source: str,
                    message: str,
                    details: Dict[str, Any],
                    timestamp: Optional[str] = None) -> Dict[str, Any]:
        """Create a new alert."""
        if level not in self.alert_levels:
            raise ValueError(f"Invalid alert level: {level}")
        
        alert = {
            'id': len(self.alert_history) + 1,
            'level': level,
            'source': source,
            'message': message,
            'details': details,
            'timestamp': timestamp or datetime.now().isoformat(),
            'status': 'new'
        }
        
        self.alert_history.append(alert)
        self._save_alert_history()
        
        # Send notifications
        self._send_notifications(alert)
        
        return alert
    
    def _send_notifications(self, alert: Dict[str, Any]):
        """Send notifications for the alert."""
        # Send email if configured
        if self.smtp_username and self.smtp_password and self.alert_recipients:
            self._send_email_alert(alert)
        
        # Send webhook if configured
        if self.webhook_url:
            self._send_webhook_alert(alert)
    
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
                
            logger.info(f"Email alert sent for alert ID {alert['id']}")
            
        except Exception as e:
            logger.error(f"Error sending email alert: {e}")
    
    def _send_webhook_alert(self, alert: Dict[str, Any]):
        """Send alert via webhook."""
        try:
            response = requests.post(
                self.webhook_url,
                json=alert,
                headers={'Content-Type': 'application/json'}
            )
            response.raise_for_status()
            logger.info(f"Webhook alert sent for alert ID {alert['id']}")
            
        except Exception as e:
            logger.error(f"Error sending webhook alert: {e}")
    
    def get_alerts(self, 
                  level: Optional[str] = None,
                  source: Optional[str] = None,
                  status: Optional[str] = None,
                  limit: int = 100) -> List[Dict[str, Any]]:
        """Get filtered alerts."""
        alerts = self.alert_history
        
        if level:
            alerts = [a for a in alerts if a['level'] == level]
        if source:
            alerts = [a for a in alerts if a['source'] == source]
        if status:
            alerts = [a for a in alerts if a['status'] == status]
        
        return sorted(alerts, key=lambda x: x['timestamp'], reverse=True)[:limit]
    
    def update_alert_status(self, alert_id: int, status: str):
        """Update alert status."""
        for alert in self.alert_history:
            if alert['id'] == alert_id:
                alert['status'] = status
                self._save_alert_history()
                return True
        return False
    
    def get_alert_stats(self) -> Dict[str, Any]:
        """Get alert statistics."""
        stats = {
            'total': len(self.alert_history),
            'by_level': {},
            'by_source': {},
            'by_status': {}
        }
        
        for alert in self.alert_history:
            # Count by level
            stats['by_level'][alert['level']] = stats['by_level'].get(alert['level'], 0) + 1
            
            # Count by source
            stats['by_source'][alert['source']] = stats['by_source'].get(alert['source'], 0) + 1
            
            # Count by status
            stats['by_status'][alert['status']] = stats['by_status'].get(alert['status'], 0) + 1
        
        return stats 