import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
import json
import csv
from jinja2 import Template
import sqlite3
from .alert_manager import AlertManager

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self):
        self.alert_manager = AlertManager()
        self.reports_dir = Path('intel_analytics/reports')
        self.reports_dir.mkdir(exist_ok=True)
        
        # Load report template
        self.template = Template("""
        Security Report: {{ period }}
        Generated: {{ generated_at }}
        
        Summary
        -------
        Total Alerts: {{ stats.total }}
        Critical: {{ stats.by_level.critical|default(0) }}
        High: {{ stats.by_level.high|default(0) }}
        Medium: {{ stats.by_level.medium|default(0) }}
        Low: {{ stats.by_level.low|default(0) }}
        
        Alert Status
        ------------
        {% for status, count in stats.by_status.items() %}
        {{ status }}: {{ count }}
        {% endfor %}
        
        Recent Alerts
        ------------
        {% for alert in recent_alerts %}
        [{{ alert.level.upper() }}] {{ alert.timestamp }} - {{ alert.source }}
        Message: {{ alert.message }}
        Status: {{ alert.status }}
        {% endfor %}
        """)
    
    def generate_daily_report(self, date: Optional[datetime] = None) -> Dict[str, Any]:
        """Generate daily security report."""
        if date is None:
            date = datetime.now()
        
        start_time = date.replace(hour=0, minute=0, second=0, microsecond=0)
        end_time = start_time + timedelta(days=1)
        
        # Get alerts for the day
        alerts = self.alert_manager.get_alerts()
        daily_alerts = [
            alert for alert in alerts
            if start_time <= datetime.fromisoformat(alert['timestamp']) < end_time
        ]
        
        # Generate report
        report = {
            'period': f"Daily Report - {date.strftime('%Y-%m-%d')}",
            'generated_at': datetime.now().isoformat(),
            'stats': self.alert_manager.get_alert_stats(),
            'recent_alerts': daily_alerts[:10]  # Show last 10 alerts
        }
        
        # Save report
        self._save_report(report, f"daily_{date.strftime('%Y%m%d')}")
        
        return report
    
    def generate_weekly_report(self, date: Optional[datetime] = None) -> Dict[str, Any]:
        """Generate weekly security report."""
        if date is None:
            date = datetime.now()
        
        # Find start of week (Monday)
        start_time = date - timedelta(days=date.weekday())
        start_time = start_time.replace(hour=0, minute=0, second=0, microsecond=0)
        end_time = start_time + timedelta(days=7)
        
        # Get alerts for the week
        alerts = self.alert_manager.get_alerts()
        weekly_alerts = [
            alert for alert in alerts
            if start_time <= datetime.fromisoformat(alert['timestamp']) < end_time
        ]
        
        # Generate report
        report = {
            'period': f"Weekly Report - {start_time.strftime('%Y-%m-%d')} to {end_time.strftime('%Y-%m-%d')}",
            'generated_at': datetime.now().isoformat(),
            'stats': self.alert_manager.get_alert_stats(),
            'recent_alerts': weekly_alerts[:20]  # Show last 20 alerts
        }
        
        # Save report
        self._save_report(report, f"weekly_{start_time.strftime('%Y%m%d')}")
        
        return report
    
    def _save_report(self, report: Dict[str, Any], filename: str):
        """Save report in multiple formats."""
        # Save as JSON
        json_path = self.reports_dir / f"{filename}.json"
        with open(json_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Save as CSV
        csv_path = self.reports_dir / f"{filename}.csv"
        with open(csv_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Period', report['period']])
            writer.writerow(['Generated At', report['generated_at']])
            writer.writerow([])
            writer.writerow(['Summary'])
            writer.writerow(['Total Alerts', report['stats']['total']])
            for level, count in report['stats']['by_level'].items():
                writer.writerow([level.capitalize(), count])
            writer.writerow([])
            writer.writerow(['Alert Status'])
            for status, count in report['stats']['by_status'].items():
                writer.writerow([status, count])
            writer.writerow([])
            writer.writerow(['Recent Alerts'])
            writer.writerow(['Level', 'Timestamp', 'Source', 'Message', 'Status'])
            for alert in report['recent_alerts']:
                writer.writerow([
                    alert['level'],
                    alert['timestamp'],
                    alert['source'],
                    alert['message'],
                    alert['status']
                ])
        
        # Save as text
        text_path = self.reports_dir / f"{filename}.txt"
        with open(text_path, 'w') as f:
            f.write(self.template.render(**report))
        
        logger.info(f"Report saved as {filename} in multiple formats")
    
    def get_report_history(self) -> List[Dict[str, Any]]:
        """Get list of available reports."""
        reports = []
        for file in self.reports_dir.glob('*.json'):
            try:
                with open(file, 'r') as f:
                    report = json.load(f)
                    reports.append({
                        'filename': file.stem,
                        'period': report['period'],
                        'generated_at': report['generated_at']
                    })
            except Exception as e:
                logger.error(f"Error reading report {file}: {e}")
        
        return sorted(reports, key=lambda x: x['generated_at'], reverse=True)
    
    def export_report(self, filename: str, format: str = 'json') -> Optional[bytes]:
        """Export report in specified format."""
        try:
            if format == 'json':
                with open(self.reports_dir / f"{filename}.json", 'rb') as f:
                    return f.read()
            elif format == 'csv':
                with open(self.reports_dir / f"{filename}.csv", 'rb') as f:
                    return f.read()
            elif format == 'txt':
                with open(self.reports_dir / f"{filename}.txt", 'rb') as f:
                    return f.read()
            else:
                raise ValueError(f"Unsupported format: {format}")
        except Exception as e:
            logger.error(f"Error exporting report {filename}: {e}")
            return None 