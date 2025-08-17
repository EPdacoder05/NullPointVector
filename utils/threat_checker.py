import re
import logging
from typing import Dict, Any, List
import json
from pathlib import Path
import secrets

logger = logging.getLogger(__name__)

class ThreatChecker:
    """Simple threat checker for testing."""
    
    def __init__(self):
        self.known_threats = {
            'urls': [
                'malicious-site.com',
                'phishing-attempt.net',
                'suspicious-link.org'
            ],
            'senders': [
                'suspicious@malicious.com',
                'phishing@fake.net',
                'spam@unwanted.org'
            ],
            'ips': [
                '192.168.1.100',
                '10.0.0.1',
                '172.16.0.1'
            ]
        }
        
        # Load additional threats from file if exists
        self.threat_file = Path('data/threats.json')
        if self.threat_file.exists():
            try:
                with open(self.threat_file, 'r') as f:
                    additional_threats = json.load(f)
                    self.known_threats.update(additional_threats)
            except Exception as e:
                logger.error(f"Error loading threat database: {e}")
    
    def check_url(self, url: str) -> Dict[str, Any]:
        """Check if URL is known to be malicious."""
        for threat_url in self.known_threats['urls']:
            if threat_url in url:
                return {
                    'is_threat': True,
                    'confidence': 0.8,
                    'source': 'local_database',
                    'details': f'URL matches known threat pattern: {threat_url}'
                }
        return {'is_threat': False, 'confidence': 0.0, 'source': 'local_database'}
    
    def check_sender(self, sender: str) -> Dict[str, Any]:
        """Check if sender is known to be malicious."""
        # Extract email if present
        email_match = re.search(r'[\w\.-]+@[\w\.-]+', sender)
        if email_match:
            email = email_match.group(0)
            for threat_sender in self.known_threats['senders']:
                if threat_sender in email:
                    return {
                        'is_threat': True,
                        'confidence': 0.8,
                        'source': 'local_database',
                        'details': f'Sender matches known threat pattern: {threat_sender}'
                    }
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'\d{10}@',  # Phone number as email
            r'[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}',  # Generic email
            r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'  # Another generic pattern
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, sender):
                return {
                    'is_threat': True,
                    'confidence': 0.6,
                    'source': 'pattern_match',
                    'details': f'Sender matches suspicious pattern: {pattern}'
                }
        
        return {'is_threat': False, 'confidence': 0.0, 'source': 'local_database'}
    
    def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check if IP is known to be malicious."""
        for threat_ip in self.known_threats['ips']:
            if threat_ip == ip:
                return {
                    'is_threat': True,
                    'confidence': 0.8,
                    'source': 'local_database',
                    'details': f'IP matches known threat: {threat_ip}'
                }
        return {'is_threat': False, 'confidence': 0.0, 'source': 'local_database'}
    
    def add_threat(self, threat_type: str, value: str):
        """Add a new threat to the database."""
        if threat_type in self.known_threats:
            self.known_threats[threat_type].append(value)
            # Save to file
            try:
                self.threat_file.parent.mkdir(exist_ok=True)
                with open(self.threat_file, 'w') as f:
                    json.dump(self.known_threats, f, indent=2)
            except Exception as e:
                logger.error(f"Error saving threat database: {e}")

# Create global instance
threat_checker = ThreatChecker()

# Export convenience functions
def check_url(url: str) -> Dict[str, Any]:
    """Check if a URL is known to be malicious."""
    return threat_checker.check_url(url)

def check_sender(sender: str) -> Dict[str, Any]:
    """Check if a sender is known to be malicious."""
    return threat_checker.check_sender(sender)

def check_ip(ip: str) -> Dict[str, Any]:
    """Check if an IP is known to be malicious."""
    return threat_checker.check_ip(ip) 