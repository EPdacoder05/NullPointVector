import logging
from typing import Dict, Any, List
from email.message import EmailMessage
import re
from urllib.parse import urlparse
import ipaddress
from pathlib import Path
import sys

# Add project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.append(str(project_root))

from utils.threat_intelligence import ThreatIntelligence

logger = logging.getLogger(__name__)

class EmailAnalyzer:
    def __init__(self):
        self.threat_intel = ThreatIntelligence()
        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        self.ip_pattern = re.compile(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        )

    def analyze_email(self, email: EmailMessage) -> Dict[str, Any]:
        """
        Analyze an email for potential threats.
        Returns a dictionary with analysis results.
        """
        analysis = {
            'email_id': email.get('Message-ID', ''),
            'from': email.get('From', ''),
            'subject': email.get('Subject', ''),
            'timestamp': email.get('Date', ''),
            'threat_score': 0.0,
            'threats': [],
            'urls': [],
            'ips': [],
            'recommendation': 'safe'
        }

        try:
            # Extract and analyze URLs
            urls = self._extract_urls(email)
            for url in urls:
                url_analysis = self.threat_intel.check_url(url)
                analysis['urls'].append({
                    'url': url,
                    'analysis': url_analysis
                })
                if self._is_threat(url_analysis):
                    analysis['threats'].append(f'Malicious URL detected: {url}')
                    analysis['threat_score'] += 0.4

            # Extract and analyze IPs
            ips = self._extract_ips(email)
            for ip in ips:
                ip_analysis = self.threat_intel.check_ip(ip)
                analysis['ips'].append({
                    'ip': ip,
                    'analysis': ip_analysis
                })
                if self._is_threat(ip_analysis):
                    analysis['threats'].append(f'Malicious IP detected: {ip}')
                    analysis['threat_score'] += 0.3

            # Analyze sender email
            sender = email.get('From', '')
            if sender:
                email_analysis = self.threat_intel.check_email(sender)
                if self._is_threat(email_analysis):
                    analysis['threats'].append(f'Suspicious sender: {sender}')
                    analysis['threat_score'] += 0.3

            # Set recommendation based on threat score
            if analysis['threat_score'] >= 0.7:
                analysis['recommendation'] = 'block'
            elif analysis['threat_score'] >= 0.4:
                analysis['recommendation'] = 'quarantine'
            else:
                analysis['recommendation'] = 'safe'

        except Exception as e:
            logger.error(f"Error analyzing email: {e}", exc_info=True)
            analysis['error'] = str(e)
            analysis['recommendation'] = 'quarantine'  # Default to quarantine on error

        return analysis

    def _extract_urls(self, email: EmailMessage) -> List[str]:
        """Extract URLs from email body and headers."""
        urls = set()
        
        # Check body
        if email.is_multipart():
            for part in email.walk():
                if part.get_content_type() == "text/plain":
                    urls.update(self.url_pattern.findall(part.get_payload(decode=True).decode()))
        else:
            urls.update(self.url_pattern.findall(email.get_payload(decode=True).decode()))

        # Check headers
        for header in ['From', 'To', 'Subject', 'Reply-To']:
            if email.get(header):
                urls.update(self.url_pattern.findall(email.get(header)))

        return list(urls)

    def _extract_ips(self, email: EmailMessage) -> List[str]:
        """Extract IP addresses from email headers."""
        ips = set()
        
        # Check headers that might contain IPs
        headers_to_check = ['Received', 'X-Originating-IP', 'X-Forwarded-For']
        for header in headers_to_check:
            if email.get(header):
                ips.update(self.ip_pattern.findall(email.get(header)))

        # Validate IPs
        valid_ips = []
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
                valid_ips.append(ip)
            except ValueError:
                continue

        return valid_ips

    def _is_threat(self, analysis: Dict[str, Any]) -> bool:
        """Determine if analysis results indicate a threat."""
        if analysis.get('status') != 'success':
            return False

        sources = analysis.get('sources', {})
        
        # Check PhishTank
        if 'phishtank' in sources:
            pt_data = sources['phishtank'].get('data', {})
            if pt_data.get('in_database', False):
                return True

        # Check AbuseIPDB
        if 'abuseipdb' in sources:
            abuse_data = sources['abuseipdb'].get('data', {})
            if abuse_data.get('abuseConfidenceScore', 0) > 50:
                return True

        return False 