#!/usr/bin/env python3
"""
Threat Triage and Action System
Handles blocking, reporting, and categorizing threats
"""

import logging
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
import imaplib
import os
from dotenv import load_dotenv

logger = logging.getLogger(__name__)
load_dotenv()

class ThreatActionManager:
    """Manages threat triage actions: block, report, warn."""
    
    def __init__(self):
        self.actions_log = Path('data/threat_actions.json')
        self.blocked_senders = Path('data/blocked_senders.json')
        self.warned_senders = Path('data/warned_senders.json')
        self._load_data()
    
    def _load_data(self):
        """Load existing action data."""
        self.actions_log.parent.mkdir(parents=True, exist_ok=True)
        
        # Load blocked senders
        if self.blocked_senders.exists():
            with open(self.blocked_senders) as f:
                self.blocked = json.load(f)
        else:
            self.blocked = {}
        
        # Load warned senders
        if self.warned_senders.exists():
            with open(self.warned_senders) as f:
                self.warned = json.load(f)
        else:
            self.warned = {}
    
    def _save_data(self):
        """Save action data to disk."""
        with open(self.blocked_senders, 'w') as f:
            json.dump(self.blocked, f, indent=2)
        
        with open(self.warned_senders, 'w') as f:
            json.dump(self.warned, f, indent=2)
    
    def _log_action(self, action_type: str, threat_data: Dict[str, Any], reason: str):
        """Log an action for audit trail."""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action_type,
            'threat_id': threat_data.get('id'),
            'sender': threat_data.get('sender'),
            'subject': threat_data.get('subject'),
            'threat_score': threat_data.get('threat_score'),
            'reason': reason
        }
        
        # Append to log file
        with open(self.actions_log, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
        
        logger.info(f"🎯 Action logged: {action_type} - {threat_data.get('sender')}")
    
    def block_sender(self, threat_data: Dict[str, Any], reason: str = "High threat detected") -> bool:
        """
        Block a sender and move their emails to Phishy bizz folder.
        
        Args:
            threat_data: Threat information including sender, subject, etc.
            reason: Reason for blocking
        
        Returns:
            bool: Success status
        """
        sender = threat_data.get('sender')
        if not sender:
            logger.error("No sender specified for blocking")
            return False
        
        # Add to blocked list
        self.blocked[sender] = {
            'blocked_at': datetime.now().isoformat(),
            'reason': reason,
            'threat_score': threat_data.get('threat_score', 0),
            'email_id': threat_data.get('id')
        }
        self._save_data()
        
        # Move email to Phishy bizz folder
        success = self._move_to_phishy_bizz(threat_data)
        
        # Log action
        self._log_action('BLOCK', threat_data, reason)
        
        return success
    
    def warn_sender(self, threat_data: Dict[str, Any], warning_level: str = "MEDIUM") -> bool:
        """
        Mark sender for warning notifications.
        
        Args:
            threat_data: Threat information
            warning_level: LOW, MEDIUM, HIGH
        
        Returns:
            bool: Success status
        """
        sender = threat_data.get('sender')
        if not sender:
            return False
        
        self.warned[sender] = {
            'warned_at': datetime.now().isoformat(),
            'warning_level': warning_level,
            'threat_score': threat_data.get('threat_score', 0),
            'message': f"⚠️ Be careful opening emails from this sender"
        }
        self._save_data()
        
        self._log_action('WARN', threat_data, f"Warning level: {warning_level}")
        return True
    
    def report_threat(self, threat_data: Dict[str, Any], report_to: str = "internal") -> Dict[str, Any]:
        """
        Generate threat report for escalation.
        
        Args:
            threat_data: Threat information with headers
            report_to: "internal", "abuse@provider.com", or custom email
        
        Returns:
            dict: Report data with forensics
        """
        # Extract IP from Received headers
        ip_addresses = self._extract_ips_from_headers(threat_data.get('headers', {}))
        
        report = {
            'report_id': f"THR-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'timestamp': datetime.now().isoformat(),
            'sender': threat_data.get('sender'),
            'subject': threat_data.get('subject'),
            'threat_score': threat_data.get('threat_score'),
            'recipient': report_to,
            'forensics': {
                'originating_ips': ip_addresses,
                'return_path': threat_data.get('headers', {}).get('return_path'),
                'message_id': threat_data.get('headers', {}).get('message_id'),
                'authentication': threat_data.get('headers', {}).get('authentication_results'),
                'spf_result': threat_data.get('headers', {}).get('received_spf'),
                'dkim': threat_data.get('headers', {}).get('dkim_signature'),
            },
            'indicators': {
                'suspicious_links': threat_data.get('suspicious_urls', []),
                'phishing_keywords': threat_data.get('phishing_indicators', []),
                'ml_confidence': threat_data.get('confidence', 0)
            }
        }
        
        # Save report
        report_file = Path(f"data/reports/{report['report_id']}.json")
        report_file.parent.mkdir(parents=True, exist_ok=True)
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self._log_action('REPORT', threat_data, f"Report generated: {report['report_id']}")
        
        return report
    
    def _extract_ips_from_headers(self, headers: Dict[str, Any]) -> List[str]:
        """Extract IP addresses from Received headers."""
        import re
        ips = []
        
        # Check X-Originating-IP
        if headers.get('x_originating_ip'):
            ips.append(headers['x_originating_ip'])
        
        # Parse Received headers
        received_headers = headers.get('received', [])
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        for received in received_headers:
            found_ips = re.findall(ip_pattern, str(received))
            ips.extend(found_ips)
        
        return list(set(ips))  # Remove duplicates
    
    def _move_to_phishy_bizz(self, threat_data: Dict[str, Any]) -> bool:
        """Move email to Phishy bizz folder in Yahoo."""
        try:
            # Connect to Yahoo IMAP
            username = os.getenv('YAHOO_USER')
            password = os.getenv('YAHOO_PASS')
            
            mail = imaplib.IMAP4_SSL('imap.mail.yahoo.com')
            mail.login(username, password)
            
            # Select current folder (INBOX)
            mail.select('INBOX')
            
            # Get email ID from threat data
            email_id = threat_data.get('id')
            
            # COPY to Phishy bizz folder
            result = mail.copy(email_id, 'Phishy bizz')
            if result[0] == 'OK':
                # DELETE from INBOX (marks as deleted)
                mail.store(email_id, '+FLAGS', '\\Deleted')
                # EXPUNGE to permanently remove
                mail.expunge()
                logger.info(f"✅ Moved email {email_id} to Phishy bizz")
                return True
        except Exception as e:
            logger.error(f"Error moving email: {e}")
            return False
        finally:
            try:
                mail.logout()
            except:
                pass
    
    def get_blocked_senders(self) -> Dict[str, Any]:
        """Get list of blocked senders."""
        return self.blocked
    
    def get_warned_senders(self) -> Dict[str, Any]:
        """Get list of warned senders."""
        return self.warned
    
    def is_blocked(self, sender: str) -> bool:
        """Check if sender is blocked."""
        return sender in self.blocked
    
    def is_warned(self, sender: str) -> bool:
        """Check if sender has warning."""
        return sender in self.warned
    
    def get_action_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent action log entries."""
        if not self.actions_log.exists():
            return []
        
        logs = []
        with open(self.actions_log) as f:
            for line in f:
                try:
                    logs.append(json.loads(line))
                except:
                    continue
        
        return logs[-limit:]  # Return last N entries


# Singleton instance
threat_actions = ThreatActionManager()
