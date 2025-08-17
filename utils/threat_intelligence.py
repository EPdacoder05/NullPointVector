import os
import logging
import requests
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv
import json
from pathlib import Path
import secrets
import socket

from Autobot.VectorDB.NullPoint_Vector import connect_db, insert_message, find_similar_messages

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

class ThreatIntelligence:
    """Threat intelligence module for checking URLs, senders, and IPs."""
    
    def __init__(self):
        """Initialize threat intelligence module."""
        self.phish_tank_api_key = os.getenv('PHISHTANK_API_KEY')
        self.abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY')
        self.cache_file = Path('data/threat_cache.json')
        self.cache = self._load_cache()
        self.db = connect_db()
        
    def _load_cache(self) -> Dict[str, Any]:
        """Load threat cache from file."""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading cache: {e}")
        return {'urls': {}, 'senders': {}, 'ips': {}}
        
    def _save_cache(self):
        """Save threat cache to file."""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f)
        except Exception as e:
            logger.error(f"Error saving cache: {e}")
            
    def _check_abuseipdb(self, ip: str) -> bool:
        """Check IP against AbuseIPDB API."""
        if not self.abuseipdb_api_key:
            logger.warning("AbuseIPDB API key not set")
            return False
            
        try:
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                params={'ipAddress': ip},
                headers={'Key': self.abuseipdb_api_key}
            )
            if response.status_code == 200:
                data = response.json()
                return data.get('data', {}).get('abuseConfidenceScore', 0) > 50
        except Exception as e:
            logger.error(f"Error checking AbuseIPDB: {e}")
        return False
        
    def check_url(self, url: str) -> bool:
        """Check if URL is known to be malicious."""
        # Check cache first
        if url in self.cache['urls']:
            cache_entry = self.cache['urls'][url]
            if datetime.fromisoformat(cache_entry['timestamp']) > datetime.now() - timedelta(days=7):
                return cache_entry['is_threat']
                
        # Check PhishTank API
        if self.phish_tank_api_key:
            try:
                response = requests.post(
                    'https://checkurl.phishtank.com/checkurl/',
                    data={'url': url},
                    headers={'User-Agent': 'YahooPhish/1.0'}
                )
                if response.status_code == 200:
                    data = response.json()
                    is_threat = data.get('in_database', False)
                    
                    # Update cache
                    self.cache['urls'][url] = {
                        'is_threat': is_threat,
                        'timestamp': datetime.now().isoformat()
                    }
                    self._save_cache()
                    
                    return is_threat
            except Exception as e:
                logger.error(f"Error checking PhishTank: {e}")
                
        # Check local database for similar URLs
        similar_urls = find_similar_messages(self.db, url, message_type='url')
        if similar_urls:
            return any(url[5] for url in similar_urls)  # Check is_threat field
            
        return False
        
    def check_sender(self, sender: str) -> bool:
        """Check if sender (email or phone) is known to be malicious."""
        # Check cache first
        if sender in self.cache['senders']:
            cache_entry = self.cache['senders'][sender]
            if datetime.fromisoformat(cache_entry['timestamp']) > datetime.now() - timedelta(days=7):
                return cache_entry['is_threat']
                
        # Extract IP if present
        if '@' in sender:
            domain = sender.split('@')[1]
            try:
                ip = socket.gethostbyname(domain)
                if self._check_abuseipdb(ip):
                    return True
            except Exception as e:
                logger.error(f"Error resolving domain: {e}")
                
        # Check local database for similar senders
        similar_senders = find_similar_messages(self.db, sender, message_type='sender')
        if similar_senders:
            return any(sender[5] for sender in similar_senders)  # Check is_threat field
            
        return False
        
    def add_threat(self, threat_type: str, identifier: str, metadata: Optional[Dict[str, Any]] = None):
        """Add a new threat to the database."""
        try:
            insert_message(
                self.db,
                message_type=threat_type,
                sender=identifier if threat_type == 'sender' else None,
                raw_content=identifier,
                preprocessed_text=identifier,
                is_threat=1,
                confidence=1.0,
                metadata=metadata
            )
            logger.info(f"Added new threat: {threat_type} - {identifier}")
        except Exception as e:
            logger.error(f"Error adding threat: {e}")
            
    def load_threats(self, file_path: str):
        """Load additional threats from a JSON file."""
        try:
            with open(file_path, 'r') as f:
                threats = json.load(f)
                
            for threat in threats:
                self.add_threat(
                    threat_type=threat['type'],
                    identifier=threat['identifier'],
                    metadata=threat.get('metadata')
                )
        except Exception as e:
            logger.error(f"Error loading threats: {e}")

# Create singleton instance
threat_intel = ThreatIntelligence()

# Export functions for easy access
def check_url(url: str) -> bool:
    """Check if URL is known to be malicious."""
    return threat_intel.check_url(url)

def check_sender(sender: str) -> bool:
    """Check if sender is known to be malicious."""
    return threat_intel.check_sender(sender)

def add_threat(threat_type: str, identifier: str, metadata: Optional[Dict[str, Any]] = None):
    """Add a new threat to the database."""
    threat_intel.add_threat(threat_type, identifier, metadata)

def load_threats(file_path: str):
    """Load additional threats from a JSON file."""
    threat_intel.load_threats(file_path) 