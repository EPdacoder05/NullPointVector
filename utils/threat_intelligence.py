# Local brain for Vector DB
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import json
from pathlib import Path

# Import your Vector DB connector
from Autobot.VectorDB.NullPoint_Vector import connect_db, insert_message, find_similar_messages

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatIntelligence:
    """
    Local-First Threat Intelligence Module.
    Uses Vector DB (Semantic Search) + Local Cache.
    No external API calls.
    """
    
    def __init__(self):
        """Initialize threat intelligence module."""
        self.cache_file = Path('data/threat_cache.json')
        self.cache = self._load_cache()
        self.db = connect_db()
        self.profiles = {}  # Sender behavioral profiles
        
    def _load_cache(self) -> Dict[str, Any]:
        """Load threat cache from file."""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading cache: {e}")
        return {'urls': {}, 'senders': {}}
        
    def _save_cache(self):
        """Save threat cache to file."""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f)
        except Exception as e:
            logger.error(f"Error saving cache: {e}")

    def check_url(self, url: str) -> bool:
        """
        Check if URL is malicious using Vector DB similarity.
        """
        # 1. Check Cache
        if url in self.cache['urls']:
            return self.cache['urls'][url]['is_threat']

        # 2. Check Vector DB (Semantic Search)
        # We treat the URL string as the "message" to embed
        is_threat = False
        try:
            similar_urls = find_similar_messages(self.db, url, limit=1)
            if similar_urls:
                # similar_urls returns tuples, index 5 is 'is_threat' (0 or 1)
                # Assuming schema: (id, type, sender, ..., is_threat, ...)
                # We need to ensure find_similar_messages returns the right column index
                # For now, let's assume if we find a VERY similar match that was a threat, this is too.
                top_match = similar_urls[0]
                # If similarity score (usually last item or separate) is high enough?
                # For now, let's trust the label of the nearest neighbor if it's a threat
                is_threat = bool(top_match[5]) # Adjust index based on your DB schema
        except Exception as e:
            logger.error(f"Vector DB lookup failed: {e}")

        # 3. Update Cache
        self.cache['urls'][url] = {
            'is_threat': is_threat,
            'timestamp': datetime.now().isoformat()
        }
        self._save_cache()
        
        return is_threat
        
    def check_sender(self, sender: str) -> bool:
        """
        Check if sender is malicious using Vector DB similarity.
        """
        # 1. Check Cache
        if sender in self.cache['senders']:
            return self.cache['senders'][sender]['is_threat']

        # 2. Check Vector DB
        is_threat = False
        try:
            similar_senders = find_similar_messages(self.db, sender, limit=1)
            if similar_senders:
                is_threat = bool(similar_senders[0][5]) # Adjust index based on schema
        except Exception as e:
            logger.error(f"Vector DB lookup failed: {e}")

        # 3. Update Cache
        self.cache['senders'][sender] = {
            'is_threat': is_threat,
            'timestamp': datetime.now().isoformat()
        }
        self._save_cache()
        
        return is_threat
        
    def add_threat(self, threat_type: str, identifier: str, metadata: Optional[Dict[str, Any]] = None):
        """
        Add a confirmed threat to the Vector DB (Training/Memory).
        """
        try:
            insert_message(
                self.db,
                message_type=threat_type, # 'url' or 'sender'
                sender=identifier if threat_type == 'sender' else None,
                raw_content=identifier, # The URL or Sender string is the content
                preprocessed_text=identifier,
                is_threat=1,
                confidence=1.0,
                metadata=metadata
            )
            logger.info(f"Added new threat to Vector DB: {threat_type} - {identifier}")
            
            # Also update cache immediately
            cache_key = 'urls' if threat_type == 'url' else 'senders'
            if cache_key in self.cache:
                self.cache[cache_key][identifier] = {
                    'is_threat': True,
                    'timestamp': datetime.now().isoformat()
                }
                self._save_cache()
                
        except Exception as e:
            logger.error(f"Error adding threat: {e}")
            
    def load_threats(self, file_path: str):
        """Load bulk threats from a JSON file."""
        try:
            with open(file_path, 'r') as f:
                threats = json.load(f)
                
            for threat in threats:
                t_type = threat.get('type')
                if not t_type:
                    logger.warning(f"Skipping malformed threat (missing type): {threat}")
                    continue
                    
                self.add_threat(
                    threat_type=t_type,
                    identifier=threat.get('identifier'),
                    metadata=threat.get('metadata')
                )
        except Exception as e:
            logger.error(f"Error loading threats: {e}")
    
    def build_profile(self, sender: str, subject: str, content: str) -> Dict[str, Any]:
        """
        Build or update behavioral profile for a sender.
        
        CONCEPT: Behavioral Profiling
        - Tracks sender patterns (volume, keywords, timing)
        - Detects anomalies (volume spikes, new suspicious keywords)
        - Returns threat score for reputation-based filtering
        """
        domain = sender.split('@')[-1] if '@' in sender else 'unknown'
        
        # Heuristic threat scoring
        threat_score = 0.0
        suspicious_words = ['urgent', 'verify', 'suspended', 'action required', 'click here']
        keyword_hits = sum(1 for word in suspicious_words if word in content.lower() or word in subject.lower())
        if keyword_hits > 0:
            threat_score += min(0.3, keyword_hits * 0.1)
        
        # Domain reputation
        suspicious_tlds = ['.ru', '.cn', '.top', '.xyz']
        if any(tld in domain for tld in suspicious_tlds):
            threat_score += 0.2
        
        # Update or create profile
        if sender in self.profiles:
            profile = self.profiles[sender]
            profile['email_count'] += 1
            profile['last_seen'] = datetime.now()
            profile['threat_score'] = (profile['threat_score'] * 0.8) + (threat_score * 0.2)
        else:
            self.profiles[sender] = {
                'email': sender,
                'domain': domain,
                'threat_score': threat_score,
                'email_count': 1,
                'first_seen': datetime.now(),
                'last_seen': datetime.now(),
                'geolocation': {}
            }
        
        return self.profiles[sender]
    
    def get_threat_profiles(self, threshold: float = 0.0):
        """Return profiles above threat threshold."""
        profiles = []
        for sender, data in self.profiles.items():
            if data['threat_score'] >= threshold:
                profiles.append(type('Profile', (), data)())
        return profiles
    
    def generate_intelligence_report(self):
        """Generate summary report for dashboard."""
        total = len(self.profiles)
        threat = sum(1 for p in self.profiles.values() if p['threat_score'] > 0.5)
        return {
            'total_profiles': total,
            'threat_profiles': threat,
            'reputation_summary': {
                'high_risk': sum(1 for p in self.profiles.values() if p['threat_score'] > 0.7),
                'medium_risk': sum(1 for p in self.profiles.values() if 0.3 < p['threat_score'] <= 0.7),
                'low_risk': total - threat
            },
            'domains_by_country': {},
            'common_patterns': {}
        }

# Create singleton instance
threat_intel = ThreatIntelligence()

# Export functions for easy access
def check_url(url: str) -> bool:
    return threat_intel.check_url(url)

def check_sender(sender: str) -> bool:
    return threat_intel.check_sender(sender)

def add_threat(threat_type: str, identifier: str, metadata: Optional[Dict[str, Any]] = None):
    threat_intel.add_threat(threat_type, identifier, metadata)

def load_threats(file_path: str):
    threat_intel.load_threats(file_path)

#Abstraction: Your fetchers (iPhone/Email) shouldn't know how to query the Vector DB. They should just ask threat_intel.check_url(url).
#Caching: Querying the DB for every single URL in a 10,000-message dump is slow. This file keeps a local JSON cache (data/threat_cache.json) to speed things up.
#Logic Hub: It's where you decide what counts as a match. (e.g., "If similarity > 0.85, flag it").