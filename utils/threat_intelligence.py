# Local brain for Vector DB
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import json
import os
from pathlib import Path

# Import your Vector DB connector
from Autobot.VectorDB.NullPoint_Vector import get_conn, release_conn, insert_message, find_similar_messages
from common.redis_client import get_redis
from common.tenant_rls import require_account_sub

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
        self.redis = get_redis()
        self.cache_ttl_seconds = int(os.getenv('THREAT_CACHE_TTL_SECONDS', '86400'))
        self.profiles = {}  # Sender behavioral profiles

    def _cache_bucket(self, threat_type: str) -> str:
        return 'urls' if threat_type == 'url' else 'senders'

    def _cache_get(self, account_sub: str, bucket: str, key: str) -> Optional[bool]:
        tenant_key = f"{account_sub}:{key}"
        entry = self.cache.get(bucket, {}).get(tenant_key)
        if entry:
            age = datetime.now() - datetime.fromisoformat(entry.get('timestamp', '2000-01-01T00:00:00'))
            if age.total_seconds() <= self.cache_ttl_seconds:
                return bool(entry.get('is_threat'))

        if self.redis is not None:
            raw = self.redis.get(f"threat:{account_sub}:{bucket}:{key}")
            if raw:
                try:
                    data = json.loads(raw)
                    return bool(data.get('is_threat'))
                except Exception:
                    return None
        return None

    def _cache_set(self, account_sub: str, bucket: str, key: str, is_threat: bool):
        tenant_key = f"{account_sub}:{key}"
        payload = {
            'is_threat': bool(is_threat),
            'timestamp': datetime.now().isoformat(),
        }
        self.cache.setdefault(bucket, {})[tenant_key] = payload
        self._save_cache()
        if self.redis is not None:
            try:
                self.redis.setex(
                    f"threat:{account_sub}:{bucket}:{key}",
                    self.cache_ttl_seconds,
                    json.dumps(payload),
                )
            except Exception as e:
                logger.debug(f"Redis cache write failed: {e}")
        
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

    def check_url(self, url: str, *, account_sub: Optional[str] = None) -> bool:
        """
        Check if URL is malicious using external feeds + Vector DB similarity.
        """
        # Tenantless legacy callers may use vendor reputation, but must not
        # read or populate another customer's learned cache/Vector DB memory.
        tenant = require_account_sub(account_sub) if account_sub else None
        if tenant:
            cached = self._cache_get(tenant, 'urls', url)
            if cached is not None:
                return cached

        # 2. External feeds (URLhaus + IPQS) — fail-open
        is_threat = False
        try:
            from common.reputation.intel import scan_url_external
            hit = scan_url_external(url)
            if hit and hit.get("risk", 0) >= 0.5:
                is_threat = True
                if tenant:
                    self._cache_set(tenant, 'urls', url, is_threat)
                return is_threat
        except Exception as e:
            logger.debug(f"External URL intel skipped: {e}")

        # 3. Check Vector DB (Semantic Search)
        # We treat the URL string as the "message" to embed
        is_threat = False
        try:
            if not tenant:
                return is_threat
            conn = get_conn()
            if conn is not None:
                try:
                    similar_urls = find_similar_messages(
                        conn, url, limit=1, account_sub=tenant,
                    )
                    if similar_urls:
                        top_match = similar_urls[0]
                        is_threat = bool(top_match[5])
                finally:
                    release_conn(conn)
        except Exception as e:
            logger.error(f"Vector DB lookup failed: {e}")

        # 3. Update Cache
        if tenant:
            self._cache_set(tenant, 'urls', url, is_threat)
        
        return is_threat
        
    def check_sender(self, sender: str, *, account_sub: Optional[str] = None) -> bool:
        """
        Check if sender is malicious using Vector DB similarity.
        """
        tenant = require_account_sub(account_sub) if account_sub else None
        if not tenant:
            return False

        # 1. Check Cache
        cached = self._cache_get(tenant, 'senders', sender)
        if cached is not None:
            return cached

        # 2. Check Vector DB
        is_threat = False
        try:
            conn = get_conn()
            if conn is not None:
                try:
                    similar_senders = find_similar_messages(
                        conn, sender, limit=1, account_sub=tenant,
                    )
                    if similar_senders:
                        is_threat = bool(similar_senders[0][5])
                finally:
                    release_conn(conn)
        except Exception as e:
            logger.error(f"Vector DB lookup failed: {e}")

        # 3. Update Cache
        self._cache_set(tenant, 'senders', sender, is_threat)
        
        return is_threat
        
    def add_threat(self, threat_type: str, identifier: str,
                   metadata: Optional[Dict[str, Any]] = None, *,
                   account_sub: str):
        """
        Add a confirmed threat to the Vector DB (Training/Memory).
        """
        tenant = require_account_sub(account_sub)
        conn = None
        try:
            conn = get_conn()
            if conn is None:
                raise RuntimeError("Unable to acquire pooled DB connection")
            insert_message(
                conn,
                message_type=threat_type, # 'url' or 'sender'
                sender=identifier if threat_type == 'sender' else None,
                raw_content=identifier, # The URL or Sender string is the content
                preprocessed_text=identifier,
                is_threat=1,
                confidence=1.0,
                metadata=metadata,
                account_sub=tenant,
            )
            logger.info(f"Added new threat to Vector DB: {threat_type} - {identifier}")
            
            # Also update cache immediately
            self._cache_set(
                tenant, self._cache_bucket(threat_type), identifier, True,
            )
                
        except Exception as e:
            logger.error(f"Error adding threat: {e}")
        finally:
            release_conn(conn)
            
    def load_threats(self, file_path: str, *, account_sub: str):
        """Load bulk threats from a JSON file."""
        tenant = require_account_sub(account_sub)
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
                    metadata=threat.get('metadata'),
                    account_sub=tenant,
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
def check_url(url: str, *, account_sub: Optional[str] = None) -> bool:
    return threat_intel.check_url(url, account_sub=account_sub)

def check_sender(sender: str, *, account_sub: Optional[str] = None) -> bool:
    return threat_intel.check_sender(sender, account_sub=account_sub)

def add_threat(threat_type: str, identifier: str,
               metadata: Optional[Dict[str, Any]] = None, *,
               account_sub: str):
    threat_intel.add_threat(
        threat_type, identifier, metadata, account_sub=account_sub,
    )

def load_threats(file_path: str, *, account_sub: str):
    threat_intel.load_threats(file_path, account_sub=account_sub)

#Abstraction: Your fetchers (iPhone/Email) shouldn't know how to query the Vector DB. They should just ask threat_intel.check_url(url).
#Caching: Querying the DB for every single URL in a 10,000-message dump is slow. This file keeps a local JSON cache (data/threat_cache.json) to speed things up.
#Logic Hub: It's where you decide what counts as a match. (e.g., "If similarity > 0.85, flag it").
