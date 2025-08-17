import requests
import logging
from typing import Dict, List, Any, Optional
import json
from datetime import datetime, timedelta
import sqlite3
from pathlib import Path
import os
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

class ThreatIntelligence:
    def __init__(self):
        load_dotenv()
        self.api_keys = {
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
            'abuseipdb': os.getenv('ABUSEIPDB_API_KEY'),
            'phishtank': os.getenv('PHISHTANK_API_KEY')
        }
        self.db_path = Path('intel_analytics/threat_intel.db')
        self.db_path.parent.mkdir(exist_ok=True)
        self._setup_db()
    
    def _setup_db(self):
        """Set up threat intelligence database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT,
                value TEXT,
                source TEXT,
                confidence REAL,
                first_seen TEXT,
                last_seen TEXT,
                details TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reputation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_id INTEGER,
                source TEXT,
                score REAL,
                timestamp TEXT,
                FOREIGN KEY (indicator_id) REFERENCES indicators (id)
            )
        """)
        
        conn.commit()
        conn.close()
    
    def check_url(self, url: str) -> Dict[str, Any]:
        """Check URL against threat intelligence sources."""
        results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'sources': {}
        }
        
        # Check VirusTotal
        if self.api_keys['virustotal']:
            vt_result = self._check_virustotal(url)
            results['sources']['virustotal'] = vt_result
        
        # Check PhishTank
        if self.api_keys['phishtank']:
            pt_result = self._check_phishtank(url)
            results['sources']['phishtank'] = pt_result
        
        # Store results
        self._store_indicator('url', url, results)
        
        return results
    
    def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP against threat intelligence sources."""
        results = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'sources': {}
        }
        
        # Check VirusTotal
        if self.api_keys['virustotal']:
            vt_result = self._check_virustotal(ip)
            results['sources']['virustotal'] = vt_result
        
        # Check AbuseIPDB
        if self.api_keys['abuseipdb']:
            abuse_result = self._check_abuseipdb(ip)
            results['sources']['abuseipdb'] = abuse_result
        
        # Store results
        self._store_indicator('ip', ip, results)
        
        return results
    
    def check_email(self, email: str) -> Dict[str, Any]:
        """Check email against threat intelligence sources."""
        results = {
            'email': email,
            'timestamp': datetime.now().isoformat(),
            'sources': {}
        }
        
        # Check VirusTotal
        if self.api_keys['virustotal']:
            vt_result = self._check_virustotal(email)
            results['sources']['virustotal'] = vt_result
        
        # Store results
        self._store_indicator('email', email, results)
        
        return results
    
    def _check_virustotal(self, indicator: str) -> Dict[str, Any]:
        """Check indicator against VirusTotal."""
        try:
            headers = {
                'x-apikey': self.api_keys['virustotal']
            }
            
            # Get report
            response = requests.get(
                f'https://www.virustotal.com/api/v3/search?query={indicator}',
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'status': 'success',
                    'data': data
                }
            else:
                return {
                    'status': 'error',
                    'error': f"HTTP {response.status_code}"
                }
                
        except Exception as e:
            logger.error(f"Error checking VirusTotal: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _check_phishtank(self, url: str) -> Dict[str, Any]:
        """Check URL against PhishTank."""
        try:
            response = requests.get(
                f'https://checkurl.phishtank.com/checkurl/',
                params={'url': url}
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'status': 'success',
                    'data': data
                }
            else:
                return {
                    'status': 'error',
                    'error': f"HTTP {response.status_code}"
                }
                
        except Exception as e:
            logger.error(f"Error checking PhishTank: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _check_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Check IP against AbuseIPDB."""
        try:
            headers = {
                'Key': self.api_keys['abuseipdb'],
                'Accept': 'application/json'
            }
            
            response = requests.get(
                f'https://api.abuseipdb.com/api/v2/check',
                params={'ipAddress': ip},
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'status': 'success',
                    'data': data
                }
            else:
                return {
                    'status': 'error',
                    'error': f"HTTP {response.status_code}"
                }
                
        except Exception as e:
            logger.error(f"Error checking AbuseIPDB: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _store_indicator(self, indicator_type: str, value: str, results: Dict[str, Any]):
        """Store indicator and results in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Insert indicator
            cursor.execute("""
                INSERT INTO indicators (type, value, source, confidence, first_seen, last_seen, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                indicator_type,
                value,
                'threat_intel',
                0.0,  # Initial confidence
                datetime.now().isoformat(),
                datetime.now().isoformat(),
                json.dumps(results)
            ))
            
            indicator_id = cursor.lastrowid
            
            # Store reputation scores
            for source, result in results['sources'].items():
                if result['status'] == 'success':
                    score = self._extract_score(source, result['data'])
                    if score is not None:
                        cursor.execute("""
                            INSERT INTO reputation (indicator_id, source, score, timestamp)
                            VALUES (?, ?, ?, ?)
                        """, (
                            indicator_id,
                            source,
                            score,
                            datetime.now().isoformat()
                        ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error storing indicator: {e}")
    
    def _extract_score(self, source: str, data: Dict[str, Any]) -> Optional[float]:
        """Extract reputation score from source data."""
        try:
            if source == 'virustotal':
                return data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) / 100.0
            elif source == 'abuseipdb':
                return data.get('data', {}).get('abuseConfidenceScore', 0) / 100.0
            elif source == 'phishtank':
                return 1.0 if data.get('data', {}).get('in_database', False) else 0.0
            return None
        except Exception as e:
            logger.error(f"Error extracting score: {e}")
            return None
    
    def get_reputation(self, indicator_type: str, value: str) -> Dict[str, Any]:
        """Get reputation for an indicator."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT i.*, r.source, r.score, r.timestamp
                FROM indicators i
                LEFT JOIN reputation r ON i.id = r.indicator_id
                WHERE i.type = ? AND i.value = ?
                ORDER BY r.timestamp DESC
            """, (indicator_type, value))
            
            rows = cursor.fetchall()
            conn.close()
            
            if not rows:
                return {
                    'status': 'not_found',
                    'indicator': value,
                    'type': indicator_type
                }
            
            # Process results
            indicator = {
                'id': rows[0][0],
                'type': rows[0][1],
                'value': rows[0][2],
                'first_seen': rows[0][5],
                'last_seen': rows[0][6],
                'details': json.loads(rows[0][7]),
                'reputation': {}
            }
            
            for row in rows:
                if row[8]:  # source
                    indicator['reputation'][row[8]] = {
                        'score': row[9],
                        'timestamp': row[10]
                    }
            
            return {
                'status': 'success',
                'data': indicator
            }
            
        except Exception as e:
            logger.error(f"Error getting reputation: {e}")
            return {
                'status': 'error',
                'error': str(e)
            } 