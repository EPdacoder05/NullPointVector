#!/usr/bin/env python3
"""
Offensive Intelligence Module
Builds profiles of senders and conducts reconnaissance.
"""

import os
import requests
import dns.resolver
import whois
import socket
import re
import json
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class SenderProfile:
    """Profile of a sender with intelligence data."""
    email: str
    domain: str
    first_seen: datetime
    last_seen: datetime
    email_count: int
    threat_score: float
    categories: List[str]
    dns_records: Dict[str, List[str]]
    whois_data: Dict[str, Any]
    ip_addresses: List[str]
    geolocation: Dict[str, Any]
    reputation_data: Dict[str, Any]
    associated_domains: List[str]
    patterns: List[str]

class OffensiveIntelligence:
    """Offensive intelligence gathering and profiling."""
    
    def __init__(self):
        self.profiles_db = Path('data/sender_profiles.json')
        self.profiles_db.parent.mkdir(exist_ok=True)
        self.profiles = self._load_profiles()
        
        # Threat intelligence APIs
        self.virustotal_api = os.getenv('VIRUSTOTAL_API_KEY')
        self.abuseipdb_api = os.getenv('ABUSEIPDB_API_KEY')
        self.shodan_api = os.getenv('SHODAN_API_KEY')
        
        # User agents for requests
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    def _load_profiles(self) -> Dict[str, SenderProfile]:
        """Load existing sender profiles."""
        if self.profiles_db.exists():
            try:
                with open(self.profiles_db, 'r') as f:
                    data = json.load(f)
                    profiles = {}
                    for email, profile_data in data.items():
                        profile_data['first_seen'] = datetime.fromisoformat(profile_data['first_seen'])
                        profile_data['last_seen'] = datetime.fromisoformat(profile_data['last_seen'])
                        profiles[email] = SenderProfile(**profile_data)
                    return profiles
            except Exception as e:
                logger.error(f"Error loading profiles: {e}")
        return {}
    
    def _save_profiles(self):
        """Save sender profiles to file."""
        try:
            data = {}
            for email, profile in self.profiles.items():
                profile_dict = {
                    'email': profile.email,
                    'domain': profile.domain,
                    'first_seen': profile.first_seen.isoformat(),
                    'last_seen': profile.last_seen.isoformat(),
                    'email_count': profile.email_count,
                    'threat_score': profile.threat_score,
                    'categories': profile.categories,
                    'dns_records': profile.dns_records,
                    'whois_data': profile.whois_data,
                    'ip_addresses': profile.ip_addresses,
                    'geolocation': profile.geolocation,
                    'reputation_data': profile.reputation_data,
                    'associated_domains': profile.associated_domains,
                    'patterns': profile.patterns
                }
                data[email] = profile_dict
            
            with open(self.profiles_db, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving profiles: {e}")
    
    def extract_domain(self, email: str) -> str:
        """Extract domain from email address."""
        return email.split('@')[1] if '@' in email else email
    
    def dns_reconnaissance(self, domain: str) -> Dict[str, List[str]]:
        """Conduct DNS reconnaissance on domain."""
        dns_data = {}
        
        try:
            # A records
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                dns_data['A'] = [str(record) for record in a_records]
            except:
                dns_data['A'] = []
            
            # MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                dns_data['MX'] = [str(record.exchange) for record in mx_records]
            except:
                dns_data['MX'] = []
            
            # TXT records
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                dns_data['TXT'] = [str(record) for record in txt_records]
            except:
                dns_data['TXT'] = []
            
            # SPF records
            try:
                spf_records = dns.resolver.resolve(domain, 'TXT')
                dns_data['SPF'] = [str(record) for record in spf_records if 'v=spf1' in str(record)]
            except:
                dns_data['SPF'] = []
            
            # NS records
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                dns_data['NS'] = [str(record) for record in ns_records]
            except:
                dns_data['NS'] = []
                
        except Exception as e:
            logger.error(f"DNS reconnaissance failed for {domain}: {e}")
            dns_data = {}
        
        return dns_data
    
    def whois_reconnaissance(self, domain: str) -> Dict[str, Any]:
        """Conduct WHOIS reconnaissance on domain."""
        try:
            w = whois.whois(domain)
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'updated_date': str(w.updated_date),
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'org': w.org,
                'country': w.country
            }
        except Exception as e:
            logger.error(f"WHOIS reconnaissance failed for {domain}: {e}")
            return {}
    
    def ip_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get geolocation data for IP address."""
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country'),
                    'region': data.get('regionName'),
                    'city': data.get('city'),
                    'isp': data.get('isp'),
                    'org': data.get('org'),
                    'timezone': data.get('timezone'),
                    'lat': data.get('lat'),
                    'lon': data.get('lon')
                }
        except Exception as e:
            logger.error(f"Geolocation failed for {ip}: {e}")
        return {}
    
    def check_reputation(self, domain: str, ip: str = None) -> Dict[str, Any]:
        """Check domain and IP reputation."""
        reputation = {}
        
        # Check VirusTotal
        if self.virustotal_api and domain:
            try:
                url = f'https://www.virustotal.com/vtapi/v2/domain/report'
                params = {'apikey': self.virustotal_api, 'domain': domain}
                response = requests.get(url, params=params, headers=self.headers)
                if response.status_code == 200:
                    vt_data = response.json()
                    reputation['virustotal'] = {
                        'positives': vt_data.get('positives', 0),
                        'total': vt_data.get('total', 0),
                        'categories': vt_data.get('categories', {}),
                        'detected_urls': len(vt_data.get('detected_urls', []))
                    }
            except Exception as e:
                logger.error(f"VirusTotal check failed: {e}")
        
        # Check AbuseIPDB
        if self.abuseipdb_api and ip:
            try:
                url = 'https://api.abuseipdb.com/api/v2/check'
                params = {'ipAddress': ip}
                headers = {'Key': self.abuseipdb_api, 'Accept': 'application/json'}
                response = requests.get(url, params=params, headers=headers)
                if response.status_code == 200:
                    abuse_data = response.json()
                    reputation['abuseipdb'] = {
                        'abuse_confidence_score': abuse_data.get('data', {}).get('abuseConfidenceScore', 0),
                        'country_code': abuse_data.get('data', {}).get('countryCode'),
                        'usage_type': abuse_data.get('data', {}).get('usageType')
                    }
            except Exception as e:
                logger.error(f"AbuseIPDB check failed: {e}")
        
        return reputation
    
    def analyze_patterns(self, emails: List[Dict[str, Any]]) -> List[str]:
        """Analyze patterns in emails from the same sender."""
        patterns = []
        
        if len(emails) < 2:
            return patterns
        
        # Time patterns
        times = [email.get('date') for email in emails if email.get('date')]
        if times:
            # Check for consistent sending times
            hour_counts = {}
            for time_str in times:
                try:
                    hour = datetime.fromisoformat(time_str.replace('Z', '+00:00')).hour
                    hour_counts[hour] = hour_counts.get(hour, 0) + 1
                except:
                    continue
            
            if hour_counts:
                most_common_hour = max(hour_counts, key=hour_counts.get)
                if hour_counts[most_common_hour] > len(times) * 0.5:
                    patterns.append(f"Consistent sending time: {most_common_hour}:00")
        
        # Content patterns
        subjects = [email.get('subject', '').lower() for email in emails]
        bodies = [email.get('body', '').lower() for email in emails]
        
        # Check for common keywords
        common_words = ['urgent', 'verify', 'account', 'payment', 'click', 'suspended']
        for word in common_words:
            if any(word in subject for subject in subjects):
                patterns.append(f"Common keyword in subjects: '{word}'")
        
        # Check for URL patterns
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = []
        for body in bodies:
            urls.extend(re.findall(url_pattern, body))
        
        if urls:
            domains = [re.search(r'https?://([^/]+)', url).group(1) for url in urls if re.search(r'https?://([^/]+)', url)]
            if len(set(domains)) == 1:
                patterns.append(f"Consistent URL domain: {domains[0]}")
        
        return patterns
    
    def build_profile(self, sender: str, emails: List[Dict[str, Any]]) -> SenderProfile:
        """Build comprehensive profile of a sender."""
        domain = self.extract_domain(sender)
        now = datetime.now()
        
        # Check if profile exists
        if sender in self.profiles:
            profile = self.profiles[sender]
            profile.last_seen = now
            profile.email_count += len(emails)
        else:
            profile = SenderProfile(
                email=sender,
                domain=domain,
                first_seen=now,
                last_seen=now,
                email_count=len(emails),
                threat_score=0.0,
                categories=[],
                dns_records={},
                whois_data={},
                ip_addresses=[],
                geolocation={},
                reputation_data={},
                associated_domains=[],
                patterns=[]
            )
        
        # Conduct reconnaissance
        logger.info(f"Conducting reconnaissance on {domain}")
        
        # DNS reconnaissance
        profile.dns_records = self.dns_reconnaissance(domain)
        
        # WHOIS reconnaissance
        profile.whois_data = self.whois_reconnaissance(domain)
        
        # Get IP addresses from DNS
        if profile.dns_records.get('A'):
            profile.ip_addresses = profile.dns_records['A']
            
            # Geolocation for first IP
            if profile.ip_addresses:
                profile.geolocation = self.ip_geolocation(profile.ip_addresses[0])
        
        # Check reputation
        ip = profile.ip_addresses[0] if profile.ip_addresses else None
        profile.reputation_data = self.check_reputation(domain, ip)
        
        # Analyze patterns
        profile.patterns = self.analyze_patterns(emails)
        
        # Calculate threat score
        profile.threat_score = self._calculate_threat_score(profile)
        
        # Update profile
        self.profiles[sender] = profile
        self._save_profiles()
        
        return profile
    
    def _calculate_threat_score(self, profile: SenderProfile) -> float:
        """Calculate threat score based on profile data."""
        score = 0.0
        
        # Reputation-based scoring
        if profile.reputation_data.get('virustotal'):
            vt = profile.reputation_data['virustotal']
            if vt['positives'] > 0:
                score += (vt['positives'] / vt['total']) * 0.4
        
        if profile.reputation_data.get('abuseipdb'):
            abuse = profile.reputation_data['abuseipdb']
            score += (abuse['abuse_confidence_score'] / 100) * 0.3
        
        # Pattern-based scoring
        suspicious_patterns = ['urgent', 'verify', 'account', 'payment', 'suspended']
        for pattern in profile.patterns:
            if any(word in pattern.lower() for word in suspicious_patterns):
                score += 0.1
        
        # Domain age scoring
        if profile.whois_data.get('creation_date'):
            try:
                creation_date = datetime.fromisoformat(profile.whois_data['creation_date'].split('T')[0])
                days_old = (datetime.now() - creation_date).days
                if days_old < 30:
                    score += 0.2  # New domains are suspicious
            except:
                pass
        
        return min(score, 1.0)  # Cap at 1.0
    
    def get_threat_profiles(self, min_score: float = 0.5) -> List[SenderProfile]:
        """Get profiles with threat score above threshold."""
        return [profile for profile in self.profiles.values() if profile.threat_score >= min_score]
    
    def generate_intelligence_report(self) -> Dict[str, Any]:
        """Generate comprehensive intelligence report."""
        threat_profiles = self.get_threat_profiles(0.3)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_profiles': len(self.profiles),
            'threat_profiles': len(threat_profiles),
            'top_threats': sorted(threat_profiles, key=lambda x: x.threat_score, reverse=True)[:10],
            'domains_by_country': {},
            'common_patterns': {},
            'reputation_summary': {
                'high_risk': len([p for p in threat_profiles if p.threat_score > 0.7]),
                'medium_risk': len([p for p in threat_profiles if 0.4 <= p.threat_score <= 0.7]),
                'low_risk': len([p for p in threat_profiles if p.threat_score < 0.4])
            }
        }
        
        # Analyze domains by country
        for profile in self.profiles.values():
            country = profile.geolocation.get('country', 'Unknown')
            report['domains_by_country'][country] = report['domains_by_country'].get(country, 0) + 1
        
        # Analyze common patterns
        all_patterns = []
        for profile in self.profiles.values():
            all_patterns.extend(profile.patterns)
        
        pattern_counts = {}
        for pattern in all_patterns:
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
        
        report['common_patterns'] = dict(sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True)[:10])
        
        return report

if __name__ == "__main__":
    # Test the offensive intelligence module
    intel = OffensiveIntelligence()
    
    # Test data
    test_emails = [
        {
            'from': 'suspicious@malware.com',
            'subject': 'Urgent account verification required',
            'body': 'Click here to verify: http://malware.com/verify',
            'date': '2024-01-01T10:00:00'
        }
    ]
    
    profile = intel.build_profile('suspicious@malware.com', test_emails)
    print(f"Profile built for {profile.email}")
    print(f"Threat score: {profile.threat_score}")
    print(f"Patterns: {profile.patterns}")
