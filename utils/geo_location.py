#!/usr/bin/env python3
"""
IP Geolocation Service
Provides IP address → location mapping for threat intelligence
"""

import logging
import requests
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
import re

logger = logging.getLogger(__name__)

class GeoLocationService:
    """IP address geolocation with caching."""
    
    def __init__(self, cache_file: str = 'data/geo_cache.json'):
        self.cache_file = Path(cache_file)
        self.cache = self._load_cache()
        self.cache_ttl = timedelta(days=7)  # Cache for 7 days
    
    def _load_cache(self) -> Dict[str, Any]:
        """Load cached geolocation data."""
        if self.cache_file.exists():
            with open(self.cache_file) as f:
                return json.load(f)
        return {}
    
    def _save_cache(self):
        """Save cache to disk."""
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f, indent=2)
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal."""
        private_patterns = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[01])\.',
            r'^192\.168\.',
            r'^127\.',
            r'^169\.254\.',
            r'^::1$',
            r'^fc00:',
            r'^fe80:'
        ]
        return any(re.match(pattern, ip) for pattern in private_patterns)
    
    def get_location(self, ip: str, force_refresh: bool = False) -> Optional[Dict[str, Any]]:
        """
        Get geolocation for an IP address.
        
        Args:
            ip: IP address to look up
            force_refresh: Force API call even if cached
        
        Returns:
            dict: Location data with country, city, lat/lon, ISP, etc.
        """
        if not ip or self._is_private_ip(ip):
            return {
                'ip': ip,
                'status': 'private',
                'message': 'Private/internal IP address'
            }
        
        # Check cache
        if not force_refresh and ip in self.cache:
            cached = self.cache[ip]
            cache_time = datetime.fromisoformat(cached.get('cached_at', '2000-01-01'))
            if datetime.now() - cache_time < self.cache_ttl:
                logger.info(f"📍 Using cached location for {ip}")
                return cached.get('data')
        
        # Query IP geolocation API
        try:
            logger.info(f"🌍 Querying geolocation for {ip}")
            
            # Using ip-api.com (free, no key required, 45 req/min limit)
            response = requests.get(
                f'http://ip-api.com/json/{ip}',
                params={'fields': 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query'},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    # Format the data
                    location = {
                        'ip': data.get('query', ip),
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'zip': data.get('zip'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'organization': data.get('org'),
                        'as_number': data.get('as'),
                        'risk_score': self._calculate_risk_score(data)
                    }
                    
                    # Cache it
                    self.cache[ip] = {
                        'cached_at': datetime.now().isoformat(),
                        'data': location
                    }
                    self._save_cache()
                    
                    logger.info(f"✅ Location: {location.get('city')}, {location.get('country')}")
                    return location
                else:
                    logger.warning(f"Geolocation failed: {data.get('message')}")
                    return {'ip': ip, 'status': 'failed', 'message': data.get('message')}
            else:
                logger.error(f"Geolocation API error: {response.status_code}")
                return {'ip': ip, 'status': 'error', 'message': 'API request failed'}
                
        except requests.Timeout:
            logger.error(f"Geolocation timeout for {ip}")
            return {'ip': ip, 'status': 'timeout', 'message': 'Request timeout'}
        except Exception as e:
            logger.error(f"Geolocation error for {ip}: {e}")
            return {'ip': ip, 'status': 'error', 'message': str(e)}
    
    def _calculate_risk_score(self, geo_data: Dict[str, Any]) -> str:
        """
        Calculate risk score based on geolocation data.
        
        Returns:
            str: 'LOW', 'MEDIUM', 'HIGH'
        """
        # High-risk countries for phishing (common phishing origins)
        high_risk_countries = ['CN', 'RU', 'NG', 'PK', 'IN', 'BR', 'RO', 'VN']
        
        country_code = geo_data.get('countryCode', '')
        isp = geo_data.get('isp', '').lower()
        
        # Check country risk
        if country_code in high_risk_countries:
            return 'HIGH'
        
        # Check for VPN/Hosting providers (often used for phishing)
        suspicious_isps = ['vpn', 'proxy', 'hosting', 'datacenter', 'cloud', 'digital ocean', 'aws', 'azure']
        if any(keyword in isp for keyword in suspicious_isps):
            return 'MEDIUM'
        
        return 'LOW'
    
    def batch_lookup(self, ips: list[str]) -> Dict[str, Dict[str, Any]]:
        """
        Look up multiple IPs at once.
        
        Args:
            ips: List of IP addresses
        
        Returns:
            dict: IP → location mapping
        """
        results = {}
        for ip in ips:
            results[ip] = self.get_location(ip)
        return results
    
    def get_location_summary(self, ip: str) -> str:
        """
        Get human-readable location summary.
        
        Args:
            ip: IP address
        
        Returns:
            str: "Moscow, Russia (High Risk)" or "Unknown"
        """
        location = self.get_location(ip)
        
        if not location or location.get('status') != 'success':
            return "Unknown Location"
        
        city = location.get('city', 'Unknown')
        country = location.get('country', 'Unknown')
        risk = location.get('risk_score', 'LOW')
        
        risk_emoji = {'LOW': '🟢', 'MEDIUM': '🟡', 'HIGH': '🔴'}
        
        return f"{city}, {country} {risk_emoji.get(risk, '')} ({risk} Risk)"


# Singleton instance
geo_service = GeoLocationService()
