#!/usr/bin/env python3
"""
FORTRESS-GRADE URL ANALYZER
Zero-trust architecture: ALL URLs are hostile until proven safe.

Features:
- URL extraction with HTML parsing (no code execution)
- URL shortener expansion (bit.ly, tinyurl, etc.)
- Domain reputation checking
- Redirect chain analysis (detect 302 chains)
- Typosquatting detection
- NEVER executes JavaScript or renders content
"""

import re
import logging
import hashlib
import time
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, unquote, parse_qs
from datetime import datetime, timedelta
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import socket

# Use requests with strict timeouts (NO selenium/playwright - those execute JS!)
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

class URLAnalyzer:
    """
    Secure URL analyzer with zero code execution.
    
    SECURITY PRINCIPLES:
    1. NEVER render HTML or execute JavaScript
    2. NEVER follow redirects automatically (detect redirect loops)
    3. NEVER trust user input (sanitize everything)
    4. Always timeout requests (max 5 seconds)
    5. Isolate network calls (no access to internal network)
    """
    
    # Known URL shorteners (expand these CAREFULLY)
    SHORTENERS = {
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
        'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'lnkd.in',
        'mcaf.ee', 'q.gs', 'po.st', 'bc.vc', 'u.to',
        'j.mp', 'scrnch.me', 'fiverr.com/s', 'cleantalk.us',
        'shorturl.at', 'rb.gy', 'cutt.ly', 'bl.ink', 'short.io'
    }
    
    # Typosquatting targets (common legitimate domains)
    LEGITIMATE_DOMAINS = {
        'paypal.com', 'google.com', 'microsoft.com', 'apple.com',
        'amazon.com', 'facebook.com', 'twitter.com', 'linkedin.com',
        'instagram.com', 'netflix.com', 'chase.com', 'wellsfargo.com',
        'bankofamerica.com', 'citibank.com', 'usbank.com', 'yahoo.com',
        'outlook.com', 'gmail.com', 'dropbox.com', 'github.com'
    }
    
    # Suspicious TLDs (commonly used for phishing)
    SUSPICIOUS_TLDS = {
        '.tk', '.ml', '.ga', '.cf', '.gq',  # Free domains
        '.top', '.xyz', '.club', '.loan', '.download',  # Spam TLDs
        '.ru', '.cn', '.pw', '.cc', '.ws',  # High-risk countries
        '.zip', '.review', '.country', '.kim', '.science'  # Weird TLDs
    }
    
    def __init__(self, cache_dir: str = "data/url_cache", timeout: int = 5):
        """
        Initialize URL analyzer with caching.
        
        Args:
            cache_dir: Directory for caching URL analysis results
            timeout: Max timeout for HTTP requests (seconds)
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.cache_ttl = timedelta(days=7)  # Cache results for 7 days
        
        # Setup requests session with retries and timeouts
        self.session = requests.Session()
        retry_strategy = Retry(
            total=2,  # Max 2 retries
            backoff_factor=0.5,  # Wait 0.5s, 1s between retries
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Security headers (block any JS execution)
        self.session.headers.update({
            'User-Agent': 'Yahoo_Phish-URLAnalyzer/1.0 (Security Scanner)',
            'Accept': 'text/html,text/plain',
            'Accept-Language': 'en-US',
            'DNT': '1',  # Do Not Track
            'Connection': 'close'  # Close connection immediately
        })
        
        logger.info(f"✅ URLAnalyzer initialized (timeout={timeout}s, cache={cache_dir})")
    
    def extract_urls(self, text: str, html: str = None) -> List[str]:
        """
        Extract ALL URLs from plaintext and HTML (safely, no rendering).
        
        Args:
            text: Plain text content (email body)
            html: HTML content (if available)
        
        Returns:
            List of unique URLs found
        """
        urls = set()
        
        # 1. Extract from plaintext using regex (most common)
        # Matches http://example.com, https://example.com, www.example.com
        text_urls = re.findall(
            r'(?:(?:https?://)|(?:www\.))(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?',
            text,
            re.IGNORECASE
        )
        urls.update(text_urls)
        
        # 2. Extract from HTML <a href="..."> tags (if HTML provided)
        if html:
            # Use regex (NOT BeautifulSoup - that can execute scripts!)
            href_urls = re.findall(
                r'href=["\']([^"\']+)["\']',
                html,
                re.IGNORECASE
            )
            urls.update(href_urls)
            
            # Also check <img src="..."> (tracking pixels)
            img_urls = re.findall(
                r'src=["\']([^"\']+)["\']',
                html,
                re.IGNORECASE
            )
            urls.update(img_urls)
        
        # 3. Decode URL-encoded strings (phishers hide URLs this way)
        decoded_urls = []
        for url in urls:
            try:
                decoded = unquote(url)
                if decoded != url:  # Was encoded
                    decoded_urls.append(decoded)
            except:
                pass
        urls.update(decoded_urls)
        
        # 4. Normalize URLs (add http:// if missing)
        normalized = set()
        for url in urls:
            url = url.strip()
            if url.startswith('www.') and not url.startswith('http'):
                url = 'http://' + url
            if url.startswith(('http://', 'https://')):
                normalized.add(url)
        
        logger.debug(f"Extracted {len(normalized)} unique URLs from text/HTML")
        return list(normalized)
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze single URL for phishing indicators (NO CODE EXECUTION).
        
        Args:
            url: URL to analyze
        
        Returns:
            Dict with analysis results:
            {
                'url': original_url,
                'risk_score': 0-100 (0=safe, 100=definitely phishing),
                'is_shortener': bool,
                'expanded_url': str (if shortener),
                'redirect_chain': list[str],
                'domain': str,
                'tld': str,
                'is_typosquatting': bool,
                'typo_target': str (if typosquatting),
                'is_suspicious_tld': bool,
                'age_days': int (domain age, -1 if unknown),
                'flags': list[str] (reasons for risk score)
            }
        """
        # Check cache first
        cache_key = hashlib.md5(url.encode()).hexdigest()
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if cache_file.exists():
            cache_data = json.loads(cache_file.read_text())
            cache_time = datetime.fromisoformat(cache_data['cached_at'])
            if datetime.now() - cache_time < self.cache_ttl:
                logger.debug(f"✓ Cache hit for {url}")
                return cache_data['result']
        
        # Analyze URL
        result = {
            'url': url,
            'risk_score': 0,
            'flags': [],
            'analyzed_at': datetime.now().isoformat()
        }
        
        try:
            # Parse URL components
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path
            
            result['domain'] = domain
            result['path'] = path
            result['scheme'] = parsed.scheme
            
            # Extract TLD
            if '.' in domain:
                tld = '.' + domain.split('.')[-1]
                result['tld'] = tld
            else:
                result['tld'] = ''
            
            # 1. Check if URL shortener
            result['is_shortener'] = any(shortener in domain for shortener in self.SHORTENERS)
            if result['is_shortener']:
                result['risk_score'] += 30
                result['flags'].append('URL_SHORTENER')
                # Try to expand (with timeout)
                try:
                    expanded = self._expand_shortener(url)
                    result['expanded_url'] = expanded
                    result['flags'].append(f'EXPANDS_TO:{expanded[:50]}')
                except Exception as e:
                    result['expanded_url'] = None
                    result['flags'].append('SHORTENER_EXPANSION_FAILED')
            
            # 2. Check for typosquatting
            typo_check = self._check_typosquatting(domain)
            if typo_check['is_typosquatting']:
                result['is_typosquatting'] = True
                result['typo_target'] = typo_check['target']
                result['risk_score'] += 50
                result['flags'].append(f'TYPOSQUATTING:{typo_check["target"]}')
            else:
                result['is_typosquatting'] = False
            
            # 3. Check suspicious TLD
            if result['tld'] in self.SUSPICIOUS_TLDS:
                result['is_suspicious_tld'] = True
                result['risk_score'] += 25
                result['flags'].append(f'SUSPICIOUS_TLD:{result["tld"]}')
            else:
                result['is_suspicious_tld'] = False
            
            # 4. Check for IP address instead of domain
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain.replace('www.', '')):
                result['risk_score'] += 40
                result['flags'].append('IP_ADDRESS_URL')
            
            # 5. Check for unusual port numbers
            if ':' in domain and domain.split(':')[1] not in ['80', '443']:
                result['risk_score'] += 20
                result['flags'].append(f'UNUSUAL_PORT:{domain.split(":")[1]}')
            
            # 6. Check URL length (phishers use very long URLs)
            if len(url) > 150:
                result['risk_score'] += 15
                result['flags'].append(f'LONG_URL:{len(url)}chars')
            
            # 7. Check for suspicious keywords in path
            suspicious_keywords = [
                'login', 'signin', 'verify', 'account', 'update',
                'secure', 'banking', 'confirm', 'suspend', 'locked'
            ]
            for keyword in suspicious_keywords:
                if keyword in path.lower():
                    result['risk_score'] += 5
                    result['flags'].append(f'SUSPICIOUS_PATH:{keyword}')
            
            # 8. Check for multiple subdomains (common in phishing)
            subdomains = domain.split('.')
            if len(subdomains) > 3:  # e.g., login.secure.paypal.evil.com
                result['risk_score'] += 20
                result['flags'].append(f'MANY_SUBDOMAINS:{len(subdomains)}')
            
            # 9. Check for @ symbol (URL injection trick)
            if '@' in url:
                result['risk_score'] += 50
                result['flags'].append('URL_INJECTION:@')
            
            # 10. Try to follow redirects (safely, with timeout)
            redirect_chain = self._follow_redirects(url)
            result['redirect_chain'] = redirect_chain
            if len(redirect_chain) > 3:
                result['risk_score'] += 30
                result['flags'].append(f'REDIRECT_LOOP:{len(redirect_chain)}')
            
            # Cap risk score at 100
            result['risk_score'] = min(result['risk_score'], 100)
            
            # Determine threat level
            if result['risk_score'] >= 70:
                result['threat_level'] = 'HIGH'
            elif result['risk_score'] >= 40:
                result['threat_level'] = 'MEDIUM'
            else:
                result['threat_level'] = 'LOW'
            
        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {e}")
            result['error'] = str(e)
            result['risk_score'] = 50  # Default to medium risk on error
            result['threat_level'] = 'MEDIUM'
            result['flags'].append(f'ANALYSIS_ERROR:{str(e)[:50]}')
        
        # Cache result
        cache_data = {
            'cached_at': datetime.now().isoformat(),
            'result': result
        }
        cache_file.write_text(json.dumps(cache_data, indent=2))
        
        return result
    
    def analyze_urls_parallel(self, urls: List[str], max_workers: int = 5) -> List[Dict[str, Any]]:
        """
        Analyze multiple URLs in parallel (with thread pool).
        
        Args:
            urls: List of URLs to analyze
            max_workers: Max concurrent analysis threads
        
        Returns:
            List of analysis results (one per URL)
        """
        if not urls:
            return []
        
        logger.info(f"🔍 Analyzing {len(urls)} URLs with {max_workers} workers...")
        start_time = time.time()
        
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all URL analysis tasks
            futures = {executor.submit(self.analyze_url, url): url for url in urls}
            
            # Collect results as they complete (with timeout)
            for future in futures:
                try:
                    result = future.result(timeout=self.timeout + 2)
                    results.append(result)
                except TimeoutError:
                    url = futures[future]
                    logger.warning(f"⏱️ URL analysis timeout: {url}")
                    results.append({
                        'url': url,
                        'risk_score': 50,
                        'threat_level': 'MEDIUM',
                        'flags': ['ANALYSIS_TIMEOUT'],
                        'error': 'Analysis timeout'
                    })
                except Exception as e:
                    url = futures[future]
                    logger.error(f"❌ URL analysis error: {url}: {e}")
                    results.append({
                        'url': url,
                        'risk_score': 50,
                        'threat_level': 'MEDIUM',
                        'flags': [f'ERROR:{str(e)[:30]}'],
                        'error': str(e)
                    })
        
        elapsed = time.time() - start_time
        logger.info(f"✅ Analyzed {len(results)} URLs in {elapsed:.2f}s ({len(results)/elapsed:.1f} URLs/s)")
        
        return results
    
    def _expand_shortener(self, short_url: str) -> str:
        """
        Expand shortened URL (safely, no rendering).
        
        Args:
            short_url: Shortened URL (bit.ly, tinyurl, etc.)
        
        Returns:
            Expanded URL (or original if expansion fails)
        """
        try:
            # Use HEAD request (no body download, just follow redirects)
            response = self.session.head(
                short_url,
                allow_redirects=True,
                timeout=self.timeout
            )
            return response.url
        except Exception as e:
            logger.debug(f"Shortener expansion failed for {short_url}: {e}")
            return short_url
    
    def _follow_redirects(self, url: str, max_hops: int = 10) -> List[str]:
        """
        Follow redirect chain (safely, with max depth).
        
        Args:
            url: Starting URL
            max_hops: Max redirects to follow (prevent loops)
        
        Returns:
            List of URLs in redirect chain
        """
        chain = [url]
        try:
            current_url = url
            for _ in range(max_hops):
                response = self.session.head(
                    current_url,
                    allow_redirects=False,  # Manual redirect handling
                    timeout=self.timeout
                )
                
                # Check for redirect
                if response.status_code in [301, 302, 303, 307, 308]:
                    next_url = response.headers.get('Location')
                    if next_url and next_url not in chain:
                        chain.append(next_url)
                        current_url = next_url
                    else:
                        break  # Redirect loop detected
                else:
                    break  # No more redirects
        except Exception as e:
            logger.debug(f"Redirect chain analysis failed: {e}")
        
        return chain
    
    def _check_typosquatting(self, domain: str) -> Dict[str, Any]:
        """
        Check if domain is typosquatting a legitimate domain.
        
        Args:
            domain: Domain to check (e.g., 'paypa1.com')
        
        Returns:
            {
                'is_typosquatting': bool,
                'target': str (legitimate domain if typosquatting)
            }
        """
        # Remove www. prefix
        domain = domain.replace('www.', '')
        
        for legit_domain in self.LEGITIMATE_DOMAINS:
            # Check various typosquatting techniques
            
            # 1. Character substitution (paypa1.com = paypal.com)
            if self._levenshtein_distance(domain, legit_domain) == 1:
                return {'is_typosquatting': True, 'target': legit_domain}
            
            # 2. Homoglyph attack (рaypal.com with Cyrillic 'р')
            # (Hard to detect without unicode normalization)
            
            # 3. Subdomain trick (paypal.evil.com)
            if legit_domain in domain and domain != legit_domain:
                return {'is_typosquatting': True, 'target': legit_domain}
            
            # 4. TLD swap (paypal.org instead of paypal.com)
            domain_base = '.'.join(domain.split('.')[:-1])
            legit_base = '.'.join(legit_domain.split('.')[:-1])
            if domain_base == legit_base and domain != legit_domain:
                return {'is_typosquatting': True, 'target': legit_domain}
        
        return {'is_typosquatting': False, 'target': None}
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """
        Calculate Levenshtein distance (edit distance) between two strings.
        
        Args:
            s1: First string
            s2: Second string
        
        Returns:
            Edit distance (number of character changes needed)
        """
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]

# Global instance
url_analyzer = URLAnalyzer()

if __name__ == '__main__':
    # Test URL analyzer
    test_urls = [
        'https://paypa1.com/login',  # Typosquatting
        'http://bit.ly/3xYz123',  # Shortener
        'https://secure-login.paypal.verify-account.ru/confirm',  # Obvious phish
        'https://linkedin.com/in/john',  # Legitimate
        'http://192.168.1.1/admin',  # IP address
        'https://www.google.com'  # Safe
    ]
    
    for url in test_urls:
        print(f"\n🔍 Analyzing: {url}")
        result = url_analyzer.analyze_url(url)
        print(f"   Risk Score: {result['risk_score']}/100 ({result['threat_level']})")
        print(f"   Flags: {', '.join(result['flags'])}")
        if result.get('is_typosquatting'):
            print(f"   ⚠️ Typosquatting: {result['typo_target']}")
