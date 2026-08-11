"""
Centralized URL utilities for NullPointVector IDPS.

Provides reusable URL extraction and validation functions
to eliminate code duplication across modules.
"""

import re
from typing import List, Tuple
from urllib.parse import urlparse

# Centralized URL regex pattern (used across 6+ modules)
URL_REGEX = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'

# Suspicious TLDs / shorteners — single source: common.ml.features (dotted for endswith).
from common.ml.features import SUSPICIOUS_TLDS as _TLD_SET, URL_SHORTENERS as _SHORT_SET

SUSPICIOUS_TLDS = [f".{t}" if not str(t).startswith(".") else str(t) for t in sorted(_TLD_SET)]
URL_SHORTENERS = sorted(_SHORT_SET)


def extract_urls(text: str) -> List[str]:
    """
    Extract all URLs from text using centralized regex pattern.
    
    Args:
        text: Text to search for URLs
        
    Returns:
        List of URL strings found in text
        
    Example:
        >>> extract_urls("Visit https://example.com and http://test.org")
        ['https://example.com', 'http://test.org']
    """
    if not text:
        return []
    return re.findall(URL_REGEX, text)


def count_urls(text: str) -> int:
    """
    Count URLs in text (useful for feature engineering).
    
    Args:
        text: Text to search
        
    Returns:
        Number of URLs found
    """
    return len(extract_urls(text))


def is_suspicious_url(url: str) -> Tuple[bool, str]:
    """
    Check if URL has phishing indicators.
    
    Args:
        url: URL to analyze
        
    Returns:
        (is_suspicious, reason) tuple
        
    Phishing Indicators:
        - Suspicious TLDs (.ru, .tk, etc.)
        - IP addresses (hides real domain)
        - URL shorteners (obscures destination)
        - Missing HTTPS (not always malicious, but risky)
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check suspicious TLDs
        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            return (True, f"Suspicious TLD: {domain}")
        
        # Check for IP addresses
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            return (True, f"IP address domain: {domain}")
        
        # Check for URL shorteners
        if any(shortener in domain for shortener in URL_SHORTENERS):
            return (True, f"URL shortener: {domain}")
        
        # Check for missing HTTPS (lower confidence)
        if parsed.scheme == 'http':
            return (True, "Unencrypted HTTP (not HTTPS)")
        
        return (False, "No suspicious indicators")
        
    except Exception as e:
        return (True, f"URL parsing error: {e}")


def analyze_urls(text: str) -> List[Tuple[str, bool, str]]:
    """
    Extract and analyze all URLs in text.
    
    Args:
        text: Text to search
        
    Returns:
        List of (url, is_suspicious, reason) tuples
        
    Example:
        >>> analyze_urls("Visit http://paypal-verify.ru")
        [('http://paypal-verify.ru', True, 'Suspicious TLD: paypal-verify.ru')]
    """
    urls = extract_urls(text)
    results = []
    
    for url in urls:
        is_suspicious, reason = is_suspicious_url(url)
        results.append((url, is_suspicious, reason))
    
    return results


def get_domain(url: str) -> str:
    """
    Extract domain from URL.
    
    Args:
        url: URL to parse
        
    Returns:
        Domain name (e.g., 'example.com')
    """
    try:
        return urlparse(url).netloc.lower()
    except:
        return ''


if __name__ == "__main__":
    # Quick tests
    test_text = """
    Visit https://google.com or update at http://paypal-verify.ru
    Click http://192.168.1.1/login or use http://bit.ly/abc123
    """
    
    print("URLs found:")
    for url in extract_urls(test_text):
        print(f"  - {url}")
    
    print("\nURL Analysis:")
    for url, suspicious, reason in analyze_urls(test_text):
        status = "🚨 SUSPICIOUS" if suspicious else "✅ SAFE"
        print(f"  {status} {url}")
        print(f"     Reason: {reason}")
