"""
Rate limiting utility for PhishGuard.
"""

import time
from collections import defaultdict
from typing import Dict, Tuple, Optional
from config.security_config import security_config

class RateLimiter:
    """Rate limiter for API endpoints and services."""
    
    def __init__(self):
        self.requests: Dict[str, list] = defaultdict(list)
        self.config = security_config.get_rate_limit_config()
        
    def _cleanup_old_requests(self, key: str):
        """Remove requests older than 1 minute.
        
        Args:
            key: Rate limit key
        """
        current_time = time.time()
        self.requests[key] = [
            req_time for req_time in self.requests[key]
            if current_time - req_time < 60
        ]
        
    def is_rate_limited(self, key: str) -> Tuple[bool, Optional[float]]:
        """Check if a request should be rate limited.
        
        Args:
            key: Rate limit key (e.g., IP address or user ID)
            
        Returns:
            Tuple of (is_limited, retry_after)
        """
        if not self.config.get('enabled', True):
            return False, None
            
        self._cleanup_old_requests(key)
        
        requests_per_minute = self.config.get('requests_per_minute', 60)
        burst_limit = self.config.get('burst_limit', 10)
        
        # Check burst limit
        if len(self.requests[key]) >= burst_limit:
            oldest_request = min(self.requests[key])
            retry_after = 60 - (time.time() - oldest_request)
            return True, max(0, retry_after)
            
        # Check rate limit
        if len(self.requests[key]) >= requests_per_minute:
            oldest_request = min(self.requests[key])
            retry_after = 60 - (time.time() - oldest_request)
            return True, max(0, retry_after)
            
        return False, None
        
    def add_request(self, key: str):
        """Add a request to the rate limiter.
        
        Args:
            key: Rate limit key
        """
        self.requests[key].append(time.time())
        
    def get_request_count(self, key: str) -> int:
        """Get the number of requests in the last minute.
        
        Args:
            key: Rate limit key
            
        Returns:
            Number of requests
        """
        self._cleanup_old_requests(key)
        return len(self.requests[key])
        
    def reset(self, key: Optional[str] = None):
        """Reset rate limiter for a key or all keys.
        
        Args:
            key: Rate limit key to reset, or None for all keys
        """
        if key:
            self.requests[key] = []
        else:
            self.requests.clear()

# Create global rate limiter instance
rate_limiter = RateLimiter() 