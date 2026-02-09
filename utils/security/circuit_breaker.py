#!/usr/bin/env python3
"""
Circuit Breaker Pattern for External Service Resilience
Prevents cascading failures and provides graceful degradation.

STATES:
- CLOSED: Normal operation, requests flow through
- OPEN: Failure threshold exceeded, requests fail fast
- HALF_OPEN: Testing if service recovered, limited requests allowed

SECURITY BENEFIT:
Prevents DoS from slow/failing external services and provides
visibility into service health for security monitoring.
"""

import time
import logging
from enum import Enum
from typing import Callable, Any, Optional
from threading import Lock

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerError(Exception):
    """Exception raised when circuit breaker is open."""
    pass


class CircuitBreaker:
    """
    Circuit breaker for external service calls.
    
    Usage:
        breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=60)
        
        try:
            result = breaker.call(external_service_function, *args, **kwargs)
        except CircuitBreakerError:
            # Handle circuit open
            logger.error("Service unavailable - circuit breaker open")
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exception: type = Exception,
        name: str = "default"
    ):
        """
        Initialize circuit breaker.
        
        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before attempting recovery
            expected_exception: Exception type that counts as failure
            name: Name for logging/monitoring
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self.name = name
        
        # State tracking
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.state = CircuitState.CLOSED
        self._lock = Lock()
        
        logger.info(f"✅ SECURITY: Circuit breaker '{name}' initialized with threshold={failure_threshold}")
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Call function through circuit breaker.
        
        Args:
            func: Function to call
            *args: Positional arguments
            **kwargs: Keyword arguments
        
        Returns:
            Function return value
        
        Raises:
            CircuitBreakerError: If circuit is open
            Exception: If function raises exception
        """
        with self._lock:
            # Check if we should attempt call
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self._transition_to_half_open()
                else:
                    raise CircuitBreakerError(
                        f"Circuit breaker '{self.name}' is OPEN - "
                        f"service unavailable for {self.recovery_timeout}s"
                    )
        
        # Attempt the call
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        
        except self.expected_exception as e:
            self._on_failure()
            raise
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset."""
        if self.last_failure_time is None:
            return True
        
        elapsed = time.time() - self.last_failure_time
        return elapsed >= self.recovery_timeout
    
    def _transition_to_half_open(self):
        """Transition from OPEN to HALF_OPEN state."""
        self.state = CircuitState.HALF_OPEN
        logger.info(f"🔄 Circuit breaker '{self.name}' transitioning to HALF_OPEN - testing recovery")
    
    def _on_success(self):
        """Handle successful call."""
        with self._lock:
            if self.state == CircuitState.HALF_OPEN:
                self._transition_to_closed()
            
            # Reset failure count on success
            self.failure_count = 0
    
    def _on_failure(self):
        """Handle failed call."""
        with self._lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.state == CircuitState.HALF_OPEN:
                # Failed in half-open state, go back to open
                self._transition_to_open()
            elif self.failure_count >= self.failure_threshold:
                # Exceeded threshold, open circuit
                self._transition_to_open()
    
    def _transition_to_open(self):
        """Transition to OPEN state."""
        self.state = CircuitState.OPEN
        logger.error(
            f"🚨 SECURITY: Circuit breaker '{self.name}' is now OPEN - "
            f"service failed {self.failure_count} times (threshold: {self.failure_threshold})"
        )
    
    def _transition_to_closed(self):
        """Transition to CLOSED state."""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        logger.info(f"✅ SECURITY: Circuit breaker '{self.name}' is now CLOSED - service recovered")
    
    def get_state(self) -> CircuitState:
        """Get current circuit state."""
        return self.state
    
    def get_failure_count(self) -> int:
        """Get current failure count."""
        return self.failure_count
    
    def reset(self):
        """Manually reset circuit breaker."""
        with self._lock:
            self.failure_count = 0
            self.last_failure_time = None
            self.state = CircuitState.CLOSED
            logger.info(f"🔄 Circuit breaker '{self.name}' manually reset")


class CircuitBreakerRegistry:
    """
    Registry for managing multiple circuit breakers.
    Singleton pattern for application-wide circuit breaker management.
    """
    
    _instance = None
    _lock = Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._breakers = {}
        return cls._instance
    
    def get_breaker(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: int = 60
    ) -> CircuitBreaker:
        """
        Get or create circuit breaker by name.
        
        Args:
            name: Circuit breaker name
            failure_threshold: Failures before opening
            recovery_timeout: Recovery timeout in seconds
        
        Returns:
            CircuitBreaker instance
        """
        if name not in self._breakers:
            self._breakers[name] = CircuitBreaker(
                failure_threshold=failure_threshold,
                recovery_timeout=recovery_timeout,
                name=name
            )
        return self._breakers[name]
    
    def get_all_states(self) -> dict:
        """Get state of all circuit breakers."""
        return {
            name: {
                "state": breaker.get_state().value,
                "failure_count": breaker.get_failure_count()
            }
            for name, breaker in self._breakers.items()
        }
    
    def reset_all(self):
        """Reset all circuit breakers."""
        for breaker in self._breakers.values():
            breaker.reset()


# Singleton instance
circuit_breaker_registry = CircuitBreakerRegistry()


# Decorator for easy circuit breaker usage
def circuit_breaker(
    name: str,
    failure_threshold: int = 5,
    recovery_timeout: int = 60
):
    """
    Decorator to wrap function with circuit breaker.
    
    Usage:
        @circuit_breaker(name="external_api", failure_threshold=5)
        def call_external_api():
            # ... API call code ...
    """
    def decorator(func: Callable) -> Callable:
        breaker = circuit_breaker_registry.get_breaker(
            name=name,
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout
        )
        
        def wrapper(*args, **kwargs):
            return breaker.call(func, *args, **kwargs)
        
        return wrapper
    return decorator


# Export main classes
__all__ = [
    'CircuitBreaker',
    'CircuitBreakerRegistry',
    'CircuitBreakerError',
    'CircuitState',
    'circuit_breaker',
    'circuit_breaker_registry',
]
