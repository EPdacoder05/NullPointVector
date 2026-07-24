"""
Observability: Prometheus metrics + structured request logging.

- Request latency histogram + count/in-flight gauges, labeled by method/route/
  status. The histogram is what proves the resume's "sub-200ms latency" claim
  (look at the p95/p99 buckets), and what alerting/SLOs are built on.
- Degrades gracefully if prometheus_client is not installed (no-op metrics),
  so the API never hard-depends on the metrics stack.

Adapted from System-Design-Engineering-Universal-Reference/monitoring/observability.py.
"""
import logging
import time

from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("api")

try:
    from prometheus_client import (Counter, Gauge, Histogram,
                                   CONTENT_TYPE_LATEST, generate_latest)
    _PROM = True
except Exception:  # pragma: no cover
    _PROM = False
    CONTENT_TYPE_LATEST = "text/plain"

    def generate_latest():  # type: ignore
        return b"# prometheus_client not installed\n"


if _PROM:
    REQUESTS = Counter("http_requests_total", "Total HTTP requests",
                       ["method", "route", "status"])
    LATENCY = Histogram("http_request_duration_seconds", "Request latency (s)",
                        ["method", "route"],
                        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.5, 1, 2, 5))
    IN_FLIGHT = Gauge("http_requests_in_flight", "In-flight HTTP requests")
else:  # no-op shims
    class _Noop:
        def labels(self, *a, **k): return self
        def inc(self, *a, **k): pass
        def dec(self, *a, **k): pass
        def observe(self, *a, **k): pass
    REQUESTS = LATENCY = IN_FLIGHT = _Noop()


def metrics_response():
    """Return (body, content_type) for a GET /metrics endpoint."""
    return generate_latest(), CONTENT_TYPE_LATEST


class ObservabilityMiddleware(BaseHTTPMiddleware):
    """Times every request, records metrics, and emits a structured access log."""

    async def dispatch(self, request, call_next):
        route = request.url.path
        method = request.method
        start = time.perf_counter()
        IN_FLIGHT.inc()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            elapsed = time.perf_counter() - start
            IN_FLIGHT.dec()
            LATENCY.labels(method, route).observe(elapsed)
            REQUESTS.labels(method, route, str(status_code)).inc()
            logger.info(
                "access",
                extra={"method": method, "route": route,
                       "status": status_code, "latency_ms": round(elapsed * 1000, 2)},
            )
