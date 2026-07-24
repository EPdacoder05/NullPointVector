"""
Shared production infrastructure for the Yahoo_Phish IDPS API surface
(Phish / Smish / Vish all reuse these — single source of truth).

    auth          — JWT issue/verify + FastAPI auth dependencies + RBAC
    rate_limit    — O(1) token-bucket limiter (in-memory or Redis-backed)
    idempotency   — atomic CAS idempotency-key store (replay-safe writes)
    pagination    — opaque keyset cursor encode/decode + page envelope
    observability — Prometheus metrics + structured request logging middleware

Mirrors System-Design-Engineering-Universal-Reference/{security,api,monitoring}.
"""
