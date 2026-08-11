"""
Shared ML pipeline used across detection channels (email/SMS/voice).

The email PhishGuard detector defines the reference architecture
(word TF-IDF + char TF-IDF + structural features → SGDClassifier + Platt).
`channel_detector` generalizes that pipeline over a channel-specific structural
feature function so SmishGuard and VishGuard bootstrap off the exact same
architecture without duplicating the ML glue (DRY, single source of truth).
"""

__all__ = ["channel_detector", "features"]
