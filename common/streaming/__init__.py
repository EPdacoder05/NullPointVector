"""
Real-time intercept (RTI) streaming infrastructure for SMS/voice channels.

Unlike email (fetched in batch windows), SMS and voice are event streams: each
message/call must be scored on arrival with single-message latency. This package
provides a source-agnostic, backpressure-aware consumer + a channel pipeline that
fuses the per-channel detector with the unified risk engine.
"""

__all__ = ["rti_consumer", "channel_pipeline"]
