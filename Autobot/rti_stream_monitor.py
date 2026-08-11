#!/usr/bin/env python3
"""
Real-Time Intercept (RTI) stream monitor — SMS (smishing) + voice (vishing).

This is the streaming counterpart to the email `yahoo_stream_monitor`. Emails
arrive in batch windows; SMS/voice arrive as an event stream, so each record is
scored on arrival through a bounded worker-pool consumer (single-message
latency, backpressure, graceful drain).

    producer(s) ──submit()──▶ RTIConsumer(channel) ──▶ risk verdict ──▶ DB sink

Producers are pluggable and decoupled. Wire a real source by calling
`consumers[channel].submit(record)` from:
  - SmishGuard.sms_fetch  (iPhone SMS) / an SMS webhook (Twilio etc.)
  - VishGuard.voice_fetch (CallKit) / a speech-to-text transcript stream
  - an external queue (Kafka/SQS) for millions-scale horizontal fan-out

Usage:
    python -m Autobot.rti_stream_monitor --demo            # synthetic load test
    python -m Autobot.rti_stream_monitor --demo -n 5000    # throughput probe
    python -m Autobot.rti_stream_monitor                   # idle, awaiting producers
"""
from __future__ import annotations

import argparse
import logging
import random
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.streaming.channel_pipeline import make_consumer  # noqa: E402

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("rti_monitor")

CHANNELS = ("smishing", "vishing")

_DEMO_SAMPLES = {
    "smishing": [
        {"from": "+18885550101", "body": "USPS: package on hold, pay fee: http://bit.ly/usps-fee"},
        {"from": "CHASE", "body": "Chase: did you make a $750 transfer? Verify: http://chase-secure.pw"},
        {"from": "+15551230201", "body": "Hey, running 5 min late — see you at the coffee shop!"},
        {"from": "DELTA", "body": "Delta: flight DL482 to ATL on time, gate B12 at 3:40pm."},
    ],
    "vishing": [
        {"caller_id": "IRS", "transcript": "This is the IRS. A warrant is issued for your arrest. Press 1 to settle your tax debt now."},
        {"caller_id": "+18005550304", "transcript": "We detected fraud on your account. Transfer your funds to a secure account now."},
        {"caller_id": "+15551230401", "transcript": "Hi, this is Dr. Lee's office confirming your appointment Thursday at 3pm."},
        {"caller_id": "+15551230411", "transcript": "Hey it's Tom, the game's on Saturday at noon, you still coming?"},
    ],
}


def build_consumers(workers: int = 4, persist: bool = True) -> dict:
    consumers = {ch: make_consumer(ch, workers=workers, persist=persist) for ch in CHANNELS}
    for c in consumers.values():
        c.start()
    return consumers


def run_demo(consumers: dict, n: int):
    """Push n synthetic records per channel and report throughput."""
    logger.info("Demo: submitting %d records/channel…", n)
    start = time.perf_counter()
    for _ in range(n):
        for ch in CHANNELS:
            consumers[ch].submit(dict(random.choice(_DEMO_SAMPLES[ch])))
    for ch in CHANNELS:
        consumers[ch].stop(drain=True)
    elapsed = time.perf_counter() - start
    total = sum(c.stats.snapshot()["processed"] for c in consumers.values())
    logger.info("Demo done in %.2fs — %.0f msg/s aggregate", elapsed,
                total / elapsed if elapsed else 0)
    for ch, c in consumers.items():
        logger.info("  %-9s %s", ch, c.stats.snapshot())


def run_forever(consumers: dict):
    stop = {"flag": False}

    def _handle(*_):
        stop["flag"] = True
    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)

    logger.info("RTI monitor running. Producers should call consumers[ch].submit(record).")
    logger.info("Channels: %s. Ctrl-C to stop.", ", ".join(CHANNELS))
    while not stop["flag"]:
        time.sleep(5)
        for ch, c in consumers.items():
            logger.info("[%s] %s", ch, c.stats.snapshot())
    for c in consumers.values():
        c.stop(drain=True)


def main():
    ap = argparse.ArgumentParser(description="RTI (SMS/voice) stream monitor")
    ap.add_argument("--demo", action="store_true", help="run a synthetic load test and exit")
    ap.add_argument("-n", type=int, default=500, help="records per channel in demo mode")
    ap.add_argument("--workers", type=int, default=4, help="worker threads per channel")
    ap.add_argument("--no-persist", action="store_true", help="skip DB sink (verdict-only)")
    args = ap.parse_args()

    consumers = build_consumers(workers=args.workers, persist=not args.no_persist)
    if args.demo:
        run_demo(consumers, args.n)
    else:
        run_forever(consumers)


if __name__ == "__main__":
    main()
