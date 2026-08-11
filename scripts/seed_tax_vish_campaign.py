#!/usr/bin/env python3
"""One-shot: screen tax-resolution campaign samples so DB + directory pick up CIDs/TFNs.

Usage (app stack up):
  docker compose exec app python scripts/seed_tax_vish_campaign.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "data" / "vish_campaigns" / "tax_resolution.json"

# Representative scripts from the pilot VM dump (enough for fingerprint + TFN extract).
SAMPLES = [
    {
        "caller_id": "+19046788702",
        "transcript": (
            "This is Stacy Ball with the tax resolution department, based on the "
            "information associated with your file. Press 2 or call me at 888-905-0279. "
            "If you're still looking for assistance call me back at 888-905-0279."
        ),
    },
    {
        "caller_id": "+19419441925",
        "transcript": (
            "Hi, this is Jenny Keys. Based on your file, you may still have federal or "
            "state tax matters that are worth reviewing. Press one or call me at "
            "833-684-5481. Call me at 866-771-5387 again, 866-771-5387. Press 9 to opt out."
        ),
    },
    {
        "caller_id": "+14437552286",
        "transcript": (
            "Hi, this is Sydney Charles with National Tax Resolution Services. If you "
            "still have unresolved federal or state tax debt, call me at 866-398-3809. "
            "Call me back at 866-771-4591. Press 9 to opt out."
        ),
    },
    {
        "caller_id": "+18456304255",
        "transcript": (
            "Hi, this is Rebecca Rogers with the taxpayer resolution unit. Press one or "
            "call me at 888-269-1541. My direct number is 866-666-1438."
        ),
    },
]


def main() -> int:
    sys.path.insert(0, str(ROOT))
    from common.vish import screen_call, CallEvent
    from common.vish.phones import extract_e164_numbers
    from common.streaming.dlq import persist_threat_durable

    pack_nums = []
    if PACK.exists():
        pack_nums = list((json.loads(PACK.read_text()).get("block") or []))
    print(f"pack numbers: {len(pack_nums)}")

    blocked = 0
    for sample in SAMPLES:
        ev = CallEvent(
            caller_id=sample["caller_id"],
            phase="voicemail",
            transcript=sample["transcript"],
            contact_known=False,
        )
        result = screen_call(ev)
        print(f"{sample['caller_id']} → threat={result.is_threat} action={result.action} risk={result.risk:.2f}")
        if result.is_threat:
            meta = {
                "risk_score": result.risk,
                "action": result.action.value if hasattr(result.action, "value") else str(result.action),
                "channel": "vishing",
                "verdict": result.verdict,
                "via": "campaign-seed",
                "campaign": "tax_resolution_robocall",
            }
            persist_threat_durable(
                content=sample["transcript"],
                threat_type="vishing",
                sender=sample["caller_id"],
                metadata=meta,
            )
            blocked += 1
            for cb in extract_e164_numbers(sample["transcript"], exclude=[sample["caller_id"]]):
                persist_threat_durable(
                    content=f"[callback] {sample['transcript'][:500]}",
                    threat_type="vishing",
                    sender=cb,
                    metadata={**meta, "via": "transcript-callback", "action": "block"},
                )
                print(f"  + callback {cb}")

    # Ensure every pack number is durably present even if screen was soft.
    for raw in pack_nums:
        persist_threat_durable(
            content="[tax_resolution campaign seed]",
            threat_type="vishing",
            sender=raw,
            metadata={
                "risk_score": 0.95,
                "action": "block",
                "channel": "vishing",
                "via": "campaign-seed-pack",
                "campaign": "tax_resolution_robocall",
            },
        )
        blocked += 1

    from Autobot.VectorDB.NullPoint_Vector import get_vish_directory
    updated, block, label = get_vish_directory()
    print(f"directory: {len(block)} blocks, {len(label)} labels @ {updated}")
    print(f"seed writes≈{blocked}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
