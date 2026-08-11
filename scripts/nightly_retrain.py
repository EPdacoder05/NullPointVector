#!/usr/bin/env python3
"""
Nightly / maintenance full-batch retrain for sibling channels.

Runs ChannelTrainer (smish/vish) and PhishGuard trainer when available.
Promotion only if golden gate passes — this is the "put the whole puzzle together"
path that repairs ephemeral drift from daytime partial_fit streams.

Cron example (host):
  15 3 * * * cd /path/to/Yahoo_Phish && docker compose exec -T app python scripts/nightly_retrain.py
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("nightly_retrain")

_ROOT = Path(__file__).resolve().parents[1]
_OUT = _ROOT / "data" / "nightly_retrain_report.json"


def _run_channel(channel: str) -> dict:
    if channel == "phishing":
        try:
            from PhishGuard.phish_mlm.training.trainer import Trainer
            r = Trainer().run()
            return {
                "channel": channel,
                "ok": True,
                "promoted": getattr(r, "promoted", None),
                "reason": getattr(r, "reason", None),
                "version": getattr(r, "version", None),
            }
        except Exception as e:
            log.exception("phishing retrain failed")
            return {"channel": channel, "ok": False, "error": str(e)[:240]}
    try:
        from common.ml.training import ChannelTrainer
        r = ChannelTrainer(channel).run()
        return {
            "channel": channel,
            "ok": True,
            "promoted": getattr(r, "promoted", None),
            "reason": getattr(r, "reason", None),
            "version": getattr(r, "version", None),
            "n_train": getattr(r, "n_train", None),
            "candidate_metrics": getattr(r, "candidate_metrics", None),
        }
    except Exception as e:
        log.exception("%s retrain failed", channel)
        return {"channel": channel, "ok": False, "error": str(e)[:240]}


def main() -> int:
    report = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "channels": [],
    }
    for ch in ("phishing", "smishing", "vishing"):
        log.info("=== nightly retrain: %s ===", ch)
        report["channels"].append(_run_channel(ch))
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    _OUT.parent.mkdir(parents=True, exist_ok=True)
    _OUT.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    log.info("wrote %s", _OUT)
    fails = [c for c in report["channels"] if not c.get("ok")]
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
