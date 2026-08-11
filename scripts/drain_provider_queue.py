#!/usr/bin/env python3
"""Drain provider_action_queue (junk/trash). Cron every ~2 min is enough for pilot."""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))


def main() -> int:
    from common.provider_sync import process_provider_queue
    stats = process_provider_queue(limit=40)
    print(stats)
    return 0 if not stats.get("error") else 1


if __name__ == "__main__":
    raise SystemExit(main())
