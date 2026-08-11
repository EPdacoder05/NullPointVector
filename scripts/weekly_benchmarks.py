#!/usr/bin/env python3
"""Weekly benchmark refresh + append-only history for auditor diffs.

Usage:
  docker compose exec -T app python scripts/weekly_benchmarks.py

Cron (host):
  30 4 * * 1 cd /path/to/Yahoo_Phish && docker compose exec -T app python scripts/weekly_benchmarks.py
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.bench_snapshot import refresh_snapshot, _PATH  # noqa: E402

_HISTORY = _ROOT / "data" / "benchmark_history.jsonl"


def main() -> int:
    print("Weekly benchmark refresh…", flush=True)
    try:
        out = refresh_snapshot(latency_n=0)
    except Exception as e:
        print("FAILED:", e, flush=True)
        return 1
    row = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "snapshot_path": str(_PATH),
        "quality": out.get("quality") or {},
        "generated_at": out.get("generated_at"),
    }
    _HISTORY.parent.mkdir(parents=True, exist_ok=True)
    with open(_HISTORY, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print("Wrote", _PATH, flush=True)
    print("Appended", _HISTORY, flush=True)
    for ch, m in (row["quality"] or {}).items():
        if m.get("available"):
            print(
                f"  {ch}: acc={m.get('accuracy')} fpr={m.get('fpr')} gate={m.get('gate_pass')}",
                flush=True,
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
