#!/usr/bin/env python3
"""Refresh data/benchmark_snapshot.json (golden + light latency). Run off the request path."""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.bench_snapshot import refresh_snapshot, _PATH  # noqa: E402


def main() -> int:
    print("Refreshing benchmark snapshot (this loads models once)…", flush=True)
    try:
        out = refresh_snapshot(latency_n=0)
    except Exception as e:
        print("FAILED:", e, flush=True)
        return 1
    print("Wrote", _PATH, flush=True)
    for ch, m in (out.get("quality") or {}).items():
        if m.get("available"):
            print(
                f"  {ch}: acc={m.get('accuracy')} fpr={m.get('fpr')} gate={m.get('gate_pass')}",
                flush=True,
            )
        else:
            print(f"  {ch}: {m.get('reason')}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
