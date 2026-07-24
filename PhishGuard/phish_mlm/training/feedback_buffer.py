"""
Durable, append-only feedback buffer.

WHY THIS REPLACES instant single-step partial_fit():
    The old learn_from_feedback() did one SGD step and immediately overwrote the
    on-disk model. That is a poisoning vector — a single mislabeled email (or a
    malicious "mark as safe" click) permanently corrupts the champion with no
    review and no rollback.

    Instead, feedback is APPENDED here (cheap, O(1), durable). The Trainer later
    folds the buffer into a full retrain that must pass the golden gate before it
    can be promoted. The running process may still do an *ephemeral* in-memory
    update for responsiveness, but the durable champion only changes via the gate.

Format: JSON Lines (one record per line) — append-only, crash-safe, greppable.
    {"ts": 1716950000.0, "label": 1, "source": "user", "email": {...}}

Complexity: append O(1); load_all O(N); reservoir_sample O(N) time, O(k) space.
"""
import json
import random
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional


class FeedbackBuffer:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, email_data: dict, label: int, source: str = "user") -> None:
        """Thread-safe O(1) append of one labeled feedback record."""
        record = {
            "ts": time.time(),
            "label": int(label),
            "source": source,
            "email": email_data,
        }
        line = json.dumps(record, ensure_ascii=False)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def load_all(self) -> List[Dict]:
        """Load every valid record (bad lines skipped, never raises)."""
        if not self.path.exists():
            return []
        rows = []
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return rows

    def count(self) -> int:
        if not self.path.exists():
            return 0
        with open(self.path, "r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())

    def reservoir_sample(self, k: int, seed: Optional[int] = None) -> List[Dict]:
        """
        Uniform random sample of up to `k` records in O(N) time / O(k) space.
        Used to cap training-set size while keeping the distribution representative
        (prevents unbounded growth from poisoning recency bias).
        """
        rng = random.Random(seed)
        sample: List[Dict] = []
        for i, row in enumerate(self.load_all()):
            if i < k:
                sample.append(row)
            else:
                j = rng.randint(0, i)
                if j < k:
                    sample[j] = row
        return sample

    def archive(self) -> Optional[Path]:
        """Roll the buffer to a timestamped file (called after a successful retrain)."""
        if not self.path.exists() or self.count() == 0:
            return None
        stamp = time.strftime("%Y%m%d_%H%M%S")
        dest = self.path.with_name(f"{self.path.stem}_{stamp}.jsonl")
        with self._lock:
            self.path.replace(dest)
        return dest
