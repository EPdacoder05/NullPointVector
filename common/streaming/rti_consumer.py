"""
Backpressure-aware streaming consumer for real-time intercept (RTI) channels.

Design goals (per the System-Design reference: bounded resources, predictable
latency, horizontal scalability):

    producer(s) ─▶ bounded queue ─▶ worker pool ─▶ handler ─▶ on_verdict sink
                       │                                 │
                  backpressure                    per-msg verdict

  * Bounded queue  → memory is O(maxsize), never unbounded. When full, the
    drop_policy decides: BLOCK (apply backpressure to producers) or DROP_NEW
    (shed load, increment a counter) — never silently OOM.
  * Worker pool    → N threads give parallelism for the I/O + CPU mix of a
    single-message verdict (classifier is sub-ms; DB sink is the slow part).
  * Decoupled      → the consumer knows nothing about SMS/voice/Kafka/webhooks;
    any producer just calls `submit(record)`. This is what lets one process
    front many sources, and many processes (pods) share one external queue
    (Kafka/SQS) for true millions-scale fan-out.

Complexity: submit O(1); throughput ≈ workers / handler_latency. For millions of
events, scale horizontally (partition by channel/shard) — this class is the
per-pod unit.
"""
from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class DropPolicy(str, Enum):
    BLOCK = "block"        # apply backpressure to the producer (default)
    DROP_NEW = "drop_new"  # shed the incoming record under overload


@dataclass
class StreamStats:
    submitted: int = 0
    processed: int = 0
    dropped: int = 0
    errors: int = 0
    retried: int = 0
    dead_lettered: int = 0
    threats: int = 0
    total_latency_s: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def snapshot(self) -> dict:
        with self._lock:
            avg = (self.total_latency_s / self.processed) if self.processed else 0.0
            return {
                "submitted": self.submitted, "processed": self.processed,
                "dropped": self.dropped, "errors": self.errors,
                "retried": self.retried, "dead_lettered": self.dead_lettered,
                "threats": self.threats, "avg_latency_ms": round(avg * 1000, 3),
            }


class RTIConsumer:
    """
    A bounded worker-pool stream consumer.

    handler(record) -> verdict        : the per-message work (e.g. risk.assess).
    on_verdict(record, verdict)        : optional sink (store threat, alert…).
    """

    def __init__(
        self,
        handler: Callable[[dict], object],
        *,
        workers: int = 4,
        maxsize: int = 10_000,
        on_verdict: Optional[Callable[[dict, object], None]] = None,
        is_threat: Callable[[object], bool] = lambda v: bool(getattr(v, "is_threat", False)),
        drop_policy: DropPolicy = DropPolicy.BLOCK,
        max_retries: int = 2,
        retry_backoff: float = 0.2,
        on_dead_letter: Optional[Callable[[dict, Exception], None]] = None,
        name: str = "rti",
    ):
        self.handler = handler
        self.on_verdict = on_verdict
        self.is_threat = is_threat
        self.drop_policy = drop_policy
        # Resilience: a transient handler/sink failure (e.g. DB blip) is retried
        # with backoff; if it still fails, the record is dead-lettered (durable)
        # rather than dropped — no silent data loss.
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff
        self.on_dead_letter = on_dead_letter
        self.name = name
        self.workers = workers
        self._q: "queue.Queue[Optional[dict]]" = queue.Queue(maxsize=maxsize)
        self._threads: list[threading.Thread] = []
        self._running = False
        self.stats = StreamStats()

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> "RTIConsumer":
        if self._running:
            return self
        self._running = True
        for i in range(self.workers):
            t = threading.Thread(target=self._worker, name=f"{self.name}-w{i}", daemon=True)
            t.start()
            self._threads.append(t)
        logger.info("RTIConsumer[%s] started with %d workers (maxsize=%d)",
                    self.name, self.workers, self._q.maxsize)
        return self

    def submit(self, record: dict, timeout: Optional[float] = None) -> bool:
        """Enqueue a record. Returns False if dropped (DROP_NEW policy under load)."""
        with self.stats._lock:
            self.stats.submitted += 1
        if self.drop_policy is DropPolicy.DROP_NEW:
            try:
                self._q.put_nowait(record)
                return True
            except queue.Full:
                with self.stats._lock:
                    self.stats.dropped += 1
                return False
        self._q.put(record, timeout=timeout)  # BLOCK = backpressure
        return True

    def stop(self, drain: bool = True, timeout: float = 10.0):
        if not self._running:
            return
        if drain:
            self._q.join()
        self._running = False
        for _ in self._threads:
            self._q.put(None)  # poison pill per worker
        for t in self._threads:
            t.join(timeout=timeout)
        self._threads.clear()
        logger.info("RTIConsumer[%s] stopped. stats=%s", self.name, self.stats.snapshot())

    # ------------------------------------------------------------------ worker
    def _worker(self):
        while True:
            record = self._q.get()
            if record is None:  # poison pill
                self._q.task_done()
                break
            start = time.perf_counter()
            last_exc: Optional[Exception] = None
            try:
                for attempt in range(self.max_retries + 1):
                    try:
                        verdict = self.handler(record)
                        if self.on_verdict is not None:
                            self.on_verdict(record, verdict)
                        with self.stats._lock:
                            self.stats.processed += 1
                            self.stats.total_latency_s += time.perf_counter() - start
                            if self.is_threat(verdict):
                                self.stats.threats += 1
                        last_exc = None
                        break
                    except Exception as e:  # transient failure → retry w/ backoff
                        last_exc = e
                        with self.stats._lock:
                            self.stats.errors += 1
                            if attempt < self.max_retries:
                                self.stats.retried += 1
                        if attempt < self.max_retries:
                            time.sleep(self.retry_backoff * (attempt + 1))
                if last_exc is not None:
                    # Retries exhausted: hand off to the dead-letter sink so the
                    # record is preserved durably, then continue (never crash).
                    logger.error("RTIConsumer[%s] handler failed after %d tries: %s",
                                 self.name, self.max_retries + 1, last_exc)
                    if self.on_dead_letter is not None:
                        try:
                            self.on_dead_letter(record, last_exc)
                            with self.stats._lock:
                                self.stats.dead_lettered += 1
                        except Exception as dle:
                            logger.error("RTIConsumer[%s] dead-letter sink failed: %s",
                                         self.name, dle)
            finally:
                self._q.task_done()
