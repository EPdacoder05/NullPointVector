"""
Sibling-channel memory — phish / smish / vish share crumbs, not weights.

Each channel keeps its own champion model. This store lets them “compare notes”:
same phone, same look-alike domain, same sentiment tags → raise shared risk on
the next message in any channel. Durable path is still per-channel feedback +
nightly gated retrain; this is a light cross-correlation layer.
"""
from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("cross_channel")

_REPO = Path(__file__).resolve().parents[2]
_PATH = _REPO / "data" / "cross_channel_crumbs.jsonl"
_PHONE_RE = re.compile(r"(\+?\d[\d\-\.\s()]{7,}\d)")
_DOMAIN_RE = re.compile(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")


def _entity_keys(record: dict) -> list[str]:
    keys = []
    sender = str(record.get("from") or record.get("sender") or record.get("caller_id") or "")
    body = str(record.get("body") or record.get("text") or record.get("transcript")
               or record.get("subject") or "")
    blob = f"{sender} {body}"
    for m in _PHONE_RE.findall(blob):
        digits = re.sub(r"\D", "", m)
        if len(digits) >= 10:
            keys.append(f"phone:{digits[-10:]}")
    for m in _DOMAIN_RE.findall(sender):
        keys.append(f"domain:{m.lower()}")
    # bare sender as alpha shortcode
    if sender and "@" not in sender and re.fullmatch(r"[A-Za-z]{3,15}", sender.strip()):
        keys.append(f"alpha:{sender.strip().upper()}")
    return keys[:6]


def share_grade_crumb(channel: str, record: dict, *, is_threat: bool,
                      deltas: Optional[list] = None) -> None:
    keys = _entity_keys(record)
    if not keys:
        return
    row = {
        "ts": time.time(),
        "channel": channel,
        "label": 1 if is_threat else 0,
        "entities": keys,
        "delta_features": [d.get("feature") for d in (deltas or [])[:5]],
    }
    try:
        _PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.debug("crumb write failed: %s", e)


def lookup_entity_risk(record: dict, limit: int = 40) -> dict[str, Any]:
    """How often sibling channels labeled related entities as threats recently."""
    keys = set(_entity_keys(record))
    if not keys or not _PATH.exists():
        return {"hits": 0, "threat_hits": 0, "channels": [], "boost": 0.0}
    threat = 0
    hits = 0
    channels = set()
    try:
        lines = _PATH.read_text(encoding="utf-8").splitlines()[-500:]
        for line in reversed(lines):
            if hits >= limit:
                break
            try:
                row = json.loads(line)
            except Exception:
                continue
            ents = set(row.get("entities") or [])
            if not ents & keys:
                continue
            hits += 1
            channels.add(row.get("channel") or "?")
            if int(row.get("label") or 0) == 1:
                threat += 1
    except Exception as e:
        logger.debug("crumb read failed: %s", e)
        return {"hits": 0, "threat_hits": 0, "channels": [], "boost": 0.0}
    boost = min(0.25, 0.05 * threat) if threat else 0.0
    return {
        "hits": hits,
        "threat_hits": threat,
        "channels": sorted(channels),
        "boost": round(boost, 3),
    }
