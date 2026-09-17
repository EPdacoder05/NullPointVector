"""On-disk vishing campaign packs (CID/TFN lists + script fingerprints).

Used by Call Directory seeding AND live screen. A new DID running a known
script should not require a human to paste the number if we have a transcript
or the number is already in a pack.
"""
from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Optional

logger = logging.getLogger("vish.campaigns")

_PACK_DIR = Path(__file__).resolve().parents[2] / "data" / "vish_campaigns"
_CAMPAIGN_BLOCK_RISK = 0.92


def _digits10(raw: str) -> str:
    digits = re.sub(r"\D", "", raw or "")[-10:]
    return digits if len(digits) == 10 else ""


@lru_cache(maxsize=1)
def _packs() -> tuple[dict, ...]:
    out: list[dict] = []
    if not _PACK_DIR.is_dir():
        return tuple(out)
    for path in sorted(_PACK_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning("campaign pack %s: %s", path.name, e)
            continue
        if not isinstance(data, dict):
            continue
        data = dict(data)
        data["_stem"] = path.stem
        out.append(data)
    return tuple(out)


def reload_packs() -> None:
    _packs.cache_clear()


def campaign_for_number(raw: str) -> Optional[dict]:
    """Return pack dict if this CID/TFN is in a pack block list."""
    needle = _digits10(raw)
    if not needle:
        return None
    for pack in _packs():
        cid = str(pack.get("campaign_id") or pack.get("_stem") or "campaign")
        for item in pack.get("block") or []:
            if _digits10(str(item)) == needle:
                return {
                    "campaign_id": cid,
                    "label": str(pack.get("label") or "Known scam campaign"),
                    "risk": _CAMPAIGN_BLOCK_RISK,
                    "match": "number",
                }
    return None


def campaign_for_transcript(transcript: str) -> Optional[dict]:
    """Fingerprint match: two or more pack phrases in the voicemail/SMS text."""
    text = (transcript or "").lower()
    if len(text) < 20:
        return None
    best: Optional[dict] = None
    best_hits = 0
    for pack in _packs():
        phrases = [str(p).lower() for p in (pack.get("phrases") or []) if str(p).strip()]
        if len(phrases) < 2:
            continue
        hits = sum(1 for p in phrases if p in text)
        if hits >= 2 and hits > best_hits:
            best_hits = hits
            cid = str(pack.get("campaign_id") or pack.get("_stem") or "campaign")
            best = {
                "campaign_id": cid,
                "label": str(pack.get("label") or "Known scam campaign"),
                "risk": _CAMPAIGN_BLOCK_RISK,
                "match": "script",
                "phrase_hits": hits,
            }
    return best


def campaign_hit(caller_id: str, transcript: str = "") -> Optional[dict]:
    return campaign_for_number(caller_id) or campaign_for_transcript(transcript)


def all_campaign_phrases() -> list[str]:
    """Deduped phrase list for on-device SMS Filter (no JWT)."""
    seen: set[str] = set()
    out: list[str] = []
    for pack in _packs():
        for raw in pack.get("phrases") or []:
            phrase = str(raw).strip()
            key = phrase.lower()
            if len(phrase) < 4 or key in seen:
                continue
            seen.add(key)
            out.append(phrase)
    return out
