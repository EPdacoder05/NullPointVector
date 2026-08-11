"""
External-feed → training-seed connectors (R3 seed expansion).

Folds labeled SMS/voice corpora from outside sources into the channel training set
so Smish/Vish learn from real-world data beyond the hand-written cold-start seed.

Two connector kinds, both FAIL-SAFE and OFFLINE-SAFE (a missing source yields []
so a retrain never depends on an external system being reachable):

  1. LOCAL DROP-IN  (works today, no keys):
        Drop labeled JSON Lines into  data/seed/<channel>/*.jsonl
        Each line: {"label": 0|1, "body"/"transcript": "...", "from": "..."}
        (Point SEED_DIR elsewhere via env if you keep corpora outside the repo,
         e.g. the Phishy_Bizz exports or downloaded Robokiller/FTC dumps.)

  2. HTTP CONNECTORS (env-keyed, opt-in):
        Register a source URL + key; the connector pulls a labeled corpus and maps
        it to channel records. Disabled automatically when the env var is absent.

To add an HTTP source: add an entry to ``_HTTP_SOURCES`` keyed by channel.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import List, Tuple

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[3]

# channel → (text field candidates) used to normalize incoming rows
_TEXT_FIELDS = {
    "smishing": ("body", "message", "text"),
    "vishing": ("transcript", "body", "text"),
}


def _seed_dir(channel: str) -> Path:
    base = os.getenv("SEED_DIR", str(_REPO_ROOT / "data" / "seed"))
    return Path(base) / channel


def _normalize_row(channel: str, raw: dict) -> Tuple[dict, int] | None:
    """Map an arbitrary labeled row to (channel-record, label). None if unusable."""
    if "label" not in raw:
        return None
    text = ""
    for f in _TEXT_FIELDS.get(channel, ("body", "text")):
        if raw.get(f):
            text = str(raw[f]); break
    if not text:
        return None
    sender = str(raw.get("from") or raw.get("sender") or raw.get("caller_id") or "")
    rec = {"body": text, "transcript": text, "from": sender, "caller_id": sender}
    try:
        return rec, int(raw["label"])
    except (TypeError, ValueError):
        return None


def _from_local_dropins(channel: str) -> List[Tuple[dict, int]]:
    d = _seed_dir(channel)
    if not d.exists():
        return []
    out: List[Tuple[dict, int]] = []
    for fp in sorted(d.glob("*.jsonl")):
        try:
            with open(fp, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    norm = _normalize_row(channel, row)
                    if norm:
                        out.append(norm)
        except Exception as e:
            logger.warning("seed connector: failed reading %s: %s", fp, e)
    if out:
        logger.info("seed connector[%s]: %d rows from local drop-ins (%s)",
                    channel, len(out), d)
    return out


# Map: channel → list of (env_key_for_url, env_key_for_token) HTTP sources.
# Absent env vars → source skipped. Wire real endpoints here when you have keys.
_HTTP_SOURCES = {
    "smishing": [("SMISH_SEED_URL", "SMISH_SEED_TOKEN")],
    "vishing": [("VISH_SEED_URL", "VISH_SEED_TOKEN")],
}


def _from_http(channel: str) -> List[Tuple[dict, int]]:
    sources = _HTTP_SOURCES.get(channel, [])
    out: List[Tuple[dict, int]] = []
    for url_key, tok_key in sources:
        url = os.getenv(url_key, "").strip()
        if not url:
            continue
        try:
            import requests
            headers = {}
            tok = os.getenv(tok_key, "").strip()
            if tok:
                headers["Authorization"] = f"Bearer {tok}"
            timeout = float(os.getenv("SEED_HTTP_TIMEOUT", "10.0"))
            resp = requests.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            rows = data.get("rows", data) if isinstance(data, dict) else data
            for row in rows or []:
                norm = _normalize_row(channel, row)
                if norm:
                    out.append(norm)
            logger.info("seed connector[%s]: %d rows from %s", channel, len(out), url_key)
        except Exception as e:
            logger.warning("seed connector[%s]: HTTP source %s failed: %s",
                           channel, url_key, e)
    return out


def collect_channel_seed(channel: str) -> List[Tuple[dict, int]]:
    """All external seed rows for a channel (local drop-ins + HTTP). Never raises."""
    rows: List[Tuple[dict, int]] = []
    try:
        rows.extend(_from_local_dropins(channel))
        rows.extend(_from_http(channel))
    except Exception as e:  # belt-and-suspenders: training must never break on seed IO
        logger.warning("seed connector[%s] failed: %s", channel, e)
    return rows
