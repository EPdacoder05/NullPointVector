"""
Homograph / confusable mitigation.

Problem (not encoding): attackers swap Latin letters for look-alikes from
Cyrillic/Greek (е U+0435 vs e U+0065) so banned-word lists and humans both miss.

Defense layers we apply:
  1. DETECT  — mixed scripts / confusable chars → HOMOGRAPH reason code
  2. FOLD    — map look-alikes → Latin before keyword / brand lexicon checks
  3. PUNYCODE — flag xn-- IDN hosts (often the wire form of homograph domains)
  4. EXPLAIN — show the real code point so humans see the trick

We do NOT strip non-Latin from TF-IDF training (that would hide signal).
Folding is for rules/lexicons and explainability only.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Optional

# Common confusables → ASCII Latin (subset; expand as we see live attacks).
_CONFUSABLE_MAP = str.maketrans({
    # Cyrillic
    "а": "a", "А": "A",
    "е": "e", "Е": "E",
    "о": "o", "О": "O",
    "р": "p", "Р": "P",
    "с": "c", "С": "C",
    "у": "y", "У": "Y",
    "х": "x", "Х": "X",
    "і": "i", "І": "I",
    "ј": "j",
    "ѕ": "s",
    "һ": "h",
    "ԛ": "q",
    "ԝ": "w",
    "ѵ": "v",
    # Greek
    "α": "a", "Α": "A",
    "ο": "o", "Ο": "O",
    "ν": "v",
    "ρ": "p", "Ρ": "P",
    "τ": "t",
    "χ": "x",
    "η": "n",
    "ι": "i",
    "κ": "k",
    "μ": "m",
    "ε": "e",
})

_TOKEN_RE = re.compile(
    r"[A-Za-z\u0370-\u03FF\u0400-\u04FF][A-Za-z0-9\u0370-\u03FF\u0400-\u04FF._\-]{1,}",
)


def fold_confusables(text: str) -> str:
    """Map common look-alikes to Latin, then NFKC-normalize."""
    if not text:
        return ""
    return unicodedata.normalize("NFKC", text.translate(_CONFUSABLE_MAP))


def script_of(ch: str) -> Optional[str]:
    if not ch.isalpha():
        return None
    name = unicodedata.name(ch, "")
    if "CYRILLIC" in name:
        return "cyrillic"
    if "GREEK" in name:
        return "greek"
    if "LATIN" in name or ord(ch) < 128:
        return "latin"
    if "ARABIC" in name:
        return "arabic"
    return "other"


def detect_mixed_script_tokens(text: str, limit: int = 5) -> list[dict]:
    """Tokens that mix Latin with Cyrillic/Greek (classic homograph)."""
    hits = []
    for m in _TOKEN_RE.finditer(text or ""):
        tok = m.group(0)
        scripts = set()
        odd = []
        for ch in tok:
            s = script_of(ch)
            if not s:
                continue
            scripts.add(s)
            if s in ("cyrillic", "greek"):
                odd.append((ch, f"U+{ord(ch):04X}", s))
        if "latin" in scripts and odd:
            ch, code, scr = odd[0]
            hits.append({
                "token": tok[:64],
                "char": ch,
                "code": code,
                "script": scr,
                "evidence": (
                    f"“{tok[:40]}” mixes Latin with {scr} {ch} ({code}) — "
                    f"looks like “{fold_confusables(tok)[:40]}”"
                ),
            })
            if len(hits) >= limit:
                break
    return hits


def has_punycode(text: str) -> list[str]:
    """Return xn-- labels found (IDN / punycode form of non-ASCII domains)."""
    found = []
    for m in re.finditer(r"\b(xn--[a-z0-9-]+)", (text or "").lower()):
        found.append(m.group(1))
    return found[:5]


def scan(text: str) -> dict:
    """Full homograph scan for explain + structural soft signals."""
    mixed = detect_mixed_script_tokens(text or "")
    puny = has_punycode(text or "")
    return {
        "mixed_script": mixed,
        "punycode": puny,
        "folded": fold_confusables(text or ""),
        "hit": bool(mixed or puny),
    }
