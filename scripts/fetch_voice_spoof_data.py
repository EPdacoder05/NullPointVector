#!/usr/bin/env python3
"""Fetch public voice-spoof research data (research licenses — read before commercial use).

ASVspoof 2019 LA is the main train set but usually needs an academic form.
This script:
  1) Creates data/voice_spoof/
  2) Documents the ASVspoof URL
  3) Optionally pulls a small WaveFake subset mirror if WAVEFAKE_URL is set

  mkdir -p data/voice_spoof
  python scripts/fetch_voice_spoof_data.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "data" / "voice_spoof"


def main() -> int:
    DEST.mkdir(parents=True, exist_ok=True)
    readme = DEST / "README.md"
    readme.write_text(
        """# Voice spoof training data (local, gitignored)

## ASVspoof 2019 Logical Access (primary)
1. Request / download from the ASVspoof organizers (research use).
2. Unpack so you have `LA/ASVspoof2019_LA_train/` wavs + protocol files.
3. Build a JSONL:
   `{"path": ".../wav/LA_T_....wav", "label": 0}` bona fide
   `{"path": "...", "label": 1}` spoof
4. Train:
   `python scripts/train_voice_spoof.py --manifest data/voice_spoof/manifest.jsonl --write`

## Augment before you trust the number
Resample to 8 kHz, μ-law, GSM — grandma's voicemail is not studio TTS.
Gate on a held-out phone-codec set, not only ASVspoof EER.

## In-the-Wild / WaveFake
Optional second eval. Do not ship a champion trained only on clean WaveFake.

Research licenses ≠ commercial rights. Production champion should include our own
graded voicemails + spoofs we synthesize.
""",
        encoding="utf-8",
    )
    print(f"wrote {readme}")
    url = (os.getenv("WAVEFAKE_URL") or "").strip()
    if not url:
        print("Set WAVEFAKE_URL to auto-download a mirror; ASVspoof still needs manual request.")
        return 0
    try:
        import urllib.request
        out = DEST / "wavefake_bundle.bin"
        print(f"downloading {url} → {out}")
        urllib.request.urlretrieve(url, out)
        print("done")
    except Exception as e:
        print(f"download failed: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
