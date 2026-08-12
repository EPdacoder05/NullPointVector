# Voice spoof training data (local, gitignored)

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
