#!/usr/bin/env python3
"""Train voice spoof ExtraTrees on feature vectors. Gate before write.

Expects a JSONL of {"path": "...wav", "label": 0|1} (1=spoof).
Or --synth-smoke to train a tiny toy model for CI wiring only.

  python scripts/train_voice_spoof.py --manifest data/voice_spoof/manifest.jsonl
  python scripts/train_voice_spoof.py --synth-smoke
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

OUT = ROOT / "VishGuard" / "vish_mlm" / "models" / "voice_spoof_et.pkl"


def _load_rows(manifest: Path):
    from VishGuard.vish_mlm.voice_spoof import extract_features, _load_wav_mono, _resample, _TARGET_SR
    X, y = [], []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        samples, sr, err = _load_wav_mono(row["path"])
        if err or samples is None:
            continue
        feat = extract_features(_resample(samples, sr, _TARGET_SR), _TARGET_SR)
        X.append(feat)
        y.append(int(row["label"]))
    return np.asarray(X, dtype=np.float32), np.asarray(y, dtype=np.int32)


def _synth_smoke(n: int = 80):
    from VishGuard.vish_mlm.voice_spoof import extract_features, _TARGET_SR
    rng = np.random.default_rng(7)
    X, y = [], []
    for i in range(n):
        t = np.linspace(0, 1.5, int(_TARGET_SR * 1.5), endpoint=False)
        if i % 2 == 0:
            # "bona fide-ish": noisy, less flat
            sig = 0.2 * np.sin(2 * np.pi * 180 * t)
            sig += 0.05 * rng.normal(size=t.size)
            y.append(0)
        else:
            # "spoof-ish": clean multi-tone
            sig = 0.3 * np.sin(2 * np.pi * 220 * t) + 0.2 * np.sin(2 * np.pi * 440 * t)
            y.append(1)
        X.append(extract_features(sig.astype(np.float32), _TARGET_SR))
    return np.asarray(X, dtype=np.float32), np.asarray(y, dtype=np.int32)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", type=Path, default=None)
    ap.add_argument("--synth-smoke", action="store_true")
    ap.add_argument("--write", action="store_true", help="Write pkl only if gate passes")
    args = ap.parse_args()
    if args.synth_smoke:
        X, y = _synth_smoke()
    elif args.manifest and args.manifest.is_file():
        X, y = _load_rows(args.manifest)
    else:
        print("Need --manifest or --synth-smoke", file=sys.stderr)
        return 2
    if X.shape[0] < 20:
        print(f"too few rows: {X.shape[0]}", file=sys.stderr)
        return 2
    from sklearn.ensemble import ExtraTreesClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import roc_auc_score
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=7, stratify=y)
    clf = ExtraTreesClassifier(
        n_estimators=120, max_depth=12, min_samples_leaf=2,
        random_state=7, n_jobs=-1, class_weight="balanced",
    )
    clf.fit(Xtr, ytr)
    proba = clf.predict_proba(Xte)[:, list(clf.classes_).index(1)]
    auc = float(roc_auc_score(yte, proba))
    # Gate: smoke must separate; real data should clear 0.75 AUC before promote.
    floor = 0.65 if args.synth_smoke else 0.75
    print(json.dumps({"rows": int(X.shape[0]), "auc": round(auc, 4), "floor": floor}))
    if auc < floor:
        print("GATE FAIL — not writing model", file=sys.stderr)
        return 1
    if not args.write:
        print("GATE PASS — pass --write to save")
        return 0
    import joblib
    OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": clf, "auc": auc, "feature_dim": int(X.shape[1])}, OUT)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
