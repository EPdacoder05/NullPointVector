#!/usr/bin/env python3
"""
Reproducible model-artifact regeneration for all three guards.

WHY: the committed .pkl artifacts must be rebuilt under the SAME (pinned) ML
stack the runtime uses. Otherwise train/serve version skew makes unpickling warn
or fail, which silently triggers a per-boot cold-start retrain — non-reproducible
verdicts and a cold-start tax on every container start.

WHAT THIS DOES (deterministic; seeds are fixed in the detectors):
  1. Force a fresh cold-start train for phishing / smishing / vishing, which
     persists each .pkl stamped with the current sklearn/numpy/scipy versions.
  2. Score each against its held-out golden set (the CI gate thresholds).
  3. Write models/REPRO_MANIFEST.json: per-channel feature_version, stack
     versions, artifact sha256 + size, and golden metrics + gate pass/fail.

Run inside the app image so it uses the pinned stack:
    docker compose exec app python scripts/regenerate_artifacts.py
"""
from __future__ import annotations

import hashlib
import importlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from common.ml.channel_detector import stack_versions  # noqa: E402
from common.streaming.channel_pipeline import normalize  # noqa: E402
from PhishGuard.phish_mlm.eval.evaluate import evaluate, passes_gate  # noqa: E402

CHANNELS = {
    "phishing": {"module": "PhishGuard.phish_mlm.phishing_detector",
                 "golden": "PhishGuard/phish_mlm/eval/golden_eval.jsonl", "normalize": False},
    "smishing": {"module": "SmishGuard.smish_mlm.smishing_detector",
                 "golden": "SmishGuard/smish_mlm/eval/golden_smish.jsonl", "normalize": True},
    "vishing":  {"module": "VishGuard.vish_mlm.vishing_detector",
                 "golden": "VishGuard/vish_mlm/eval/golden_vish.jsonl", "normalize": True},
}
MANIFEST_PATH = ROOT / "models" / "REPRO_MANIFEST.json"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _golden_metrics(channel: str, cfg: dict, detector) -> dict:
    gp = ROOT / cfg["golden"]
    if not gp.exists():
        return {"error": f"missing golden set {cfg['golden']}"}
    rows = [json.loads(l) for l in gp.read_text().splitlines() if l.strip()]
    if cfg["normalize"]:
        norm = []
        for r in rows:
            nr = normalize(channel, r)
            for k in ("label", "tags"):
                if k in r:
                    nr[k] = r[k]
            norm.append(nr)
        rows = norm
    m = evaluate(detector, rows)
    return {"n": m["n"], "accuracy": round(m["accuracy"], 4),
            "recall": round(m["recall"], 4), "fpr": round(m["fpr"], 4),
            "confusion": m["confusion"], "gate_pass": bool(passes_gate(m))}


def regenerate(channel: str, cfg: dict) -> dict:
    mod = importlib.import_module(cfg["module"])
    det = mod.detector
    print(f"[{channel}] regenerating artifact …", flush=True)
    det._cold_start_training()  # retrain from fixed seed corpus + persist (stamped)

    model_path = Path(getattr(det, "model_path", None) or getattr(mod, "MODEL_PATH"))
    feature_version = getattr(det, "num_features", None)
    if feature_version is None:
        feature_version = getattr(mod, "NUM_STRUCTURAL_FEATURES", None)

    entry = {
        "feature_version": feature_version,
        "stack": stack_versions(),
        "artifact": str(model_path.relative_to(ROOT)) if model_path.is_absolute() else str(model_path),
        "sha256": _sha256(model_path) if model_path.exists() else None,
        "bytes": model_path.stat().st_size if model_path.exists() else None,
        "golden": _golden_metrics(channel, cfg, det),
    }
    g = entry["golden"]
    print(f"[{channel}] feature_version={feature_version} "
          f"sha256={entry['sha256'][:12] if entry['sha256'] else 'NA'} "
          f"golden={g.get('accuracy')} gate={g.get('gate_pass')}", flush=True)
    return entry


def main() -> int:
    manifest = {"generated_at": datetime.now(timezone.utc).isoformat(),
                "stack": stack_versions(), "channels": {}}
    ok = True
    for channel, cfg in CHANNELS.items():
        try:
            entry = regenerate(channel, cfg)
            manifest["channels"][channel] = entry
            if entry["golden"].get("gate_pass") is False:
                ok = False
        except Exception as e:  # keep going; record the failure
            manifest["channels"][channel] = {"error": str(e)}
            ok = False
            print(f"[{channel}] FAILED: {e}", flush=True)

    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2))
    print(f"\nWrote {MANIFEST_PATH.relative_to(ROOT)}")
    print("ALL GATES PASS" if ok else "ONE OR MORE GATES FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
