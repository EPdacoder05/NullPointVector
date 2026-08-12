"""Voicemail deepfake / synthetic-speech risk (VishGuard deep path).

Fail open. Never solo-BLOCK. CPU-first DSP features → sklearn tree when trained.
Adversarial posture (what a smarter attacker will try):
  - Codec laundering (re-encode to hide TTS artifacts)
  - Silence padding / clip chopping to dodge duration priors
  - Replay through a phone speaker (acoustic channel)
  - Ultra-clean studio TTS that never saw telephony
  - Oversized / corrupt / non-audio uploads (DoS / parser bombs)

We bound decode, score multiple feature families, and cap influence in the fuser.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Optional

import numpy as np

logger = logging.getLogger("voice_spoof")

_MAX_BYTES = 12 * 1024 * 1024
_MAX_SECONDS = 90.0
_TARGET_SR = 16000
_MODEL_PATH = Path(__file__).resolve().parent / "models" / "voice_spoof_et.pkl"


def _load_wav_mono(path: str) -> tuple[Optional[np.ndarray], int, Optional[str]]:
    """Load audio as float32 mono. Returns (samples, sr, error_code).

    Duration is checked *before* allocating a full decode buffer when metadata
    is available (soundfile.info / wave headers). Fail open on decode errors.
    """
    p = Path(path)
    try:
        if not p.is_file():
            return None, 0, "missing_file"
        size = p.stat().st_size
        if size <= 44 or size > _MAX_BYTES:
            return None, 0, "bad_size"

        # Metadata-first path (optional dependency).
        try:
            import soundfile as sf  # type: ignore[import-not-found]
            info = sf.info(str(p))
            sr_meta = int(getattr(info, "samplerate", 0) or 0)
            frames = int(getattr(info, "frames", 0) or 0)
            if sr_meta <= 0 or frames <= 0:
                return None, 0, "bad_format"
            if frames / float(sr_meta) > _MAX_SECONDS:
                return None, 0, "too_long"
            # Cap frames read even if metadata lied.
            max_frames = int(_MAX_SECONDS * sr_meta) + 1
            data, sr = sf.read(str(p), always_2d=False, frames=max_frames)
            data = np.asarray(data, dtype=np.float32)
            if data.ndim > 1:
                data = data.mean(axis=1)
            if sr <= 0 or data.size == 0:
                return None, 0, "bad_format"
            if data.size / float(sr) > _MAX_SECONDS:
                return None, 0, "too_long"
            return data.astype(np.float32, copy=False), int(sr), None
        except Exception:
            pass

        import wave
        with wave.open(str(p), "rb") as w:
            if w.getnchannels() < 1 or w.getsampwidth() not in (1, 2):
                return None, 0, "bad_format"
            sr = int(w.getframerate() or 0)
            n = w.getnframes()
            if sr <= 0 or n <= 0:
                return None, 0, "bad_format"
            if n / float(sr) > _MAX_SECONDS:
                return None, 0, "too_long"
            raw = w.readframes(n)
            sw = w.getsampwidth()
            if sw == 1:
                data = (np.frombuffer(raw, dtype=np.uint8).astype(np.float32) - 128.0) / 128.0
            else:
                data = np.frombuffer(raw, dtype=np.int16).astype(np.float32) / 32768.0
            if w.getnchannels() > 1:
                data = data.reshape(-1, w.getnchannels()).mean(axis=1)
        return data.astype(np.float32, copy=False), int(sr), None
    except Exception as e:
        logger.warning("voice_spoof load failed: %s", e)
        return None, 0, "decode_error"


def _resample(x: np.ndarray, sr: int, target: int = _TARGET_SR) -> np.ndarray:
    if sr == target or x.size == 0:
        return x
    # Linear resample — dependency-free; good enough for feature stats.
    n = int(round(x.size * float(target) / float(sr)))
    if n < 8:
        return x[:0]
    xp = np.linspace(0.0, 1.0, num=x.size, endpoint=False)
    xq = np.linspace(0.0, 1.0, num=n, endpoint=False)
    return np.interp(xq, xp, x).astype(np.float32)


def extract_features(x: np.ndarray, sr: int = _TARGET_SR) -> np.ndarray:
    """Fixed-length feature vector. Order is part of the gate contract."""
    x = np.asarray(x, dtype=np.float32)
    if x.size < 256:
        return np.zeros(22, dtype=np.float32)
    # Energy / silence
    rms = float(np.sqrt(np.mean(x * x) + 1e-12))
    zcr = float(np.mean(np.abs(np.diff(np.signbit(x).astype(np.int8)))))
    silence = float(np.mean(np.abs(x) < 0.01))
    # Peakiness / clipping
    peak = float(np.max(np.abs(x)) + 1e-12)
    crest = float(rms / peak)
    clip = float(np.mean(np.abs(x) > 0.98))
    # Spectral via rFFT on a mid window (bounded)
    n = min(x.size, sr * 4)
    start = max(0, (x.size - n) // 2)
    win = x[start:start + n] * np.hanning(n).astype(np.float32)
    spec = np.abs(np.fft.rfft(win)) + 1e-12
    freqs = np.fft.rfftfreq(n, d=1.0 / sr)
    power = spec * spec
    ps = power / (np.sum(power) + 1e-12)
    centroid = float(np.sum(freqs * ps))
    bandwidth = float(np.sqrt(np.sum(((freqs - centroid) ** 2) * ps)))
    flatness = float(np.exp(np.mean(np.log(spec))) / (np.mean(spec) + 1e-12))
    # High-band energy (TTS often too smooth up high; telephony rolls off)
    hi = freqs >= 3400
    lo = freqs < 1000
    hi_ratio = float(np.sum(power[hi]) / (np.sum(power) + 1e-12))
    lo_ratio = float(np.sum(power[lo]) / (np.sum(power) + 1e-12))
    # Spectral rolloff 85%
    cump = np.cumsum(ps)
    roll_idx = int(np.searchsorted(cump, 0.85))
    rolloff = float(freqs[min(roll_idx, len(freqs) - 1)])
    # Mel-ish bands (8 triangular bags over 0-8k)
    mel = []
    edges = np.linspace(0, min(8000, sr / 2), 9)
    for i in range(8):
        m = (freqs >= edges[i]) & (freqs < edges[i + 1])
        mel.append(float(np.log(np.sum(power[m]) + 1e-12)))
    # Temporal jitter proxy: frame energy variance
    frame = max(64, sr // 50)
    energies = [float(np.mean(x[i:i + frame] ** 2)) for i in range(0, x.size - frame, frame)]
    e = np.asarray(energies, dtype=np.float32) if energies else np.zeros(1, dtype=np.float32)
    e_var = float(np.var(e))
    e_delta = float(np.mean(np.abs(np.diff(e)))) if e.size > 1 else 0.0
    # Duration priors (attackers pad silence — silence ratio already covers most)
    dur = float(x.size) / float(sr)
    vec = np.array(
        [rms, zcr, silence, crest, clip, centroid, bandwidth, flatness,
         hi_ratio, lo_ratio, rolloff, e_var, e_delta, dur] + mel,
        dtype=np.float32,
    )
    return vec


def _heuristic_risk(feat: np.ndarray) -> float:
    """Untrained fallback: telephony-ish real speech vs ultra-clean / robotic."""
    # indices match extract_features
    silence, flatness, hi_ratio, lo_ratio, clip = feat[2], feat[7], feat[8], feat[9], feat[4]
    risk = 0.15
    if flatness > 0.45 and silence < 0.35:
        risk += 0.25  # overly flat spectrum → synthetic
    if hi_ratio > 0.22 and lo_ratio < 0.25:
        risk += 0.2   # too much high-band for phone VM
    if silence > 0.85:
        risk += 0.15  # silence padding / empty lure
    if clip > 0.05:
        risk += 0.1
    return float(min(0.85, risk))


def _model_predict(feat: np.ndarray) -> Optional[float]:
    path = Path(os.getenv("VOICE_SPOOF_MODEL", str(_MODEL_PATH)))
    if not path.is_file():
        return None
    try:
        import joblib
        bundle = joblib.load(path)
        clf = bundle.get("model") if isinstance(bundle, dict) else bundle
        if clf is None:
            return None
        proba = clf.predict_proba(feat.reshape(1, -1))[0]
        # Assume class 1 = spoof
        classes = list(getattr(clf, "classes_", [0, 1]))
        if 1 in classes:
            return float(proba[classes.index(1)])
        return float(proba[-1])
    except Exception as e:
        logger.warning("voice_spoof model failed: %s", e)
        return None


def score_file(path: str) -> dict[str, Any]:
    """Score a voicemail file. Always returns a dict; never raises to callers."""
    out: dict[str, Any] = {
        "ok": False, "risk": 0.0, "codes": [], "path": "voice",
        "error": None, "source": "none",
    }
    samples, sr, err = _load_wav_mono(path)
    if err or samples is None:
        out["error"] = err or "decode_error"
        return out  # fail open — caller omits path
    try:
        x = _resample(samples, sr, _TARGET_SR)
        feat = extract_features(x, _TARGET_SR)
        model_risk = _model_predict(feat)
        heur = _heuristic_risk(feat)
        if model_risk is None:
            risk = heur
            out["source"] = "heuristic"
        else:
            # Blend: model primary, heuristic as floor against codec-laundered TTS
            risk = max(float(model_risk), heur * 0.6)
            out["source"] = "model+heuristic"
        codes = []
        if risk >= 0.55:
            codes.append("SYNTHETIC_VOICE_SUSPECTED")
        if feat[2] > 0.85:
            codes.append("VOICE_SILENCE_PAD")
        if feat[7] > 0.5:
            codes.append("VOICE_FLAT_SPECTRUM")
        out.update({"ok": True, "risk": float(min(0.92, risk)), "codes": codes})
        return out
    except Exception as e:
        logger.warning("voice_spoof score failed: %s", e)
        out["error"] = "score_error"
        return out


def score_event_audio(raw: Optional[dict]) -> Optional[dict[str, Any]]:
    """Pull audio_path / voicemail_path from CallEvent.raw. None → skip."""
    if not isinstance(raw, dict):
        return None
    path = raw.get("audio_path") or raw.get("voicemail_path") or raw.get("wav_path")
    if not path or not isinstance(path, str):
        return None
    return score_file(path)
