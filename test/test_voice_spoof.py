"""Voice spoof path — fail open, never solo-block, feature extract works offline."""
import numpy as np

from VishGuard.vish_mlm.voice_spoof import extract_features, score_file, _heuristic_risk
from common.vish.adapter import screen_call
from common.vish.contract import CallEvent, CallKitAction


def test_feature_dim_stable():
    rng = np.random.default_rng(1)
    x = rng.normal(size=16000).astype(np.float32) * 0.1
    f = extract_features(x, 16000)
    assert f.shape == (22,)


def test_missing_file_fail_open():
    out = score_file("/tmp/nullpoint-no-such-voicemail.wav")
    assert out["ok"] is False
    assert out["risk"] == 0.0


def test_voice_alone_never_blocks(tmp_path):
    # Write a tiny PCM wav via wave module
    import wave
    path = tmp_path / "t.wav"
    sr = 16000
    t = np.linspace(0, 1.0, sr, endpoint=False)
    sig = (0.4 * np.sin(2 * np.pi * 440 * t) * 32767).astype(np.int16)
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(sr)
        w.writeframes(sig.tobytes())
    scored = score_file(str(path))
    assert scored["ok"] is True
    ev = CallEvent(
        caller_id="+15555550100",
        transcript=None,
        raw={"audio_path": str(path)},
    )
    result = screen_call(ev)
    assert result.action != CallKitAction.BLOCK
    assert "voice" in result.paths


def test_heuristic_flat_spectrum_raises():
    # Clean multi-tone → higher flatness-ish heuristic
    t = np.linspace(0, 1.0, 16000, endpoint=False)
    sig = (0.3 * np.sin(2 * np.pi * 220 * t) + 0.3 * np.sin(2 * np.pi * 880 * t)).astype(np.float32)
    f = extract_features(sig, 16000)
    assert _heuristic_risk(f) >= 0.15
