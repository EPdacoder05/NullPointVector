# CallKit → VishGuard Data Contract (R1)

**Decision: HYBRID (reputation + transcription).** This is the spec the iOS
CallKit client builds against, and the backend honors. It is intentionally small
and stable so the Swift side can be developed independently of model internals.

Status: **implemented + tested** (backend). iOS client + live vendor keys are the
remaining work (see "What's needed from you").

---

## Why hybrid

CallKit hands the app a **call event + caller ID**, never an audio transcript.
VishGuard scores **text**. So we run two complementary paths and fuse them:

| Path | Runs when | Input | Strength |
|---|---|---|---|
| **Reputation** | every call (ring-time) | `caller_id` only | instant, zero audio; catches known-bad numbers |
| **Transcription** | voicemail / post-call / opt-in | `transcript` | catches NEW numbers running known scripts; gives the "why" |

The reputation path always runs. The transcription path runs only when a
transcript is supplied — so the **same endpoint** serves ring-time screening and
voicemail/post-call deep analysis.

```
CallEvent
   ├─ reputation path  (always)  ── score_number(caller_id) ─┐
   └─ transcription path (if transcript) ── VishGuard model ─┴─ fuse ─▶ ScreenResult
```

---

## Endpoint

```
POST /api/v1/vish/screen
Authorization: Bearer <JWT>        # role: analyst (service token for the app)
Content-Type: application/json
```

### Request (`CallEvent`)

```json
{
  "caller_id": "+18005551001",     // required; E.164, or alphanumeric sender id
  "phase": "incoming",             // incoming | voicemail | post_call
  "transcript": null,              // optional; present → deep path runs
  "direction": "inbound",          // inbound | outbound
  "contact_known": false,          // is the number in the user's contacts?
  "carrier_verified": null,        // STIR/SHAKEN attestation: true|false|null
  "timestamp": "2026-06-30T19:00:00Z",
  "device_id": "opaque-per-install"
}
```

### Response (`ScreenResult`)

```json
{
  "action": "block",               // allow | label | silence | block
  "is_threat": true,
  "risk": 0.93,                    // fused 0..1
  "verdict": "fraud",             // fraud | spam | neutral | unknown
  "label": "Likely IRS scam",     // short caller-id string for CallKit to display
  "reputation": {                  // reputation path result (always present)
    "number": "+18005551001", "risk": 0.9, "verdict": "fraud",
    "categories": ["irs_scam"], "sources": ["local","hiya"],
    "report_count": 4, "confidence": 0.9
  },
  "content": {                     // transcription path result (null if no transcript)
    "is_threat": true, "risk": 0.97, "confidence": 0.98,
    "anomaly_level": "HIGH", "reasons": ["..."], "action": "quarantine"
  },
  "reasons": ["Number flagged as IRS scam by 4 reports (sources: local, hiya).",
              "Pressure/urgency language", "Requests gift-card payment"],
  "paths": ["reputation", "transcription"]
}
```

### Action → CallKit mapping (recommended client behavior)

| `action` | CallKit behavior |
|---|---|
| `allow` | ring normally |
| `label` | ring, set caller display name to `label` (e.g. "Spam likely") |
| `silence` | report as suspicious → send to voicemail silently |
| `block` | block the call (high-confidence fraud) |

> Numbers in the user's contacts are never auto-`block`/`silence` — at most
> `label` — to avoid hiding important legitimate calls.

---

## Reputation provider framework

Vendor-agnostic and **env-keyed**: a provider with no API key is auto-disabled,
so the system ships now and lights up each feed when you drop a key in the env.
Results are fused (weighted-max + consensus boost) and Redis-cached (default 6h)
so we never re-bill a vendor for the same number.

| Provider | env key(s) | base-url env | cost | status |
|---|---|---|---|---|
| `local` (our own confirmed-threat history) | — always on | — | free | **live now** |
| `ftc` | `FTC_DNC_API_KEY` | `FTC_DNC_BASE_URL` | free | needs source/mirror |
| `nomorobo` | `NOMOROBO_API_KEY` | `NOMOROBO_BASE_URL` | paid | needs key |
| `hiya` | `HIYA_API_KEY` / `HIYA_TOKEN` | `HIYA_BASE_URL` | paid | needs key |
| `truecaller` | `TRUECALLER_API_KEY` | `TRUECALLER_BASE_URL` | paid | needs key |
| `robokiller` | `ROBOKILLER_API_KEY` | `ROBOKILLER_BASE_URL` | paid | needs key |

Add a vendor: subclass `_HTTPProvider` in `common/reputation/providers.py`, set
`name`/`env_key`/`base_url`, implement `_parse(number, json)`, register in
`_PROVIDER_CLASSES`. The `_parse` methods already assume common response shapes
(`spamScore`, `category`, `complaint_count`, …) — adjust per the vendor's real
schema when you have their docs.

---

## Files

| Piece | File |
|---|---|
| Data contract (schemas) | `common/vish/contract.py` |
| Hybrid fusion adapter | `common/vish/adapter.py` |
| Reputation core (fusion, normalize) | `common/reputation/base.py` |
| Providers (vendors) | `common/reputation/providers.py` |
| Aggregator (fan-out + cache) | `common/reputation/aggregator.py` |
| API endpoint | `api/main.py` → `POST /api/v1/vish/screen` |
| Local history lookup | `Autobot/VectorDB/NullPoint_Vector.py` → `get_threats_by_sender` |
| Tests | `test/test_vish_hybrid.py` |

---

## What's needed from YOU

### Apple / CallKit side (you do this)
1. **Apple Developer Program** membership (~$99/yr). CallKit isn't purchased — this
   account is what unlocks signing + distribution.
2. **Xcode project** for the iOS client with a **Call Directory extension**
   (caller-id labels / blocking) and optionally a **Live Voicemail / Speech**
   capability for the transcription path.
3. **Entitlements / capabilities**: Call Directory, (optional) Speech recognition,
   background fetch for periodic reputation-list refresh.
4. **App privacy**: privacy policy + App Store data-use disclosures (call metadata,
   optional transcript). Plan a **false-positive appeal/allow-list** UX.
5. **A service token**: the app authenticates to `/api/v1/vish/screen` with a
   scoped JWT (role `analyst`). Decide token issuance/rotation for the app.

> Transcription note: with the hybrid model, transcription is **optional** and runs
> on voicemail/opt-in, so the live ring-time experience never waits on audio.

### External feeds side (you provide keys; we wire them)
- For each vendor you have an account with (Hiya / Truecaller / Robokiller /
  Nomorobo / FTC mirror): the **API key**, the **base URL**, and their **response
  schema docs**. Drop the key in the env and we confirm the `_parse` mapping.
- Tell us which vendors are active so we prioritize their adapters.

### Data / training side (in progress)
- The external feeds also feed **seed/training expansion** for Smish/Vish (R3).
  See the channel trainer + seed connectors (`common/ml/training/`).
