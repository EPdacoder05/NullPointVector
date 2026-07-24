# NullPoint Guard — iOS (CallKit pilot)

XcodeGen scaffold for Call Directory + Message Filter extensions per `docs/CALLKIT_DATA_CONTRACT.md`.

## Prerequisites

- Apple Developer Program ($99/yr) — already purchased
- Xcode 15+
- [XcodeGen](https://github.com/yonaskolb/XcodeGen): `brew install xcodegen`

## Generate project

```bash
cd ios
xcodegen generate
open NullPointGuard.xcodeproj
```

Set your **Development Team** in Xcode for all three targets.

## Targets

| Target | Bundle ID | Role |
|---|---|---|
| NullPointGuard | `com.nullpoint.guard` | Main app — token storage, blocklist sync |
| NullPointDirectory | `com.nullpoint.guard.directory` | CallKit block + caller ID labels |
| NullPointSMSFilter | `com.nullpoint.guard.smsfilter` | Message Filter extension (unknown senders) |

App Group: `group.com.nullpoint.guard` (shared `blocklist.json`).

## Backend contract

| Endpoint | Status |
|---|---|
| `POST /api/v1/vish/screen` | **Live** — hybrid reputation + transcript |
| `GET /api/v1/vish/directory` | **Live** — block/label sync for Call Directory |

Expected directory response:

```json
{
  "updatedAt": "2026-07-09T12:00:00Z",
  "block": ["+18005550199"],
  "label": [{"number": "+18005550200", "label": "Likely IRS scam"}]
}
```

Wire `APIService.baseURL` and `accessToken` (analyst JWT from `POST /api/v1/token`).

## Device setup

1. Build & run on a physical iPhone (extensions require a device).
2. Settings → Phone → Call Blocking & Identification → enable NullPoint Directory.
3. Settings → Messages → Unknown & Spam → enable NullPoint SMS Filter.

## Notes

- Extensions cannot embed Python/ML — all scoring stays on the backend.
- Transcription path is optional (voicemail / Apple Speech); ring-time uses reputation only.
- Do not commit API keys; use Keychain + short-lived JWTs.
