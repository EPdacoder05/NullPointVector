# Latch (iOS) — Call Directory + Message Filter

Internal Xcode project name stays `NullPointGuard`; **App Store display name = Latch**.
Bundle IDs stay `com.nullpoint.guard*` (customers never see those).

**Not** Apple’s VoIP CallKit sample. We ship **Call Directory + Message Filter only**.

---

## What you register in Apple Developer (and what you skip)

### Identifiers → App IDs (do these)

| Description | Bundle ID (Explicit) | On Capabilities tab enable |
|---|---|---|
| `Latch` | `com.nullpoint.guard` | **App Groups** only |
| `Latch Directory` | `com.nullpoint.guard.directory` | **App Groups** only |
| `Latch SMS Filter` | `com.nullpoint.guard.smsfilter` | **App Groups** only |

Then Identifiers → **App Groups** → `group.com.nullpoint.guard`, and tick that group on all three App IDs.

### Why you do **not** see “Call Directory” or “Message Filter” checkboxes

Those are **extension point types**, not App Services (MusicKit / WeatherKit) and not
Capability Requests (Hotspot Helper, etc.).

- `.directory` = Call Directory extension → Xcode sets  
  `NSExtensionPointIdentifier = com.apple.callkit.call-directory`
- `.smsfilter` = SMS / Message Filter extension → Xcode sets  
  `NSExtensionPointIdentifier = com.apple.identitylookup.message-filter`

“Messages Collaboration” is a different product. Ignore it.

On the Register App ID page: stay on **Capabilities** → enable **App Groups** → Continue.
Ignore **App Services** and **Capability Requests** for this pilot.

### Certificates / Profiles / Devices / Keys

| Item | Needed now? |
|---|---|
| App IDs + App Group | **Yes** (what you’re doing) |
| Development / Distribution certs | Xcode **Automatic Signing** creates them |
| Provisioning profiles | Automatic Signing creates them when you Archive |
| Register device | Only for direct USB debug; TestFlight uses the phone’s Apple ID |
| Keys / Services IDs | **No** (Sign in with Apple / Music / Maps — not this pilot) |

Click **Generate a profile** only if you insist on Manual signing. Prefer Automatic in Xcode.

### App Store Connect → New App

| Field | Value |
|---|---|
| Name | **Latch** |
| Bundle ID | `com.nullpoint.guard` |
| SKU | `latch-ios` |
| User Access | Full Access |

Upload before **Aug 8, 6 a.m. PDT** maintenance if you can.

---

## Generate + Archive

```bash
cd /Users/ep/DevProjects/Yahoo_Phish/ios
xcodegen generate
open NullPointGuard.xcodeproj
```

Signing & Capabilities on **all 3 targets**: Team = Ellis Pinaman (`KX3P7M3B6L`),
App Group `group.com.nullpoint.guard`. Then Product → Archive → TestFlight.
Add tester for **614-695-8215**.

Entitlements in repo are **App Groups only** (correct). Extension behavior comes from
`NSExtensionPointIdentifier` in `project.yml`, not from a VoIP entitlement.

---

## Public HTTPS without buying a domain (pilot)

Named Cloudflare tunnels need a **domain already on Cloudflare**. Until you buy
`ishguard.com` (or point another owned domain at Cloudflare), use **ngrok’s free
static domain** — one fixed HTTPS hostname that survives restarts.

### A. Claim ngrok free static domain (once)

1. Sign up / log in at [https://dashboard.ngrok.com](https://dashboard.ngrok.com)
2. Get your authtoken: **Getting Started → Your Authtoken** → copy
3. On this Mac:

```bash
ngrok config add-authtoken YOUR_TOKEN_HERE
```

4. **Cloud Edge → Domains** (or **Universal Gateway → Domains**) → **New Domain**  
   Claim the free `*.ngrok-free.app` (or `*.ngrok-free.dev`) name they offer.  
   Example: `nullpoint-pilot.ngrok-free.app`
5. Keep that hostname — it is your stable API base:  
   `https://nullpoint-pilot.ngrok-free.app`

### B. Run stack + tunnel (every session Mac is online)

```bash
cd /Users/ep/DevProjects/Yahoo_Phish
docker compose up -d
curl -s localhost:8088/health   # must be healthy

# Use YOUR claimed domain:
ngrok http --url=nullpoint-pilot.ngrok-free.app 8088
```

Leave that terminal open. Verify:

```bash
curl -s https://nullpoint-pilot.ngrok-free.app/health
```

(Optional) Cloudflare quick tunnels still work for ad-hoc tests but the hostname
**changes every restart** — do not bake those into TestFlight.

### C. Bake URL into the iOS build (so users never paste a server URL)

Edit `ios/project.yml` → `settings.base.API_BASE_URL`:

```yaml
API_BASE_URL: "https://nullpoint-pilot.ngrok-free.app"
```

Also set the same string in `ios/Info.plist` key `API_BASE_URL`, then:

```bash
cd ios && xcodegen generate
```

Archive → upload build **1.0 (2+)** → Internal TestFlight.

When you later own `ishguard.com` on Cloudflare: create a **Published application**
route (not Private hostname) → service `http://localhost:8088` → bake
`https://api.ishguard.com` instead. Then flip `allowURLOverride` to `false` in
`App.swift` for App Store.

### D. Auth — Sign in, never paste JWT

App Store / TestFlight users must **not** paste bearer tokens.

1. Open Guard → **Sign in**
2. Username / password = Signal Deck account (pilot: values in gitignored `.ios_pilot_auth`)
3. App calls `POST /api/v1/token`, stores access + refresh JWT in **Keychain**
4. **Refresh blocklist** runs after sign-in (and on demand)
5. Later opens: still signed in until **Sign out** (refresh token renews access)

External App Store (post-approval): same Sign in UX; each customer gets their own
account (signup / Sign in with Apple is a later product slice — not paste-JWT).

> Note: `GET /api/v1/vish/directory` currently requires **analyst+**. Pilot uses the
> admin/analyst account. Customer-tier directory sync is a follow-up before wide launch.

---

## Internal TestFlight (you + 2 friends)

1. Public HTTPS API (Fly/Railway/`docker-compose.prod.yml` — see `docs/PILOT_SHIP.md`). Not localhost. Not a changing tunnel hostname.
2. Bake it: `API_BASE_URL` in `project.yml` + Info.plist → `https://YOUR_HOST`. `xcodegen generate`.
3. Archive → App Store Connect → **Internal Testing** (your Apple ID + two testers). External review can wait.
4. Each friend creates a Signal Deck account at `https://YOUR_HOST/app/signup` (`SIGNUP_OPEN=true`). Same email/password in Guard → Sign in. Directory sync is **customer+**.
5. Settings → Phone → Call Blocking & Identification → Directory. Messages → Unknown & Spam → SMS Filter. Force-quit both apps.

I cannot upload the binary without your Apple ID. Team stays `KX3P7M3B6L` until you change it.

## Device after TestFlight

1. Open Guard → **Sign in** (once) → wait for “Synced N blocks…”
2. Settings → Phone → Call Blocking & Identification → enable Directory extension.
3. Settings → Messages → Unknown & Spam → enable SMS Filter.
4. Force-quit Phone + Messages after toggling (iOS caches extensions).
5. API base must be public HTTPS (ngrok static or your domain → `:8088`).

## Inbox vs Quarantine (console)

- **Inbox stream** = recent feed / triage.
- **Quarantine** = ungraded model holds that need Block / Safe / Needs review.
- **Open** any row → `/app/message/{id}` full body (encrypted at rest; analyst console only).
