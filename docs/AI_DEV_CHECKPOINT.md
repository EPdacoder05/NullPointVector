# AI Dev Checkpoint — resume anchor

> Purpose: **start here** in any new session, with any model. This file assumes the
> reader has ZERO memory of prior sessions. It captures locked decisions, current
> verified state, bounded specs for every open item, and exact verify commands with
> expected outputs. Do not re-litigate locked decisions. Do not invent scope.

_Last updated: 2026-07-24 (session: quarantine grading loop verified E2E + recovered decisions from lost chats)_

---

## 0. Product identity — LOCKED, do not change

- Product name: **NullPoint**. Console name: **Signal Deck**.
- Channels are labeled **Phishing / Smishing / Vishing** in the UI (never "PhishGuard" etc.).
- Design system: **gold/brass + forest green** ("brass rail", corner brackets, forest ink)
  in `web/static/app.css`. **NEVER**: purple, emojis in UI, npm/Node/CDN dependencies.
  The web console is server-rendered Jinja + one hand-written CSS + one hand-written JS file.
- Pricing tiers: Essential (3-day trial, 7-day history) / Pro (family, OSINT, credit) /
  Enterprise (developers+teams, expedited support). Catalog: `common/plans.py` (DB seed + fallback).
- JWT roles: viewer / customer / analyst / admin / enterprise (`common/auth.py`).
- Credit/OSINT is **outsourced to vendors** (Plaid, Array/credit partner, IPQS/HIBP/SpyCloud).
  **NEVER** build DIY credit bureaus or dark-web scrapers.

## 1. How to resume in one minute

```bash
cd /Users/ep/DevProjects/Yahoo_Phish
docker compose ps        # expect 5 containers healthy: app, db, pgbouncer, redis, proxy
curl -s localhost:8088/health
# expect: {"status":"healthy",...,"model_loaded":true,"dlq_pending_threats":0}
```

UI (all must return 200; verified 2026-07-13):

```bash
for p in dashboard inbox identity pricing connectors calls login; do
  curl -s -o /dev/null -w "/app/$p=%{http_code}\n" http://localhost:8088/app/$p
done
```

Gates (all green as of 2026-07-13 — "10 passed"):

```bash
docker compose exec app python -m pytest -q \
  test/test_model_gate.py test/test_vish_hybrid.py test/test_api_smoke.py
# full set also includes: test_trainer_gate.py test_resilience_dlq.py test_channel_trainer.py
```

If UI routes 404 after a code change: `docker compose restart app` (dev bind mount `.:/app`;
new routes need a process restart).

## 2. Current verified state (2026-07-13)

| Item | Status | Evidence |
|---|---|---|
| Stack | healthy | app/db/pgbouncer/redis/proxy up; nginx `:8088` → app `:8000`; `/` redirects to `/app` |
| Model gates | PASS | Phish 97.5%/100% recall; Smish 100%; Vish 93.8% (`models/REPRO_MANIFEST.json`) |
| Web console | live | Dashboard, Inbox, channel analyze, Identity, Pricing, Connectors, Call log, Login |
| Vishing UI | live | Paste→Analyze (ML) + Call screen toggle (hybrid reputation) on `/app?channel=vishing` |
| Call screen → log | live | UI `/app/screen` AND API `POST /api/v1/vish/screen` both write via `common/call_events.record_screen`; visible at `/app/calls` |
| Identity phone enrich | wired, vendors down | `POST /app/identity/enrich` + `/api/v1/identity/enrich`; IPQS returns `unavailable` (credits), credit returns `missing_keys` — **fail-open by design** |
| OAuth connectors | routes live, no client IDs | `/app/connectors` + callbacks in `common/oauth_email.py`; needs `GOOGLE_OAUTH_*` / `MICROSOFT_OAUTH_*` in `.env` |
| Call Directory sync | live | `GET /api/v1/vish/directory` returns block/label JSON for iOS |
| iOS scaffold | code done, unsigned | `ios/` XcodeGen project; 3 targets; needs Apple Team ID + device |
| Inbox Jinja bug | fixed | `counts.clear` collided with dict method → renamed to `counts.cleared` |
| DB connection | workaround | app points at `db:5432` DIRECTLY (pgbouncer was refusing conns). See §6. |

## 2b. Session 2026-07-24 — what is NEW and verified

The full hands-off engine loop + the one manual touchpoint now works E2E:

| Piece | Status | Evidence |
|---|---|---|
| Quarantine page `/app/quarantine` | live | review queue with bands: Quarantined (conf≥0.85) / Potential threat (≥0.5) / Unsure |
| Grading buttons (right-aligned, legacy style) | live | Block & Report / **Needs review** / Mark as safe on dashboard, inbox, quarantine, call log |
| Grade → feedback buffer | verified | `POST /app/quarantine/grade` → `set_message_grade` + `common/grading.py` → per-channel `feedback.jsonl` (label 1/0); "unsure" keeps label NULL |
| Call log upgrade | verified | Blocked (proactive IDPS) / Potential threat / Cleared badges; **Show transcription** toggle; `POST /app/calls/grade` → vishing buffer |
| Login portal | verified | `POST /app/login` → 8h cookie session → sidebar shows account + Sign out; `/app/logout`; login redirects when already authed |
| Console analyze persists | new | risk ≥ 0.35 → DLQ-safe persist with label NULL → feeds dashboard/inbox/quarantine |
| **Self-labeling bug fixed** | critical | `email_ingestion.py` wrote `label=1 if is_threat` (model grading its own homework → empty review queue + self-poisoning). Now `label=None`; that column is HUMAN verdicts only |
| Decrypt tolerance | fixed | TEXT columns hold two formats ("gAAAA…" str tokens AND "\x67…" bytea-hex from bytes inserts); `decrypt_data` now unwraps both |
| Gates | green | 12 passed (model_gate, vish_hybrid, api_smoke, resilience_dlq) on 2026-07-24 |

Key files: `web/templates/quarantine.html`, `common/grading.py`, `common/call_events.py`
(now with id/transcript/graded + `get_screen`/`mark_graded`), `get_review_queue` /
`set_message_grade` in `Autobot/VectorDB/NullPoint_Vector.py`.

## 2c. RECOVERED DECISIONS (from chats lost to the billing lapse, 2026-07-24)

These were decided in external chats that are gone. They are LOCKED unless the user says otherwise.

1. **Vish automation = Loop A + Loop B only. Loop C (own VoIP path) is DROPPED** —
   too much operational overhead. The automated story is:
   - Loop A (ring-time): backend generates block/label lists → Call Directory. Never
     auto-block on single-number reputation alone; thresholds: very-high → block,
     medium → "Potential threat" label, low → observe server-side only.
   - Loop B (post-call): one-tap voicemail share / transcript import — minimal-touch,
     NOT silent capture (Apple forbids reading Recents/voicemail transcripts).
   - Every reviewed event feeds ring-time lists for everyone (community loop).
2. **Beat number rotation with an entity graph, not per-number blocklists.** Scammers
   rotate DIDs / neighbor-spoof. Score: number + CNAM + carrier/line type + NPA-NXX
   cluster + call velocity + transcript/campaign similarity + linked smish/phish
   domains + breach-lure correlation. Cross-channel correlation (phish email → smish
   → "support" call) elevates risk of a never-seen number. This is the moat vs
   Apple's built-in screening (which commoditized generic spam labeling).
3. **Positioning**: not "we label spam calls" but "identity-risk defense across
   phishing/smishing/vishing + account exposure" with contextual explanations.
4. **OAuth: YES, wire Gmail + Microsoft** (user is setting up GCP + Azure OAuth apps).
   Free to register. HARD RULE: OAuth is for connectors only, never required for base
   login; connector failure must never break auth. Options, not force.
5. **Identity/OSINT full report (Pro tier — required for pilot)**: in-app summary +
   linked "View full identity report" surface (hosted page/partner portal is fine —
   does NOT need native app UI v1). Scope: breach exposure, dark-web credential
   findings, leaked-password sites, credit/fraud markers, people/household records.
   **NEVER show plaintext leaked passwords** — show source site, age, severity,
   reuse risk + reset/MFA CTA only.
6. **DB: plain Postgres as source of truth, own backend API.** Supabase optional
   later as convenience (hosted PG/admin) only — never client-direct-to-DB
   architecture for this product. (Current pgvector Postgres already complies.)
7. **Hosting: Cloudflare in front, compute elsewhere.** Cloudflare = DNS + proxy/WAF
   + Tunnel (pilot). The Python/ML Docker stack cannot run on Workers/Pages; put
   compose on a small VPS (Hetzner/DO/Lightsail). Cloudflare Tunnel to :8088 is the
   fastest dev-vet path and doubles as the `PUBLIC_BASE_URL`.
8. **TestFlight order**: App Store Connect account holder sign-in + agreements →
   app record (bundle `com.nullpoint.guard`) → signing/Team in Xcode → INTERNAL
   TestFlight first (≤100 testers, no review) → external beta (needs App Review)
   later. Common blockers: bundle-ID mismatch, missing app record before upload,
   missing privacy strings, entitlement mismatch.
9. **New call-event schema fields to grow into** (backend): direction, duration,
   transcript_source, grade_by/grade_reason, model_version, campaign_cluster,
   review_status. Materialized "latest effective risk by number" for fast
   directory-sync export.
10. **UI themes (2026-07-24)**: three appearances, switcher in sidebar foot,
   persisted in localStorage (`np_theme`): **Deck** (default gold+green Signal
   Deck), **Terminal** (green-phosphor console), **Blackout** (pure black).
   Implemented as CSS-variable overrides on `body[data-theme]` in `app.css` —
   new themes = new variable block, never a parallel stylesheet.
   NOTE: the legacy Dash console still serves on :8050 (blue UI) — do not
   confuse it with the Signal Deck at :8088/app. Its "Active Threats" panel has
   a known bug: queries a nonexistent `processed` column.

### Recovered verbatim prompt (was wiped before it got a response)

> "So the only way to get the log inside our app is the user has to hit share,
> but doing that on every phone call… even on every call they think is
> fraudulent is not going to work. That adds a task for users which we wanted to
> remove… there's gotta be a better more slick creative way to wire into app and
> build an automation loop so user doesn't have to share data for each call,
> suspicious or not."

Answer (now locked as decisions 1–3 above): the hands-off loop is ring-time
Call Directory screening fed by the entity graph + community grades + vendor
feeds. Voicemail share is optional training input only — never a per-call task.

## 3. Locked architecture decisions

1. **CallKit = HYBRID** (decision R1, resolved): reputation path on every call
   (caller_id only, instant) + transcription path only when a transcript exists
   (voicemail/opt-in). One endpoint `POST /api/v1/vish/screen` serves both.
   Spec: `docs/CALLKIT_DATA_CONTRACT.md`. Apple gives NO carrier call history to
   third-party apps — the pilot visibility path is: screens recorded server-side
   → Call log UI → `GET /api/v1/vish/directory` → Call Directory block/label.
   **No Twilio needed.**
2. **Reputation providers are env-keyed and fail-open**: no key → provider silently
   disabled; vendor error → skip, never block the verdict pipeline
   (unless `REPUTATION_STRICT=true`). Contacts are never auto-block/silence — at most `label`.
3. **Vendor stack** (outsourced): Plaid = KYC/bank (Layer 1); Array preferred or
   `CREDIT_PARTNER_*` = credit (Layer 2); IPQS now → HIBP Pro → SpyCloud/Constella
   at scale = breach OSINT (Layer 3).
4. **Email ingest**: Yahoo/Gmail/Outlook via IMAP app-passwords in `.env` today;
   OAuth (Gmail/Microsoft) is the GUI-first path once client IDs exist.
5. **Resilience**: durable DLQ (Redis + disk) with auto-replay; proven zero-loss in
   a live DB-outage drill. `restart: unless-stopped`, health-gated deps.

## 4. Open work — bounded specs (priority order)

Each item states: goal, files, done-when. Do them in order unless the user redirects.

### 4.1 Dev-vet deployment (NEXT — user was preparing to send to developers)
- Goal: 3 external developers can log in and exercise the console remotely.
- Blocked on USER inputs (see §5). Agent work once inputs exist:
  a. Set `PUBLIC_BASE_URL` to the tunnel/VPS URL in `.env`; restart app.
  b. Create per-vetter credentials via `API_CUSTOMER_USER/PASSWORD` env pairs or DB users.
  c. Smoke the public URL: `/app/login`, analyze one sample per channel, one call screen.
- Done when: an outsider can complete login → analyze → call screen → see Call log.

### 4.2 OAuth email connect (needs `GOOGLE_OAUTH_*` / `MICROSOFT_OAUTH_*`)
- Files: `common/oauth_email.py`, `web/ui.py` (connector routes), `web/templates/connectors.html`.
- Redirect URIs to register: `{PUBLIC_BASE_URL}/app/connectors/callback/gmail` and
  `{PUBLIC_BASE_URL}/app/connectors/callback/microsoft`.
- Remaining code work: wire `Autobot/email_ingestion.py` to use stored OAuth tokens
  (today it only reads IMAP `.env` creds).
- Done when: Connect Gmail button → Google consent → token stored → inbox shows that
  account's mail through the ML pipeline.

### 4.3 Plan gating of Credit & OSINT
- Goal: identity enrich requires plan >= Pro (customer role + plan check), viewer sees upsell.
- Files: `web/ui.py` (identity routes), `common/plans.py`, `api/main.py` (`/api/v1/identity/enrich`).
- Done when: Essential user gets an upgrade prompt; Pro+ gets reports.

### 4.4 R2 leftover — anomaly IF pickle regeneration
- `anomaly_if_*.pkl` trained under sklearn 1.8 warn under 1.9 (`InconsistentVersionWarning`).
- Fix: `docker compose exec app python scripts/regenerate_artifacts.py`, confirm gates still
  PASS, commit regenerated pkls + updated `models/REPRO_MANIFEST.json`.

### 4.5 R3 — golden set expansion (smish/vish)
- Feed corpora into `data/seed/<channel>/*.jsonl` (or `*_SEED_URL` env), grow held-out sets
  to hundreds, fix the known Vish false negative, retrain through the gate:
  `python -m common.ml.training.channel_trainer <channel>`. The gate correctly blocks
  promotion below 0.90 recall — do not bypass it.

### 4.6 PgBouncer restore (deferred, low priority)
- App currently bypasses pgbouncer (see §6). Restore: fix pgbouncer auth config, point app
  back to `pgbouncer:6432`, verify `/health` stays healthy under load.

### 4.7 iOS TestFlight (blocked on USER: Team ID, device)
- `cd ios && xcodegen generate && open NullPointGuard.xcodeproj`; set Team on all 3 targets;
  point `APIService.baseURL` at the public API; analyst JWT via `POST /api/v1/token`;
  physical iPhone; enable extensions in Settings (Call Blocking / SMS Filter).

## 5. USER-owned inputs (nothing here is agent work)

1. **Hosting** for vetters: ngrok/Cloudflare tunnel to `:8088` OR small VPS. → sets `PUBLIC_BASE_URL`.
2. **IPQS account**: resolve credits/dispute, or accept empty OSINT panels for the vet.
3. **OAuth apps**: Google Cloud OAuth client (Web) + Azure AD app registration → client IDs/secrets.
4. **Credit partner**: Array sandbox key OR `CREDIT_PARTNER_*` — or skip for vet.
5. **Apple**: Team ID in Xcode, physical iPhone(s), TestFlight/Ad-Hoc choice. Program already purchased.
6. **Rotate every secret in `.env`** before any shared/public deploy — several were pasted in
   chat and must be treated as burned (Yahoo/Gmail/Outlook app passwords, `ENCRYPTION_KEY`, IPQS, …).
7. Strong `API_ADMIN_*`, `API_CUSTOMER_*`, `JWT_SECRET_KEY` values (defaults are `changeme`-class).

## 6. Known gotchas / tribal knowledge

- **UI is at `http://localhost:8088/app`** through nginx. Never `python -m http.server`.
- **Restart the app container after adding routes** (bind mount ≠ auto-reload).
- **PgBouncer bypass**: `docker-compose.yml` has `DB_HOST=db`, `DB_PORT=5432` because
  pgbouncer refused connections. Intentional temporary state (spec 4.6).
- **Jinja dict-method collision**: never key template dicts with names shadowing dict
  methods (`clear`, `items`, `keys`, `values`). We hit this with `counts.clear`.
- **Env in Docker**: `Autobot/VectorDB/NullPoint_Vector.py` prefers process env over `.env`
  file so container env wins.
- **IPQS fail-open**: enrich reports return `{"ok": false, "error": "unavailable"}` per layer
  rather than failing the request. This is correct behavior, not a bug.
- **`.env` is gitignored and must stay so.** `.env.example` documents names only.
- **`Phishy_Bizz/` golden corpus is NOT on this host** (user has it elsewhere).
- sklearn model pkls emit a benign `security-maintainability` pytest warning — ignore;
  the `InconsistentVersionWarning` on anomaly IFs is the real one (spec 4.4).

## 7. Key file map

| Area | File |
|---|---|
| API (JWT, RBAC, rate-limit, screen, enrich, directory) | `api/main.py` |
| Web console routes | `web/ui.py` |
| Templates | `web/templates/{base,index,dashboard,inbox,identity,login,pricing,connectors,calls,_feed,_result,_screen}.html` |
| Design system / JS | `web/static/app.css`, `web/static/app.js` |
| Plans catalog | `common/plans.py` |
| OAuth email connectors | `common/oauth_email.py` |
| Call event log | `common/call_events.py` |
| CallKit contract + fusion | `common/vish/{contract,adapter}.py` |
| Reputation framework | `common/reputation/{base,providers,aggregator}.py` |
| Identity vendors (IPQS/Plaid/Array/credit) | `common/vendors/identity.py`, `common/vendors/plaid_client.py` |
| Channel ML core | `common/ml/channel_detector.py`; detectors under `PhishGuard/ SmishGuard/ VishGuard/` |
| Training loop + gate | `common/ml/training/{channel_trainer,channel_eval,seed_connectors}.py` |
| DLQ / streaming | `common/streaming/{dlq,rti_consumer,channel_pipeline}.py` |
| Vector DB | `Autobot/VectorDB/NullPoint_Vector.py` |
| Reproducibility | `scripts/regenerate_artifacts.py`, `models/REPRO_MANIFEST.json` |
| iOS | `ios/` (XcodeGen; README has device steps) |
| Docs | `docs/{CALLKIT_DATA_CONTRACT,PRE_CALLKIT_ROADBLOCKS,COMPLIANCE_DRAFT,DEPLOYMENT}.md` |

## 8. Quick E2E smoke (copy-paste)

```bash
# call screen via UI path → should say BLOCK and appear in /app/calls
curl -s -X POST http://localhost:8088/app/screen \
  -d 'caller_id=%2B16145550100&transcript=IRS+warrant+press+1' | grep -o 'call-action-label">[A-Z]*'

# identity enrich (fail-open vendor errors are expected without live keys)
curl -s -X POST http://localhost:8088/app/identity/enrich \
  -H 'Content-Type: application/json' -d '{"subject":"6146958215","consented":true}'

# CallKit directory feed
curl -s http://localhost:8088/api/v1/vish/directory   # requires analyst JWT in prod
```

## 9. Standing prompt artifacts (user's verbatim constraints)

- "unique gold+green UI … not a Twitter/Cursor clone; Unroll.me-inspired inbox, not a copy."
- "no purple, no emojis, no npm."
- "outsource credit/OSINT — not DIY bureaus: Plaid + Array + SpyCloud/Constella/IPQS/HIBP."
- "store API keys in local .env; rotate before prod."
- "E2E customer flow: phone lookup reports, OAuth email, CallKit inbound visibility,
  Call screen for ML tuning / App Store pilot."
- "send to a few developers to vet" — see §4.1/§5.
