# AI Dev Checkpoint — resume anchor

> Purpose: **start here** in any new session, with any model. This file assumes the
> reader has ZERO memory of prior sessions. It captures locked decisions, current
> verified state, bounded specs for every open item, and exact verify commands with
> expected outputs. Do not re-litigate locked decisions. Do not invent scope.

_Last updated: 2026-08-11 (pilot/friends-family: signup, OAuth persist+XOAUTH2, /privacy, IPQS enrich cron, Fly/Railway compose, TestFlight notes; Pages deploy main-only; WET deferred)

### ANSWERED (delta — reports / vishing / known-good)
| Question | Answer |
|---|---|
| Cap1 / every known-good spoofable? | **Yes — locked.** `is_known_good_sender` requires **auth_pass for EVERY domain**. Domain alone never short-circuits. |
| PayPal ask without paypal.com? | **Hard malice** via `_payment_brand_spoof` in `policy_pipeline`. |
| Granny report vs triage? | Separate **Report this** (flag) → expected? + reasons + detail → `user_reports` / fleet. Triage buttons still own grades. |
| Become telecom for RTI vishing? | **No.** Call Directory + Live Lookup + IPQS/etc. No SIP/Telnyx/MVNO product track. |
| SMS RTI already? | **Yes** — Message Filter on device. Email → tighter poll; Vish → number reputation + fleet reports. |

### ANSWERED (delta — Cap1 / time / Avinash)
| Question | Answer |
|---|---|
| Cap1 / every known-good spoofable? | **Yes — locked.** `is_known_good_sender` requires **auth_pass for EVERY domain** (GitHub, Cap1, Chime, …). Domain match alone never short-circuits. Spoofed Cap1 with spf=fail → ML. |
| Why no Message-ID dedup / “we solved this”? | **Honest gap:** `Idempotency-Key` + Redis only covered **API** POSTs (`/analyze`). IMAP batch ingest never used it — `compute_hash` existed in the sanitizer but was never applied on insert. **Now:** `rfc_message_id` + `ingest_fp` + **partial unique indexes** + skip-on-conflict. |
| Why Cap1 needs hardcoding? | AUTH_PASS + financial-notice dampens; ESP list blocks false BAD_URL; Cap1 on list still **auth_pass gated**. |
| Times wrong (4:32 vs 9:01 PM)? | Poll clock vs `Date:` — fixed. TZ cookie sync + EDT labels. |
| Why 80 Avinash clones? | Re-poll without ingest dedup. Collapsed flood; durable indexes now. |

### Checkout / payment fraud controls (honest)
| Control | Status |
|---|---|
| Server price authority (reject client `amount`/`price`) | **OK** `validate_checkout_payload` |
| Payload shape / key-count guard | **OK** |
| Origin allowlist on POST `/app/checkout` | **OK** |
| Checkout velocity (Redis/process) | **OK** |
| Hash-chained `payment_audit_events` | **OK** |
| Trial fingerprint abuse score | **OK** (Pro trial) |
| Guest checkout disabled (login required) | **OK** |
| Stripe-hosted card entry (no raw PAN stored) | **OK** when live |
| Stripe webhook HMAC (`STRIPE_WEBHOOK_SECRET`) | **OK** route `/api/v1/billing/webhook` — live needs secret; mock accepts `Stripe-Signature: mock_ok` |
| Apple Pay / Google Pay / PayPal / BNPL | **OPEN** — Stripe Checkout `automatic_payment_methods` enables wallets when Stripe account supports them; PayPal/BNPL not wired as separate merchants yet |
| Not a guarantee of “no fraud” | Chargebacks, stolen cards, account takeover still exist — we harden *payload/session* fraud, Stripe handles card fraud tooling |

### Provider junk/trash sync
| Piece | Status |
|---|---|
| Grade updates NullPoint DB immediately | **OK** |
| Cascade Apply never waits on IMAP | **OK** — enqueue `provider_action_queue` + BackgroundTasks drain |
| `metadata.provider_actions` JSONB per provider | **OK** pending/ok/failed |
| Actual Yahoo/Gmail move | **HALF** — needs `metadata.imap_id` from ingest; `scripts/drain_provider_queue.py` for cron |
| Trash vs junk | junk path live; trash maps to junk until fetcher supports trash |

### Policy pipeline (Codex + review amalgam)
Single pass `common/policy_pipeline.extract_signals` → malice/recruit ≥0.90 → known-good → marketing cap → ML. Malice wins over allowlist. Payment-brand spoof (PayPal ask without paypal origin) is hard malice.

### User reports (granny path)
- UI: **Report this** (flag, bottom of card, not in triage row) → modal “Were you expecting this?” → reasons → optional detail.
- `POST /app/report` → `common/user_reports.py` → `user_reports` + `fleet_threat_keys`.
- Fleet: 3 distinct reporters / 30d → analyst flag; 8 → auto key at conf ≤0.75 (score influence only).
- Triage Block/Needs review/Safe still owns grades + feedback.jsonl. Report does not grade alone.

### Evidence tags (2026-08-11)
High-signal codes in `common/explain.py` (+ `common/lookalike.py`, mood `ADVANCE_FEE` in `message_tags.py`):
`REPLY_TO_MISMATCH`, `ADVANCE_FEE`, `ATTACHMENT_RISK`, `IMAGE_ONLY` (also caps ML confidence ≤0.72 in `phishing_detector.predict`), `LOOKALIKE_DOMAIN`, `TOLL_FREE_CALLBACK`, `NEIGHBOR_SPOOF` (needs `user_area_code` / `X-NullPoint-User-Area` in headers — **HALF** until account profile stores it), `CAMPAIGN_MATCH` (fleet key + `data/vish_campaigns/*.json` pack CIDs).
Tag pills: **inline-block flow** in `.reason-tags` (not flex) — lone-row pills must never stretch full width. Cache-bust `?v=` on static assets in `base.html`.

### Quarantine routing
- Inbox/Dashboard: `label IS NULL AND confidence < 0.85`
- Quarantine: `label IS NULL AND confidence >= 0.85` only (no duplicate)

### Grade velocity
`common/grade_velocity.py` — 8+ grades same sender-domain campaign in 60m → extra ephemeral nudge (not champion promote).

### LOCKED UI — cascade confirm modal
Do not redesign `#cascade-modal` without explicit ask.

### ANSWERED (delta)
| Question | Answer |
|---|---|
| Payload verification = no payment fraud? | Hardens checkout *tampering* (price, origin, velocity, login, webhook sig). Does **not** eliminate card fraud/chargebacks — Stripe does card checks; wallets via Stripe AMP when live. |
| Backend reflects Block to provider junk? | **Yes, async.** Queue + background drain; siblings not inline IMAP. |
| Strawberry / Vertiv | Strawberry known-good; Vertiv Mark-Safe learn (not forever allowlist). |

### HALF-ASSED / UNFINISHED (operator pain — audit 2026-08-10)
Do **not** mark these done until verified with curl/device.

| Gap | Reality |
|---|---|
| OAuth tokens → ingest | **HALF** — refresh tokens persist in `user_mailboxes`; Gmail IMAP XOAUTH2 + app-password ingest across all subs. Microsoft oauth persist yes; XOAUTH2 IMAP still password-first |
| Personal phone allow/block | **Not built** (no namespaced UI/API) |
| Polling interval by plan | **Not built** (fixed ~5 min batch) |
| IMAP IDLE / push | **Not built** |
| Vendor enrich cron (A) | **OK code** `scripts/enrich_directory.py` → `number_reputation` → Call Directory. Needs `IPQS_API_KEY` |
| Live Caller ID Lookup (C) | **Not built** — user ready; no PIR server/extension |
| Account signup DB users | **OK code** `deck_accounts` + `/app/signup` behind `SIGNUP_OPEN` |
| Stripe live | **Still `BILLING_MOCK`** |
| iOS device sync | Source passwordless; Funnel+Archive still operator-fragile |
| Secrets in chat | Burned — rotate before shared deploy |

### FULL CHECKPOINT AUDIT (2026-08-10) — beginning → tagging/pwd
Re-read §§0–9 + session notes. Verified against live stack + code (not memory).

Legend: **OK** = true now · **HALF** = UI/code stub, not E2E · **STALE** = doc lies · **OPEN** = not built · **LOCK** = decision only

#### Locked product (§0 / identity) — OK
NullPoint + Signal Deck; Phish/Smish/Vish labels; brass+forest; no purple/emoji/npm; Jinja+hand CSS/JS; plans in `common/plans.py`; JWT roles; OSINT outsourced fail-open. Themes Deck/Standard/Terminal/Blackout live.

#### Pilot sequence (§0b) status
| ID | Claim | Verdict |
|---|---|---|
| P0a Grade loop | Persist label + bubble-out + reload | **OK** in NullPoint DB/UI. User pain = Yahoo not updated (**OPEN** junk move) + siblings need modal (**OK** modal shipped) |
| P0b Known-good | auth_pass allowlist | **OK** Costco/GitHub/Sezzle on list; no-auth → ML. `test_safe_domains` + gate **7 passed** just now |
| M1 Checkout | mock Stripe + audit chain | **HALF** — routes 200, `BILLING_MOCK=true` still; live Stripe **OPEN** |
| M2 Feedback | buffer + Δw toast + nightly | **OK** code path; durable champion = nightly gate only |
| M3 Benchmarks | snapshot deck | **OK** `/app/benchmarks` 200; snapshot: phish 97.5% GATE PASS, smish 100%, vish 93.8% |
| P0c Home feel | logged-in operator home | **HALF** — dashboard works; not a polished “account home” |
| P1 Identity views | enrich fail-open | **OK** UI; vendors often `missing_keys`/`unavailable` |
| P1 Connectors customer | no .env lecture | **HALF** — app-password form exists; ingest still .env; OAuth needs client IDs |
| P2 iOS TestFlight | Call Directory + SMS Filter | **HALF** — source passwordless; device/Funnel flaky; display name still **NullPoint Guard** not Latch (**STALE** vs README) |
| P2 Redis multi-replica | shared RL/idempotency | **OK** code + `REDIS_URL` in compose (verify under 2 replicas not re-proven today) |
| P3 Android | deferred | **LOCK** |

#### Phone/SMS honesty (§0 phone) — OK
Email batch ingest live. SMS paste on Signal Deck. SMS RTI needs public host + extension. Calls = Call Directory lists; no carrier Recents API. Loop C VoIP **DROPPED**.

#### Session 2026-07-13 / 07-24 claims
| Claim | Verdict |
|---|---|
| 5 containers + `/health` | **OK** now |
| Quarantine + grade → feedback.jsonl | **OK** |
| Self-labeling bug fixed (`label=None` on ingest) | **OK** (locked) |
| Legacy Dash `:8050` / `ui/dash_app.py` | **STALE** — deleted; only `:8088/app` |
| `docs/REFERENCE.md` | **STALE** — deleted; checkpoint is sole resume anchor |
| ASC “Add Apps before Aug 8” | **STALE date** — today is Aug 10; check ASC manually |

#### Recovered decisions (§2c) vs built
| Decision | Built? |
|---|---|
| Loop A+B only, no Loop C | **LOCK** + Call Directory path **OK** |
| Entity graph (number+CNAM+velocity+cross-channel) | **OPEN** (crumbs stub only) |
| OAuth connectors, never force login | **HALF** (routes; no ingest wire) |
| Identity full report Pro | **OPEN** plan-gating (§4.3) + vendor keys |
| Postgres SoT, Cloudflare front | **OK** / Funnel pilot |
| Call-event schema growth fields | **OPEN** partial |

#### Architecture (§3) — OK with gaps
Hybrid CallKit contract doc **OK**. Reputation fail-open **OK**. Email still **`.env` IMAP** (§3.4 **HALF** vs Connectors form). DLQ Redis+disk **OK**.

#### Open specs (§4) — none closed since last honest cut
4.1 Dev-vet deploy — **OPEN** (user hosting).  
4.2 OAuth→ingest — **OPEN**.  
4.3 Plan-gate Credit/OSINT — **OPEN**.  
4.4 Anomaly IF regen — **OPEN** (warn may remain).  
4.5 Smish/Vish golden expand — **OPEN** (n=16 each).  
4.6 PgBouncer restore — **OPEN** (still direct `db:5432`).  
4.7 iOS TestFlight — **HALF** (user device work).

#### User inputs (§5) — still on you
Hosting/`PUBLIC_BASE_URL`, IPQS credits, OAuth apps, credit partner, Apple Team/device, **rotate burned secrets**.

#### Gotchas (§6) — OK
`:8088/app`, restart app after routes, Jinja dict keys, fail-open IPQS, `.env` gitignored.

#### Session 2026-08-10 “done” — re-grade after tagging/pwd
| Item | Verdict |
|---|---|
| Costco/GitHub FP fix + HTML body + backfill 2447 | **OK** (code+DB); new mail needs auth headers on ingest |
| Cascade confirm modal | **OK** in templates/JS |
| TZ on dash/inbox/quarantine + 12/24h | **OK** |
| Connectors app-password UI | **HALF** — saves encrypted; **ingest never reads it** |
| Category / “sentiment” tags | **HALF** — keyword+coarse tone on Quarantine/detail only; **not** sentiment analysis; **Inbox has zero tags** |
| `origin_blocked` Funnel | **OK** allow `.ts.net` |
| Password honesty | **OK** — login = pbkdf2 salted hash; mailbox = Fernet (not hash) |
| NullPoint≠Yahoo delete | **OK** documented; junk wire **OPEN** |
| iOS “Synced N” / Sync buttons | **HALF** — API directory returns **34 blocks** with pilot JWT; Mac/phone UX still operator-fragile (Funnel/VPN/stale binary) |

#### Console UX note to fix in doc
Older line “Mark Safe cascades automatically” is **STALE** — now **asks** via modal. Directory seed ≠ “only 3 forever” — tax pack → ~34.

### Done this session (2026-08-10) — continued
- **Known-good FPs:** `costco.com` / `digital.costco.com` on allowlist; Gmail/Yahoo fetchers preserve auth headers + HTML→text body (image-only retail). Backfill cleared **2447** known-good false quarantines (`scripts/backfill_known_good_safe.py`).
- **Cascade confirm modal:** Safe/Block opens sibling checklist (select all / none / this only / apply selected). Grade API accepts `also_ids`.
- **Timezone everywhere:** Quarantine + message detail use `format_local`; sidebar **12h/24h** cookie `np_hour12`. Dashboard/Inbox already local.
- **Connectors B (partial):** `/app/connectors` Yahoo/IMAP app-password form → encrypted `user_mailboxes` (`common/mailbox_store.py`). OAuth buttons unchanged. **Still open:** wire saved secrets into `email_ingestion`; per-user phone allow/block namespace.
- **Category tags:** `common/message_tags.py` (recruit-gmail, blast, pressure, tone) on quarantine/detail — rules, not a second model.
- **Checkout origin:** Funnel `*.ts.net` allowed (`origin_blocked` fix).
- **Honest product:** Mark Safe/Block = NullPoint DB only; does **not** delete Yahoo mail until IMAP `move_to_junk` on Block is wired.
- Login hint no longer claims `admin/changeme` (use `.env` `API_ADMIN_*` / pilot `API_PILOT_*`).

### Remaining (ordered — still open)
| # | Item | Status |
|---|---|---|
| 1 | Wire `user_mailboxes` / OAuth tokens into `email_ingestion` + personal phone allow/block namespaced | **HALF** — Gmail XOAUTH2 + all-sub ingest; phone allow/block still open |
| 2 | IMAP move-to-junk on Block (so Yahoo inbox matches NullPoint) | **Not built** |
| 3 | **A** Vendor enrich cron → directory growth | **OK code** — `scripts/enrich_directory.py` + IPQS key |
| 4 | IMAP IDLE / push | **Not built** |
| 5 | **C** Live Caller ID Lookup (iOS 18 PIR) | **Not built** — user ready with Apple + public HTTPS |
| 6 | SIP/Telnyx | **Deferred** |

### Feedback loop (locked)
Ephemeral Δw = process only. Durable champion = nightly gated retrain. Triage = `label IS NULL`. Docs: `docs/NULLPOINT_FEEDBACK_LOOP.html`.

### Gate vs live FPs (honest)
Golden gate (97.5% phish) = held-out seeds. Live Costco/GitHub 100% FPs were **empty auth headers** on GmailDoggy + missing Costco domain — not the gate lying. New mail with auth_pass short-circuits; old rows needed backfill/grade.

### Recruiter Gmail (locked judgment)
`khemsara@gmail.com` + BCC blast + Vandana/Vanessa mismatch = **suspicious**, not known-good. Tags: Recruiter via free mail / Tone: suspicious. Do not allowlist free-mail recruiters.

### INTEGER `is_threat`
Keep INTEGER 0/1; query with `= 1` not `TRUE`. Boolean migration = cosmetic unless greenfield table.

### Ship board — today / tomorrow (locked cut)
Crosswalk vs pilot sequence §0b. Legacy Dash/Streamlit docs were deleted 2026-08-09.

| Your pain | Maps to | Today? | Notes |
|---|---|---|---|
| Mac `sharingd` / iCloudHelper keychain prompts | Ops (dev Mac only) | **Yes** | `scripts/fix_login_keychain_lock.sh` — **TestFlight users never see this** |
| iOS Mac/phone “not working” (localhost/Tailscale) | **P2** | **Yes** | Funnel host is local-only (`PilotSecrets.apiBaseURL`); need **build 5+** auto-connect (screenshots still show old Sign-in UI = old binary) |
| Good mail (Sezzle) = 100% phish | **P0b** | **Yes** | `sezzle.com` + auth_pass allowlist; hyphen auth header keys accepted |
| Missed bad mail / “models not ready” | Gate + grading | Partial | Golden gate was PASS 2026-08-06; live FPs need grade→`nightly_retrain` — not a full rewrite today |
| Feedback loop / sibling weights | **M2** | Verify | Grade toast + `scripts/nightly_retrain.py` already exist — prove with one Mark Safe / Block cycle |
| Credit / dark-web freemium | **P1** | **No** | Outsource vendors only (Array/IPQS/HIBP); cards fail-open without keys — sell as “coming Pro” |
| Mobile web UI / Fiverr wireframe | Later | **No** | Console stays Signal Deck; **iOS Guard home** now matches consumer IA (auto / scan / recon / Pro stubs) — Fiverr polish optional after sync works |
| Jarvis MCP | Out of scope | **No** | Not required to ship NullPoint; optional for your other repo |

**Do not do today:** MCP, DIY OSINT, model architecture rewrite, angel deck polish. **Do:** Archive **build 10**, prove scan on phone + grade loop on email.

### iOS (2026-08-09)
- Public API path: **Tailscale Funnel** (home ISP blocks ngrok free edge). Keep `tailscale funnel --bg 8088`.
- Build **10** Guard home (consumer IA, not sync stub): **Auto-mode** (info) → **Scan for threats** → **Active recon** (screen number + directory/activity) → **Credit / SSN** + **Dark web** as Pro fail-open stubs (Array/Plaid/IPQS — no DIY scrapers). Passwordless pilot connect. Mac → `http://127.0.0.1:8088`; phone → Funnel host.
- `GET /api/v1/vish/screens` feeds Recent screens. Credit/dark-web live checks stay **P1** (vendor keys).
- If UI still shows “Sign in” / bare “Sync again” → **old binary**; Archive/upload 10.
- **Not TestFlight:** Mac `sharingd` / login-keychain prompts — fix once with `scripts/fix_login_keychain_lock.sh`; pilots never see those.
- **No Jarvis MCP** required to ship NullPoint.

### Keychain (2026-08-09)
- Prompts are Apple Continuity (`sharingd` / `iCloudHelper`), not NullPoint JWT storage.
- Fix once: `bash scripts/fix_login_keychain_lock.sh` then sync login keychain password in Keychain Access if needed.

### Console UX
- Mark Safe / Block opens **cascade confirm modal** (siblings checklist); then persists + bubble-out.
- `/app/message/{id}` opens full decrypted body (analyst console; encrypted at rest).
- Brand mention alone is **not** IMPERSONATION — needs spoof/pressure context.
- Inbox = ungraded feed; Quarantine = ungraded holds. Both can Open. Graded rows leave both.

### iOS / Latch
- README wants display name **Latch**; **STALE in Xcode** — `CFBundleDisplayName` still **NullPoint Guard** / Directory / SMS Filter. Bundles stay `com.nullpoint.guard*`.
- Call Directory / Message Filter are **extension points in Xcode**, not portal App Services checkboxes.

### GitHub / known-good FP (2026-08-06)
- **Froms** = email `From:` addresses (not HTML forms).
- Live GitHub CI mail scored 100% threat: (1) auth headers truncated at 500 chars in `base_fetcher` so `auth_pass` never fired; (2) headers not stored in metadata; (3) explain matched **ups** inside **Upstream**; (4) display-name ≠ mailbox flagged normal GitHub CI.
- **Fixes:** preserve long auth headers; persist `headers` in ingest metadata; word-boundary brand match; skip DISPLAY_NAME_SPOOF on known-good domains; SOCIAL_ENGINEERING needs ≥2 lure hits. Cleared 2142 github.com rows in DB.
- MiniLM embed-on-insert disabled by default (`ENABLE_MESSAGE_EMBEDDINGS=0`); `API_WORKERS=1` — was OOM → nginx 502.

### Phishing gate (2026-08-06) — FIXED
- **Root cause:** known-good allowlist short-circuited on brand From alone → spoofed Apple/PayPal/Google pump_fake scored 0.02 safe → pump recall 0.5, gate FAIL.
- **Fix:** `common/safe_domains.is_known_good_sender` requires **auth_pass** (SPF/DKIM/DMARC); no headers / auth_fail → fall through to ML. Call sites pass full `email_data`.
- **Verified (one-shot, app stopped):** phishing acc **97.5%**, FPR 4.8%, pump_fake **100%**, **GATE PASS**. Snapshot refreshed. Remaining 1 FP: transactional flight confirmation (does not fail gate).
- Test: `test/test_safe_domains.py`.

### Ops / resilience (2026-08-06)
- **502 Bad Gateway** root cause: app OOM when `/app/benchmarks` ran golden eval + latency bench inline, and quarantine loaded detectors per row. App restart count climbed; nginx returned 502 while gunicorn respawned.
- **Mitigation:** benchmarks read `data/benchmark_snapshot.json` only; refresh via `scripts/refresh_benchmarks.py` (one-shot, app stopped). Quarantine explain = rules only (no per-row SGD). Nginx `/app` timeouts + `proxy_next_upstream`. Dashboard mock geo pins removed.

### App Store Connect
- ASC shows **No Apps** → must **Add Apps** before TestFlight (hurry before Aug 8 maintenance).
- Do **not** follow Apple VoIP CallKit sample; NullPoint = Call Directory + Message Filter only.
- Full steps: `ios/README.md`.

---

## 0b. PILOT SEQUENCE — do in this order (locked 2026-08-05; money path promoted 2026-08-06)

Do **not** parallelize App Store + FinOps + Android + model rewrite.
Ship thorough, but sequence so P0s unblock the pilot.

| # | Deliverable | Go / no-go |
|---|---|---|
| **P0a** | Grade loop works: Mark safe / Block bubble-out via CSS `transform`, persists `label`+`is_threat`, survives page reload | Mark safe on inbox → row gone → reload → still gone |
| **P0b** | Known-good FPR guardrail (`common/safe_domains.py`) so GitHub/Google/AWS noreply are not 100% threats | `detector.predict(noreply@github.com) == (0, ~0.02)` |
| **M1** | Pricing → checkout → success (mock Stripe until keys); hash-chained `payment_audit_events`; server price authority | CTA works; `BILLING_MOCK=true` shows SIMULATED; search `TODO(BILLING_MOCK)` to remove |
| **M2** | Grade → buffer + ephemeral `partial_fit` with Δw toast; reason-code tags; plain-English math; nightly `scripts/nightly_retrain.py`; sibling crumbs | Grade toast shows weight movers; `/app/benchmarks` shows golden metrics |
| **M3** | Benchmark Deck (BenchmarkList-inspired) — real golden/latency only; assist slots keyed/missing | `/app/benchmarks` 200; no vanity filler |
| **P0c** | Logged-in home feel (not same shell + credentials in footer only) | After login, dashboard reads as operator home |
| **P1** | Identity / Credit / OSINT **views** (no plaintext passwords) | Enrich cards even when vendor missing_keys |
| **P1** | Connectors as customer surface; OAuth optional | Presentable without `.env` lecture |
| **P2** | iOS TestFlight: Message Filter + Call Directory only (no VoIP Loop C) | Internal TestFlight installs |
| **P2** | Redis rate limit + idempotency before multi-replica | Two app replicas share limits |
| **P3** | Android (deferred; share OpenAPI contract) | Not blocking iOS |
| **Later** | Entity graph, FinOps, stego/qhish modules; DeepSeek/Kimi ensemble votes | Assist only |

### Pricing (locked 2026-08-06)
- Essential **$4.99** / **$50** yr — **no trial**
- Pro **$14.99** / **$149.99** yr — **7-day trial** (fingerprint + IP risk score)
- Enterprise **$49.99** / **$499** yr + Contact sales

### Model / AI stance (locked)
- Hot path stays **TF-IDF + calibrated SGD + structural features** — not DeepSeek.
- LLMs (DeepSeek / Kimi / Groq) are **optional explanation/analyst assist only**, swappable, never sole enforcement.
- Sibling channels: separate champions + shared entity crumbs (`common/ml/cross_channel.py`).
- Contract: `docs/contracts/analyze.openapi.yaml` → generate TS for extensions later.
- Prefer **owned thin wrappers**; REST + async workers; Postgres.

### Phone / SMS ingest (honest)
- **Email RTI:** live via ingest stream (already connected).
- **SMS without TestFlight:** paste into Signal Deck `/app?channel=smishing` (or analyze form) — works on localhost now; no live host required for paste.
- **SMS RTI:** iOS Message Filter extension POSTs to your public API — needs a reachable host (Tunnel/Cloudflare) + TestFlight build.
- **Calls:** Call Directory lists = automated when installed; voicemail/transcript = paste or one-tap share into vishing channel.
- **Do not** auto-text strangers as the product agent without explicit product/legal design — grading + analyze first.
- Android: richer hooks later; share the OpenAPI contract, don’t rewrite Python ML in TypeScript.

---

## 0. Product identity — LOCKED, do not change

- Product name: **NullPoint**. Console name: **Signal Deck**.
- Channels are labeled **Phishing / Smishing / Vishing** in the UI (never "PhishGuard" etc.).
- Design system: **gold/brass + forest green** ("brass rail", corner brackets, forest ink)
  in `web/static/app.css`. **NEVER**: purple, emojis in UI, npm/Node/CDN dependencies.
  The web console is server-rendered Jinja + one hand-written CSS + one hand-written JS file.
- Pricing tiers: Essential ($4.99 / $50 yr, no trial) / Pro ($14.99 / $149.99 yr, 7-day abuse-gated trial) /
  Enterprise ($49.99 / $499 yr + Contact sales). Catalog: `common/plans.py`.
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
10. **UI themes (2026-07-24)**: four appearances, switcher in sidebar foot,
   persisted in localStorage (`np_theme`): **Deck** (default gold+green Signal
   Deck), **Standard** (legacy NullPointVector light/blue console palette),
   **Terminal** (green-phosphor console), **Blackout** (pure black).
   Implemented as CSS-variable overrides on `body[data-theme]` in `app.css` —
   new themes = new variable block, never a parallel stylesheet.
   NOTE: legacy Dash (`ui/dash_app.py` :8050) was **deleted 2026-08-09**. Only Signal Deck
   at `http://localhost:8088/app` is the console.

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
